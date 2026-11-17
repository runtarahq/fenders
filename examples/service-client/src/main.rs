use wasi::http::{outgoing_handler,types::{Fields,OutgoingRequest,Scheme,IncomingBody,OutgoingBody,Method,RequestOptions,IncomingResponse}};
use wasi::io::streams::StreamError;
mod pg;
mod valkey;
mod filesystem;
mod tcp;
fn env(key:&str,default:&str)->String {std::env::var(key).unwrap_or_else(|_|default.into())}
fn request(path:&str,post:Option<&[u8]>,timeout:bool)->Result<IncomingResponse,String> {
    let id=env("RUN_ID","manual");
    let fields=Fields::from_list(&[("x-fenders-run".into(),id.into_bytes()),("user-agent".into(),b"fenders-acceptance/1.0".to_vec())]).map_err(|e|format!("fields: {e:?}"))?;
    let request=OutgoingRequest::new(fields);
    let scheme=if env("HTTP_SCHEME","http")=="https" {Scheme::Https} else {Scheme::Http};
    request.set_scheme(Some(&scheme)).unwrap();
    request.set_authority(Some(&env("HTTP_AUTHORITY","127.0.0.1:8081"))).unwrap();
    request.set_path_with_query(Some(path)).unwrap();
    if post.is_some() {request.set_method(&Method::Post).unwrap();}
    let body=post.map(|_|request.body().unwrap());
    let options=RequestOptions::new();
    options.set_connect_timeout(Some(2_000_000_000)).unwrap();
    options.set_first_byte_timeout(Some(if timeout {40_000_000} else {2_000_000_000})).unwrap();
    options.set_between_bytes_timeout(Some(if env("HTTP_CASE","")=="public-stream" {1_000_000_000} else {100_000_000})).unwrap();
    let response=outgoing_handler::handle(request,Some(options)).map_err(|e|format!("handle: {e:?}"))?;
    if let (Some(bytes),Some(body))=(post,body) {
        let output=body.write().unwrap();
        for chunk in bytes.chunks(4096) {output.blocking_write_and_flush(chunk).map_err(|e|format!("write: {e:?}"))?;}
        drop(output);
        OutgoingBody::finish(body,None).map_err(|e|format!("finish: {e:?}"))?;
    }
    response.subscribe().block();
    response.get().ok_or("not ready")?.map_err(|_|"already consumed")?.map_err(|e|format!("response: {e:?}"))
}
fn consume(response:IncomingResponse)->Result<(Vec<u8>,Option<Fields>),String> {
    let body=response.consume().unwrap();let input=body.stream().unwrap();let mut bytes=Vec::new();
    loop {match input.blocking_read(4096) {
        Ok(chunk)=>{bytes.extend(chunk);if bytes.len()>1024*1024 {return Err("test body limit exceeded".into());}}
        Err(StreamError::Closed)=>break,
        Err(StreamError::LastOperationFailed(e))=>return Err(format!("stream: {:?}",wasi::http::types::http_error_code(&e))),
    }}
    drop(input);
    let trailers=IncomingBody::finish(body);trailers.subscribe().block();
    let trailers=trailers.get().ok_or("trailers not ready")?.map_err(|_|"trailers consumed")?.map_err(|e|format!("trailers: {e:?}"))?;
    Ok((bytes,trailers))
}
fn run()->Result<(),String> {
    if env("HTTP_CASE", "") == "connections" {
        tcp::run().map_err(|e| format!("tcp: {e}"))?;
    }
    if env("HTTP_CASE", "") == "tcp" {
        return tcp::run().map_err(|e| format!("tcp: {e}"));
    }
    if env("HTTP_CASE", "") == "valkey" {
        return valkey::run().map_err(|e| format!("valkey: {e:?}"));
    }
    if env("HTTP_CASE", "") == "postgres-denied" {
        return pg::expect_denied().map_err(|e| format!("postgres denial: {e:?}"));
    }
    if env("HTTP_CASE", "") == "postgres" {
        return pg::run().map_err(|e| format!("postgres: {e:?}"));
    }
    if env("FS_CASE","")!="" {
        filesystem::run().map_err(|e|format!("filesystem: {e}"))?;
        if env("FS_CONTINUE","0")!="1" {return Ok(());}
    }
    match env("HTTP_CASE","get").as_str() {
        "public-denied"=>{
            let req=OutgoingRequest::new(Fields::new());
            req.set_scheme(Some(&Scheme::Https)).unwrap();
            req.set_authority(Some(&env("HTTP_AUTHORITY","httpbingo.org"))).unwrap();
            req.set_path_with_query(Some("/get")).unwrap();
            let error=match outgoing_handler::handle(req,None) {
                Err(error)=>error,
                Ok(future)=>{
                    future.subscribe().block();
                    match future.get().ok_or("denial not ready")?.map_err(|_|"denial already consumed")? {
                        Err(error)=>error,
                        Ok(_)=>return Err("ungranted HTTPS request succeeded".into()),
                    }
                }
            };
            assert!(matches!(error,wasi::http::types::ErrorCode::HttpRequestDenied),"{error:?}");
            println!("FENDERS_PUBLIC_HTTPS_DENIED {error:?}");
        }
        "public-stream"=>{
            let response=request("/drip?duration=10&numbytes=1000&delay=0",None,false)?;
            assert_eq!(response.status(),200);
            let body=response.consume().unwrap();let input=body.stream().unwrap();
            let mut first=true;
            loop {match input.blocking_read(4096) {
                Ok(bytes)=>if !bytes.is_empty()&&first {
                    println!("FENDERS_PUBLIC_HTTPS_STREAM_OPEN bytes={}",bytes.len());first=false;
                },
                Err(StreamError::Closed)=>return Err("HTTPS stream completed before revocation".into()),
                Err(StreamError::LastOperationFailed(error))=>return Err(format!("stream failed before process fencing: {error:?}")),
            }}
        }
        "public-get"|"connections"=>{
            assert_eq!(env("HTTP_SCHEME",""),"https");
            let response=request(&env("HTTP_PATH","/"),None,false)?;
            let status=response.status();assert_eq!(status,200);
            let (bytes,_)=consume(response)?;
            let body=String::from_utf8(bytes).map_err(|e|format!("UTF-8: {e}"))?;
            assert!(body.contains(&env("HTTP_EXPECT","Example Domain")),"unexpected response body: {body}");
            println!("FENDERS_PUBLIC_HTTPS_RESPONSE status={status} body={body}");
        }
        "post"=>{
            let payload:Vec<u8>=(0..131072).map(|i|(i%251) as u8).collect();
            let response=request("/echo",Some(&payload),false)?;assert_eq!(response.status(),200);
            let (bytes,trailers)=consume(response)?;assert_eq!(bytes,payload);
            assert_eq!(trailers.unwrap().get("x-fenders-trailer"),vec![b"complete".to_vec()]);
        }
        "chunked"=>{
            let response=request("/chunked",None,false)?;assert_eq!(response.status(),200);
            let (bytes,trailers)=consume(response)?;assert_eq!(bytes,vec![b'x';131072]);
            assert_eq!(trailers.unwrap().get("x-fenders-trailer"),vec![b"complete".to_vec()]);
        }
        "status"=>{let response=request("/missing",None,false)?;assert_eq!(response.status(),404);assert_eq!(consume(response)?.0,b"not found");}
        "redirect"=>{
            let response=request("/redirect",None,false)?;assert_eq!(response.status(),302);
            assert_eq!(response.headers().get("location"),vec![b"http://127.0.0.1:1/forbidden".to_vec()]);
            consume(response)?;
        }
        "timeout"=>{let error=request("/slow",None,true).err().ok_or("timeout did not fail")?;assert!(error.contains("ConnectionReadTimeout"),"{error}");println!("FENDERS_EXPECTED_TIMEOUT {error}");}
        "body-timeout"=>{let response=request("/slow-body",None,false)?;let error=consume(response).err().ok_or("body timeout did not fail")?;assert!(error.contains("ConnectionReadTimeout"),"{error}");println!("FENDERS_EXPECTED_BODY_TIMEOUT {error}");}
        "cancel"=>{
            let response=request("/slow-body",None,false)?;let body=response.consume().unwrap();let input=body.stream().unwrap();
            assert_eq!(input.blocking_read(4096).unwrap(),b"first");drop(input);drop(body);drop(response);
            assert_eq!(consume(request("/probe",None,false)?)?.0,b"upstream-wasi-http\n");
        }
        "get"=>{let response=request("/probe",None,false)?;assert_eq!(response.status(),200);assert_eq!(consume(response)?.0,b"upstream-wasi-http\n");}
        other=>return Err(format!("unknown HTTP case {other}")),
    }
    println!("FENDERS_WASI_HTTP_VERIFIED");
    match env("RESOURCE_CASE","").as_str() {
        "memory"=>{assert_eq!(core::arch::wasm32::memory_grow::<0>(65),usize::MAX);println!("FENDERS_MEMORY_LIMIT_VERIFIED");}
        "fuel"=>{let mut value=0u64;loop {value=std::hint::black_box(value.wrapping_add(1));}}
        _=>{}
    }
    if env("PG_ENABLE","0")=="1" {pg::run().map_err(|e|format!("postgres: {e:?}"))?;}
    println!("FENDERS_APP_READY");Ok(())
}
fn main() {if let Err(e)=run() {eprintln!("HTTP test failed: {e}");std::process::exit(1);}}
