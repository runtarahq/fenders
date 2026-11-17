use wasi::filesystem::{preopens,types::{Descriptor,DescriptorFlags as D,OpenFlags as O,PathFlags as P,DescriptorType,NewTimestamp,Advice,ErrorCode}};
use wasi::clocks::wall_clock::Datetime;
use wasi::io::streams::StreamError;

fn named(dirs:&[(Descriptor,String)],name:&str)->usize {
    dirs.iter().position(|(_,n)|n==name).expect("missing filesystem preopen")
}
fn finish() {
    println!("FENDERS_FILESYSTEM_VERIFIED");
    if std::env::var("FS_CONTINUE").as_deref()!=Ok("1") {println!("FENDERS_APP_READY");}
}
pub fn run()->Result<(),String> {
    let dirs=preopens::get_directories();
    let case=std::env::var("FS_CASE").unwrap_or_default();
    if case=="none" {assert!(dirs.is_empty());finish();return Ok(());}
    let app=&dirs[named(&dirs,"/app")].0;
    let data=&dirs[named(&dirs,"/data")].0;
    let file=app.open_at(P::empty(),"asset.txt",O::empty(),D::READ).map_err(|e|format!("asset open: {e:?}"))?;
    assert_eq!(file.read(128,0).unwrap().0,b"read-only asset\n");
    if case=="persist-read" {
        let file=data.open_at(P::empty(),"created.txt",O::empty(),D::READ).unwrap();
        assert_eq!(file.read(128,0).unwrap().0,b"hello filesystem");
        assert!(dirs[named(&dirs,"/tmp")].0.read_directory().unwrap().read_directory_entry().unwrap().is_none());
        println!("FENDERS_FS_CHECK persistent-read");finish();return Ok(());
    }
    let file=data.open_at(P::empty(),"created.txt",O::CREATE|O::EXCLUSIVE,D::READ|D::WRITE).map_err(|e|format!("create: {e:?}"))?;
    assert_eq!(file.write(b"hello filesystem",0).unwrap(),16);
    assert_eq!(file.read(128,0).unwrap().0,b"hello filesystem");
    assert_eq!(file.stat().unwrap().size,16);
    file.sync_data().unwrap();file.sync().unwrap();
    println!("FENDERS_FS_CHECK create-read-write-sync");
    if case=="std" {
        use std::io::{Read,Write,Seek,SeekFrom};
        std::fs::create_dir_all("/data/std/nested").unwrap();
        std::fs::write("/data/std/nested/a.txt",b"standard Rust filesystem").unwrap();
        assert_eq!(std::fs::read("/data/std/nested/a.txt").unwrap(),b"standard Rust filesystem");
        std::fs::copy("/data/std/nested/a.txt","/data/std/nested/b.txt").unwrap();
        std::fs::rename("/data/std/nested/b.txt","/data/std/nested/c.txt").unwrap();
        let mut f=std::fs::OpenOptions::new().read(true).write(true).open("/data/std/nested/c.txt").unwrap();
        f.seek(SeekFrom::Start(9)).unwrap();f.write_all(b"WASI").unwrap();f.seek(SeekFrom::Start(0)).unwrap();
        let mut text=String::new();f.read_to_string(&mut text).unwrap();assert!(text.starts_with("standard WASI"));drop(f);
        assert_eq!(std::fs::read_dir("/data/std/nested").unwrap().count(),2);
        std::fs::remove_dir_all("/data/std").unwrap();
        println!("FENDERS_FS_CHECK rust-stdlib");
    }
    if case=="basic" || case=="std" {
        finish();return Ok(());
    }
    assert_eq!(file.get_type().unwrap(),DescriptorType::RegularFile);
    assert!(file.get_flags().unwrap().contains(D::READ|D::WRITE));
    file.advise(0,16,Advice::Normal).unwrap();
    assert_eq!(data.stat_at(P::empty(),"created.txt").unwrap().size,16);
    let again=data.open_at(P::empty(),"created.txt",O::empty(),D::READ).unwrap();
    assert!(file.is_same_object(&again));
    let h=file.metadata_hash().unwrap();let h2=data.metadata_hash_at(P::empty(),"created.txt").unwrap();
    assert_eq!((h.lower,h.upper),(h2.lower,h2.upper));
    assert!(data.open_at(P::empty(),"created.txt",O::CREATE|O::EXCLUSIVE,D::WRITE).is_err());
    println!("FENDERS_FS_CHECK metadata-flags-identity-exclusive");
    file.set_size(5).unwrap();assert_eq!(file.read(64,0).unwrap().0,b"hello");
    file.set_size(32).unwrap();assert_eq!(file.read(27,5).unwrap().0,vec![0;27]);
    assert_eq!(file.write(b"tail",40).unwrap(),4);assert_eq!(file.stat().unwrap().size,44);
    assert_eq!(file.read(8,32).unwrap().0,vec![0;8]);
    let timestamp=NewTimestamp::Timestamp(Datetime{seconds:1_700_000_000,nanoseconds:123_000_000});
    file.set_times(NewTimestamp::NoChange,timestamp).unwrap();
    assert_eq!(file.stat().unwrap().data_modification_timestamp.unwrap().seconds,1_700_000_000);
    data.set_times_at(P::empty(),"created.txt",NewTimestamp::Now,NewTimestamp::Timestamp(Datetime{seconds:1_700_000_001,nanoseconds:0})).unwrap();
    assert_eq!(file.stat().unwrap().data_modification_timestamp.unwrap().seconds,1_700_000_001);
    println!("FENDERS_FS_CHECK resize-sparse-timestamps");
    data.create_directory_at("nested").unwrap();
    assert!(data.open_at(P::empty(),"nested/../created.txt",O::empty(),D::READ).unwrap().is_same_object(&file));
    let nested=data.open_at(P::empty(),"nested",O::DIRECTORY,D::READ|D::MUTATE_DIRECTORY).unwrap();
    data.symlink_at("created.txt","valid-link").unwrap();
    assert_eq!(data.readlink_at("valid-link").unwrap(),"created.txt");
    assert!(data.readlink_at("escape-absolute").is_err());
    assert!(data.symlink_at("/etc/passwd","invalid-absolute-link").is_err());
    assert!(data.open_at(P::empty(),"valid-link",O::empty(),D::READ).is_err());
    assert_eq!(data.stat_at(P::empty(),"valid-link").unwrap().type_,DescriptorType::SymbolicLink);
    data.set_times_at(P::empty(),"valid-link",NewTimestamp::NoChange,NewTimestamp::Timestamp(Datetime{seconds:1_700_000_002,nanoseconds:0})).unwrap();
    assert_eq!(data.stat_at(P::empty(),"valid-link").unwrap().data_modification_timestamp.unwrap().seconds,1_700_000_002);
    assert_eq!(file.stat().unwrap().data_modification_timestamp.unwrap().seconds,1_700_000_001);
    let linked=data.open_at(P::SYMLINK_FOLLOW,"valid-link",O::empty(),D::READ).unwrap();assert!(linked.is_same_object(&file));
    data.link_at(P::empty(),"created.txt",&data,"hard-link").unwrap();
    assert!(data.open_at(P::empty(),"hard-link",O::empty(),D::READ).unwrap().is_same_object(&file));
    // Wasmtime 38 explicitly rejects SYMLINK_FOLLOW for hard links.
    assert_eq!(data.link_at(P::SYMLINK_FOLLOW,"valid-link",&nested,"followed-hard-link"),Err(ErrorCode::Invalid));
    data.link_at(P::empty(),"created.txt",&nested,"nested-hard-link").unwrap();
    data.rename_at("hard-link",&nested,"renamed.txt").unwrap();
    assert!(nested.open_at(P::empty(),"renamed.txt",O::empty(),D::READ).unwrap().is_same_object(&file));
    let entries=nested.read_directory().unwrap();let independent=nested.read_directory().unwrap();let mut names=Vec::new();
    while let Some(entry)=entries.read_directory_entry().unwrap(){names.push(entry.name);}
    names.sort();assert_eq!(names,vec!["nested-hard-link","renamed.txt"]);drop(entries);
    let mut names2=Vec::new();while let Some(entry)=independent.read_directory_entry().unwrap(){names2.push(entry.name);}
    names2.sort();assert_eq!(names,names2);drop(independent);
    nested.sync().unwrap();nested.sync_data().unwrap();
    assert!(data.remove_directory_at("nested").is_err());
    nested.unlink_file_at("renamed.txt").unwrap();nested.unlink_file_at("nested-hard-link").unwrap();
    drop(nested);data.remove_directory_at("nested").unwrap();data.unlink_file_at("valid-link").unwrap();
    println!("FENDERS_FS_CHECK directories-links-rename-removal");
    file.set_size(0).unwrap();let bytes=vec![b'x';131072];
    let output=file.write_via_stream(0).unwrap();
    for chunk in bytes.chunks(4096){output.blocking_write_and_flush(chunk).unwrap();}drop(output);
    let append=file.append_via_stream().unwrap();append.blocking_write_and_flush(b"end").unwrap();drop(append);
    let input=file.read_via_stream(0).unwrap();let mut read=Vec::new();
    loop {match input.blocking_read(4096){Ok(bytes)=>read.extend(bytes),Err(StreamError::Closed)=>break,Err(e)=>panic!("stream read: {e:?}")}}
    assert_eq!(&read[..131072],&bytes);assert_eq!(&read[131072..],b"end");drop(input);
    println!("FENDERS_FS_CHECK streamed-io-append");
    for path in ["../outside/secret.txt","/etc/passwd","escape-relative","escape-absolute","/data/created.txt"] {
        assert!(data.open_at(P::SYMLINK_FOLLOW,path,O::empty(),D::READ).is_err(),"escaped via {path}");
        assert!(data.stat_at(P::SYMLINK_FOLLOW,path).is_err(),"stat escaped via {path}");
    }
    assert!(data.open_at(P::empty(),"nul\0file",O::CREATE,D::WRITE).is_err());
    assert!(data.open_at(P::empty(),"blocked-fifo",O::empty(),D::READ).is_err());
    assert!(data.unlink_file_at("created.txt/").is_err());
    assert!(data.create_directory_at("../outside/new-dir").is_err());
    assert!(data.rename_at("created.txt",&data,"../outside/moved").is_err());
    assert!(data.link_at(P::SYMLINK_FOLLOW,"escape-relative",&data,"stolen").is_err());
    assert!(app.open_at(P::empty(),"asset.txt",O::empty(),D::WRITE).is_err());
    assert!(app.open_at(P::empty(),"new.txt",O::CREATE,D::WRITE).is_err());
    assert!(app.open_at(P::empty(),"/data/created.txt",O::empty(),D::READ).is_err());
    assert!(app.unlink_file_at("asset.txt").is_err());
    assert!(app.create_directory_at("new-dir").is_err());
    assert!(app.set_times_at(P::empty(),"asset.txt",NewTimestamp::Now,NewTimestamp::Now).is_err());
    assert!(app.open_at(P::empty(),"asset.txt",O::empty(),D::READ).unwrap().set_times(NewTimestamp::Now,NewTimestamp::Now).is_err());
    let tmp=&dirs[named(&dirs,"/tmp")].0;
    assert!(data.rename_at("created.txt",tmp,"cross-mount").is_err());
    assert!(data.link_at(P::empty(),"created.txt",tmp,"cross-mount").is_err());
    let scratch=tmp.open_at(P::empty(),"ephemeral.txt",O::CREATE|O::EXCLUSIVE,D::WRITE).unwrap();
    scratch.write(b"ephemeral sandbox data",0).unwrap();drop(scratch);
    println!("FENDERS_FS_CHECK readonly-traversal-symlinks-cross-mount");
    let truncated=data.open_at(P::empty(),"created.txt",O::TRUNCATE,D::WRITE).unwrap();assert_eq!(file.stat().unwrap().size,0);drop(truncated);
    file.write(b"hello filesystem",0).unwrap();file.sync().unwrap();
    finish();
    Ok(())
}
