use fenders_control_plane::public_egress::{PublicEgress, PublicEgressConfig};
use hickory_resolver::proto::{
    op::{Message, OpCode, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, CNAME},
    },
};
use std::{
    net::SocketAddrV4,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{Mutex, Semaphore},
    task::JoinHandle,
};

pub struct DnsLab {
    pub gate: Arc<Semaphore>,
    pub answer_mode: Arc<AtomicUsize>,
    pub config: PublicEgressConfig,
    pub queries: Arc<Mutex<Vec<(String, RecordType)>>>,
    task: JoinHandle<()>,
}
impl Drop for DnsLab {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl DnsLab {
    pub async fn new() -> Self {
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca = params.self_signed(&ca_key).unwrap();
        let server_key = rcgen::KeyPair::generate().unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["resolver.test".into()])
            .unwrap()
            .signed_by(&server_key, &ca, &ca_key)
            .unwrap();
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: SocketAddrV4 = listener.local_addr().unwrap().to_string().parse().unwrap();
        let queries = Arc::new(Mutex::new(Vec::new()));
        let seen = queries.clone();
        let rebind = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Semaphore::new(0));
        let answer_mode = Arc::new(AtomicUsize::new(0));
        let gate_task = gate.clone();
        let answers = answer_mode.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls.clone()));
                let seen = seen.clone();
                let rebind = rebind.clone();
                let gate = gate_task.clone();
                let answers = answers.clone();
                connections.spawn(async move {
                    let Ok(mut socket) = acceptor.accept(socket).await else {
                        return;
                    };
                    while let Ok(length) = socket.read_u16().await {
                        let mut wire = vec![0; length as usize];
                        if socket.read_exact(&mut wire).await.is_err() {
                            break;
                        }
                        let query = Message::from_vec(&wire).unwrap();
                        assert_eq!(query.queries.len(), 1);
                        let name = query.queries[0].name.to_ascii();
                        let record_type = query.queries[0].query_type();
                        seen.lock().await.push((name.clone(), record_type));
                        assert_eq!(record_type, RecordType::A);
                        assert!(name.ends_with('.'));
                        if name == "held.test." || name == "held-ttl.test." {
                            gate.acquire().await.unwrap().forget();
                        }
                        if name.starts_with("stall") {
                            continue;
                        }
                        let mut response = Message::response(query.metadata.id, OpCode::Query);
                        response.metadata.recursion_available = true;
                        response.metadata.recursion_desired = query.metadata.recursion_desired;
                        response.queries = query.queries.clone();
                        let ttl = match name.as_str() {
                            "zero.test." => 0,
                            "ttl.test." | "held-ttl.test." => 1,
                            "cap.test." => 3600,
                            _ => 60,
                        };
                        let addresses: Vec<&str> = match name.as_str() {
                            "changing.test." if answers.load(Ordering::SeqCst) == 1 => {
                                vec!["8.8.8.8"]
                            }
                            "changing.test." if answers.load(Ordering::SeqCst) == 2 => {
                                vec!["127.0.0.1"]
                            }
                            "mixed.test." => vec!["1.1.1.1", "10.0.0.1"],
                            "metadata.test." => vec!["169.254.169.254"],
                            "managed.test." => vec!["9.9.9.9"],
                            "many.test." => {
                                vec!["1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5"]
                            }
                            "rebinding.test." if rebind.fetch_add(1, Ordering::SeqCst) > 0 => {
                                vec!["127.0.0.1"]
                            }
                            "empty.test." => vec![],
                            "nxdomain.test." => {
                                response.metadata.response_code = ResponseCode::NXDomain;
                                vec![]
                            }
                            "alias.test." | "evil-alias.test." => {
                                let target = Name::from_ascii("target.test.").unwrap();
                                response.answers.push(Record::from_rdata(
                                    query.queries[0].name.clone(),
                                    2,
                                    RData::CNAME(CNAME(target.clone())),
                                ));
                                let ip = if name == "evil-alias.test." {
                                    "10.1.1.1"
                                } else {
                                    "1.1.1.1"
                                };
                                response.answers.push(Record::from_rdata(
                                    target,
                                    90,
                                    RData::A(A(ip.parse().unwrap())),
                                ));
                                vec![]
                            }
                            "chain.test." => {
                                response.answers.push(Record::from_rdata(
                                    query.queries[0].name.clone(),
                                    2,
                                    RData::CNAME(CNAME(Name::from_ascii("target.test.").unwrap())),
                                ));
                                vec![]
                            }
                            "wrong-question.test." => {
                                response.queries = vec![Query::query(
                                    Name::from_ascii("foreign.test.").unwrap(),
                                    RecordType::A,
                                )];
                                vec!["1.1.1.1"]
                            }
                            "wrong-id.test." => {
                                response.metadata.id = response.metadata.id.wrapping_add(1);
                                vec!["1.1.1.1"]
                            }
                            "unrelated.test." => {
                                response.answers.push(Record::from_rdata(
                                    Name::from_ascii("unrelated-extra.test.").unwrap(),
                                    60,
                                    RData::A(A("8.8.8.8".parse().unwrap())),
                                ));
                                vec!["1.1.1.1"]
                            }
                            "deep.test." => {
                                let mut current = query.queries[0].name.clone();
                                for index in 0..9 {
                                    let next =
                                        Name::from_ascii(format!("hop{index}.test.")).unwrap();
                                    response.answers.push(Record::from_rdata(
                                        current,
                                        60,
                                        RData::CNAME(CNAME(next.clone())),
                                    ));
                                    current = next;
                                }
                                response.answers.push(Record::from_rdata(
                                    current,
                                    60,
                                    RData::A(A("1.1.1.1".parse().unwrap())),
                                ));
                                vec![]
                            }
                            "ambiguous.test." => {
                                response.answers.push(Record::from_rdata(
                                    query.queries[0].name.clone(),
                                    60,
                                    RData::CNAME(CNAME(Name::from_ascii("target.test.").unwrap())),
                                ));
                                vec!["1.1.1.1"]
                            }
                            _ => vec!["1.1.1.1"],
                        };
                        for address in addresses {
                            response.answers.push(Record::from_rdata(
                                query.queries[0].name.clone(),
                                ttl,
                                RData::A(A(address.parse().unwrap())),
                            ));
                        }
                        let wire = response.to_vec().unwrap();
                        if socket.write_u16(wire.len() as u16).await.is_err()
                            || socket.write_all(&wire).await.is_err()
                        {
                            break;
                        }
                    }
                });
            }
        });
        Self {
            gate,
            answer_mode,
            config: PublicEgressConfig {
                dns_address: address,
                dns_server_name: "resolver.test".into(),
                dns_ca_pem: Some(ca.pem()),
                denied_ipv4: vec!["9.9.0.0/16".into()],
            },
            queries,
            task,
        }
    }
    pub fn resolver(&self) -> PublicEgress {
        PublicEgress::new(self.config.clone()).unwrap()
    }
}
