use std::{future::Future, io, pin::Pin, sync::Arc, task::{Context, Poll}};
use base64::Engine;
use rustls::{ClientConfig, RootCertStore, pki_types::{CertificateDer, ServerName}};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_postgres::tls::{ChannelBinding, TlsConnect, TlsStream};
use super::Socket;

pub struct Connector { config:Arc<ClientConfig>, name:ServerName<'static> }
pub struct Stream(tokio_rustls::client::TlsStream<Socket>);
impl Connector {
    pub fn from_env()->Result<Self,Box<dyn std::error::Error>> {
        // Managed services supply a PEM trust root and an IP/DNS host. Verify
        // that identity through rustls; never replace verification with a probe.
        if let Ok(pem) = std::env::var("PGSSLROOTCERT_PEM") {
            use rustls::pki_types::pem::PemObject;
            let cert = CertificateDer::from_pem_slice(pem.as_bytes())?;
            return Self::from_config(
                &base64::engine::general_purpose::STANDARD.encode(cert.as_ref()),
                std::env::var("PGHOST")?,
            );
        }
        Self::from_config(&std::env::var("TLS_CA_DER")?,std::env::var("TLS_SERVER_NAME")?)
    }
    pub fn from_config(ca:&str,server_name:String)->Result<Self,Box<dyn std::error::Error>> {
        let der=base64::engine::general_purpose::STANDARD.decode(ca)?;
        let mut roots=RootCertStore::empty();roots.add(CertificateDer::from(der))?;
        let mut config=ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots).with_no_client_auth();
        config.resumption=rustls::client::Resumption::disabled();
        let name=ServerName::try_from(server_name)?;
        Ok(Self{config:Arc::new(config),name})
    }
}
impl TlsConnect<Socket> for Connector {
    type Stream=Stream;
    type Error=io::Error;
    type Future=Pin<Box<dyn Future<Output=Result<Stream,io::Error>>>>;
    fn connect(self,socket:Socket)->Self::Future {
        Box::pin(async move {
            let stream=self.handshake(socket).await?;
            println!("FENDERS_TLS_READY");
            Ok(stream)
        })
    }
}
impl Connector {
    pub async fn handshake(self,socket:Socket)->io::Result<Stream> {
        let stream=tokio_rustls::TlsConnector::from(self.config).connect(self.name,socket).await?;
        if stream.get_ref().1.protocol_version()!=Some(rustls::ProtocolVersion::TLSv1_3) {
            return Err(io::Error::other("TLS 1.3 was not negotiated"));
        }
        Ok(Stream(stream))
    }
}

impl TlsStream for Stream { fn channel_binding(&self)->ChannelBinding {ChannelBinding::none()} }
impl AsyncRead for Stream {
    fn poll_read(mut self:Pin<&mut Self>,cx:&mut Context<'_>,buf:&mut ReadBuf<'_>)->Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx,buf)
    }
}
impl AsyncWrite for Stream {
    fn poll_write(mut self:Pin<&mut Self>,cx:&mut Context<'_>,bytes:&[u8])->Poll<io::Result<usize>> {Pin::new(&mut self.0).poll_write(cx,bytes)}
    fn poll_flush(mut self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>> {Pin::new(&mut self.0).poll_flush(cx)}
    fn poll_shutdown(mut self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>> {Pin::new(&mut self.0).poll_shutdown(cx)}
}
