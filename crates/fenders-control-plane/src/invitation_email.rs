//! Operator-configured SMTP delivery. Credentials never enter customer responses.
use crate::error::{Error, Result};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::Mailbox,
    transport::smtp::authentication::Credentials,
};
use serde::Deserialize;
use std::{path::PathBuf, time::Duration};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvitationEmailConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password_file: PathBuf,
    pub from: String,
    pub console_origin: String,
}
impl InvitationEmailConfig {
    /// Validate credentials without connecting to the platform database or sending mail.
    pub async fn check(self) -> Result<()> {
        InvitationMailer::new(self)?.check().await
    }
}
pub(crate) struct InvitationMailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    origin: String,
}
impl InvitationMailer {
    pub fn new(config: InvitationEmailConfig) -> Result<Self> {
        let origin = url::Url::parse(&config.console_origin)
            .map_err(|_| Error::invalid("invalid invitation console origin"))?;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.path() != "/"
            || config.port == 0
        {
            return Err(Error::invalid(
                "invitation console origin must be an HTTPS origin",
            ));
        }
        let password = std::fs::read_to_string(&config.password_file)?;
        if password.trim().is_empty() {
            return Err(Error::invalid("empty SMTP credential"));
        }
        let transport = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
            .map_err(|_| Error::invalid("invalid SMTP relay"))?
            .port(config.port)
            .timeout(Some(Duration::from_secs(10)))
            .credentials(Credentials::new(
                config.username,
                password.trim_end().to_owned(),
            ))
            .build();
        Ok(Self {
            transport,
            from: config
                .from
                .parse()
                .map_err(|_| Error::invalid("invalid invitation sender"))?,
            origin: config.console_origin.trim_end_matches('/').to_owned(),
        })
    }
    pub async fn check(&self) -> Result<()> {
        match tokio::time::timeout(Duration::from_secs(20), self.transport.test_connection()).await
        {
            Ok(Ok(true)) => Ok(()),
            _ => Err(Error::invalid(
                "SMTP STARTTLS authentication failed; check relay configuration",
            )),
        }
    }
    pub async fn send(
        &self,
        id: &str,
        email: &str,
        workspace: &str,
        role: &str,
        scope: &str,
    ) -> Result<()> {
        // The link identifies a request, not a credential. Verified-email ownership
        // and a fresh explicit decision are still required by the customer API.
        let message = Message::builder().from(self.from.clone())
            .to(email.parse().map_err(|_| Error::invalid("invalid invitation recipient"))?)
            .subject("You're invited to a Fenders workspace")
            .message_id(Some(format!("<invitation-{id}@{}>", url::Url::parse(&self.origin).unwrap().host_str().unwrap())))
            .body(format!("You've been invited to join {workspace} on Fenders.\n\nRole: {role}\nAccess: {scope}\n\nReview and accept or decline your invitation:\n{}/console/#invitation={id}\n\nSign in with {email} and verify your email. This invitation expires seven days after it was created. Opening this link does not grant access.\n\nFenders — airtight sandboxes.\n", self.origin))
            .map_err(|_| Error::invalid("invalid invitation email"))?;
        match tokio::time::timeout(Duration::from_secs(20), self.transport.send(message)).await {
            Ok(Ok(_)) => Ok(()),
            // Do not log provider replies, credentials, or recipient addresses.
            _ => Err(Error::invalid("invitation email delivery failed")),
        }
    }
}
