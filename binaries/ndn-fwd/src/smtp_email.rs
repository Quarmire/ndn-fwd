//! Real SMTP delivery for the NDNCERT `email` challenge (feature `smtp`).
//!
//! Implements `ndn_cert::EmailSender` over `lettre` (rustls TLS). The
//! dependency-free fallback is `ndn_identity::LoggingEmailSender`; see
//! `demo_ca::make_email_sender`.

use std::future::Future;
use std::pin::Pin;

use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use ndn_cert::EmailSender;
use ndn_config::SmtpConfig;

/// Sends the challenge code over SMTP. Holds the connection parameters and
/// builds a transport per send (cheap; surfaces relay/TLS errors as
/// `EmailSender` failures).
pub struct SmtpEmailSender {
    host: String,
    port: u16,
    from: String,
    username: Option<String>,
    password: Option<String>,
    starttls: bool,
}

impl SmtpEmailSender {
    pub fn new(cfg: &SmtpConfig) -> Self {
        Self {
            host: cfg.host.clone(),
            port: cfg.port,
            from: cfg.from.clone(),
            username: cfg.username.clone(),
            password: cfg.password.clone(),
            starttls: cfg.starttls,
        }
    }

    fn transport(&self) -> Result<AsyncSmtpTransport<Tokio1Executor>, String> {
        let mut builder = if self.starttls {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.host)
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&self.host)
        }
        .map_err(|e| format!("smtp relay setup: {e}"))?
        .port(self.port);

        if let (Some(user), Some(pass)) = (&self.username, &self.password) {
            builder = builder.credentials(Credentials::new(user.clone(), pass.clone()));
        }
        Ok(builder.build())
    }
}

impl EmailSender for SmtpEmailSender {
    fn send<'a>(
        &'a self,
        address: &'a str,
        code: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        let from = self.from.clone();
        let address = address.to_string();
        let code = code.to_string();
        Box::pin(async move {
            let transport = self.transport()?;
            let email = Message::builder()
                .from(from.parse().map_err(|e| format!("bad from address: {e}"))?)
                .to(address
                    .parse()
                    .map_err(|e| format!("bad to address: {e}"))?)
                .subject("Your NDNCERT verification code")
                .body(format!("Your NDNCERT verification code is: {code}\n"))
                .map_err(|e| format!("build message: {e}"))?;
            transport
                .send(email)
                .await
                .map(|_| ())
                .map_err(|e| format!("smtp send: {e}"))
        })
    }
}
