use std::{convert::TryFrom, sync::Arc};

use rustls::pki_types::ServerName;
use rustls_config_stream::ClientConfigProvider;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_postgres::tls::MakeTlsConnect;

use crate::private;

/// [`MakeTlsConnect`] implementation backed by [`rustls`] with a dynamic TLS client config stream
/// provided by a [`rustls_config_stream::ClientConfigProvider`].
#[derive(Clone)]
pub struct MakeDynamicRustlsConnect {
    config_provider: Arc<ClientConfigProvider>,
}

impl MakeDynamicRustlsConnect {
    /// Creates a new [`MakeDynamicRustlsConnect`] from the provided
    /// [`Arc<ClientConfigProvider>`].
    #[must_use]
    pub const fn new(config_provider: Arc<ClientConfigProvider>) -> Self {
        Self { config_provider }
    }
}

impl<S> MakeTlsConnect<S> for MakeDynamicRustlsConnect
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = private::RustlsStream<S>;
    type TlsConnect = private::RustlsConnect;
    type Error = rustls::pki_types::InvalidDnsNameError;

    /// Creates a new [`MakeDynamicRustlsConnect`] from the given [`ClientConfigProvider`].
    fn make_tls_connect(&mut self, hostname: &str) -> Result<Self::TlsConnect, Self::Error> {
        ServerName::try_from(hostname).map(|dns_name| {
            private::RustlsConnect(private::RustlsConnectData {
                hostname: dns_name.to_owned(),
                connector: Arc::clone(&self.config_provider.get_config()).into(),
            })
        })
    }
}
