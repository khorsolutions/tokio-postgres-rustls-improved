use tokio_postgres::Config;
use tokio_postgres::config::{ChannelBinding, SslMode, SslNegotiation};
use tokio_postgres_rustls_improved::MakeRustlsConnect;

mod support;
use rcgen::{
    PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ECDSA_P521_SHA512, PKCS_ED25519,
    PKCS_RSA_SHA256, PKCS_RSA_SHA384, PKCS_RSA_SHA512,
};
use support::certstore::CertStore;
use support::container::PostgresContainer;

#[tokio::test]
async fn ssl_user_without_client_cert_rejected() {
    let cs = CertStore::default();
    let pg = PostgresContainer::start(
        "ssl-user-without-client-cert-rejected",
        "./tests/support/sql_setup.sh",
        cs.root_pem,
        cs.server_pem,
        cs.server_key_pem,
    )
    .await;

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(cs.rootstore)
        .with_no_client_auth();
    let tls = MakeRustlsConnect::new(tls_config);

    let mut pg_config = Config::new();
    pg_config
        .host("localhost")
        .port(pg.port().await)
        .dbname("postgres")
        .user("ssl_user")
        .ssl_mode(SslMode::Prefer);

    let Err(err) = pg_config.connect(tls).await else {
        panic!("connect to postgres as ssl_user without client auth should fail");
    };

    if !format!("{:?}", err).contains("connection requires a valid client certificate") {
        // mac raises an os-level connection refused error; linux works as expected, windows is
        // unverified.
        #[cfg(not(target_os = "macos"))]
        panic!(
            "connect to postgres as ssl_user without client auth failed with unexpected error: {:?}",
            err
        );
    }
}

#[tokio::test]
async fn ssl_user_ok() {
    let cs = CertStore::default();
    let pg = PostgresContainer::start(
        "ssl-user-with-client-cert-ok",
        "./tests/support/sql_setup.sh",
        cs.root_pem,
        cs.server_pem,
        cs.server_key_pem,
    )
    .await;

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(cs.rootstore)
        .with_client_auth_cert(cs.client_certs, cs.client_key)
        .expect("build rustls client config");
    let tls = MakeRustlsConnect::new(tls_config);

    let mut pg_config = Config::new();
    pg_config
        .host("localhost")
        .port(pg.port().await)
        .dbname("postgres")
        .user("ssl_user")
        .ssl_mode(SslMode::Require);
    let (client, conn) = pg_config.connect(tls).await.expect("connect");
    tokio::spawn(async move { conn.await.map_err(|e| panic!("{:?}", e)) });

    let stmt = client.prepare("SELECT 1::INT4").await.expect("prepare");
    let rows = client.query(&stmt, &[]).await.expect("query");
    assert_eq!(1, rows.len());
    let res: i32 = (&rows[0]).get(0);
    assert_eq!(1, res);
}

#[tokio::test]
async fn ssl_direct_negotiation() {
    let cs = CertStore::default();
    let pg = PostgresContainer::start(
        "ssl-direct-negotiation",
        "./tests/support/sql_setup.sh",
        cs.root_pem,
        cs.server_pem,
        cs.server_key_pem,
    )
    .await;

    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(cs.rootstore)
        .with_client_auth_cert(cs.client_certs, cs.client_key)
        .expect("build rustls client config");
    tls_config.alpn_protocols = vec![b"postgresql".to_vec()];
    let tls = MakeRustlsConnect::new(tls_config);

    let mut pg_config = Config::new();
    pg_config
        .host("localhost")
        .port(pg.port().await)
        .dbname("postgres")
        .user("ssl_user")
        .ssl_negotiation(SslNegotiation::Direct)
        .ssl_mode(SslMode::Require);
    let (client, conn) = pg_config.connect(tls).await.expect("connect");
    tokio::spawn(async move { conn.await.map_err(|e| panic!("{:?}", e)) });

    let stmt = client.prepare("SELECT 1::INT4").await.expect("prepare");
    let rows = client.query(&stmt, &[]).await.expect("query");
    assert_eq!(1, rows.len());
    let res: i32 = (&rows[0]).get(0);
    assert_eq!(1, res);
}

macro_rules! scram_test {
    ($name:ident, $algo:expr, $binding_mode:expr) => {
        #[tokio::test]
        async fn $name() {
            let cs = CertStore::make_certs($algo);
            let pg = PostgresContainer::start(
                &format!("scram-{:?}", $algo),
                "./tests/support/sql_setup.sh",
                cs.root_pem,
                cs.server_pem,
                cs.server_key_pem,
            )
            .await;

            let tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(cs.rootstore)
                .with_client_auth_cert(cs.client_certs, cs.client_key)
                .expect("build rustls client config");
            let tls = MakeRustlsConnect::new(tls_config);

            let mut pg_config = Config::new();
            pg_config
                .host("localhost")
                .port(pg.port().await)
                .dbname("postgres")
                .user("scram_user")
                .password("password")
                .ssl_mode(SslMode::Require)
                .channel_binding($binding_mode);
            let (client, conn) = pg_config.connect(tls).await.expect("connect");
            let _guard = tokio::spawn(async move { conn.await.map_err(|e| panic!("{:?}", e)) });

            let stmt = client.prepare("SELECT 1::INT4").await.expect("prepare");
            let rows = client.query(&stmt, &[]).await.expect("query");
            assert_eq!(1, rows.len());
            let res: i32 = (&rows[0]).get(0);
            assert_eq!(1, res);
        }
    };
}

scram_test!(
    scram_p256_sha256,
    &PKCS_ECDSA_P256_SHA256,
    ChannelBinding::Require
);
scram_test!(
    scram_p384_sha384,
    &PKCS_ECDSA_P384_SHA384,
    ChannelBinding::Require
);
scram_test!(
    scram_p521_sha512,
    &PKCS_ECDSA_P521_SHA512,
    ChannelBinding::Require
);
scram_test!(scram_rsa_sha256, &PKCS_RSA_SHA256, ChannelBinding::Require);
scram_test!(scram_rsa_sha384, &PKCS_RSA_SHA384, ChannelBinding::Require);
scram_test!(scram_rsa_sha512, &PKCS_RSA_SHA512, ChannelBinding::Require);

// postgres does not yet support tls-exporter channel binding (RFC9266) and a past effort to
// add it seems to be abandoned (ref: https://www.postgresql.org/message-id/flat/YwxWWQR6uwWHBCbQ%40paquier.xyz)
scram_test!(scram_ed25519, &PKCS_ED25519, ChannelBinding::Prefer);

#[cfg(feature = "config-stream")]
mod dynamic_config {
    use std::{
        collections::VecDeque,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use rustls::ClientConfig;
    use rustls_config_stream::{
        ClientConfigProvider, ClientConfigStreamBuilder, ClientConfigStreamError,
    };
    use thiserror::Error;
    use tokio::sync::{Mutex, mpsc};
    use tokio_postgres::{Config, config::SslMode};
    use tokio_postgres_rustls_improved::MakeDynamicRustlsConnect;
    use tokio_stream::wrappers::ReceiverStream;

    use crate::support::{certstore::CertStore, container::PostgresContainer};

    #[derive(Error, Debug)]
    struct MockError(&'static str);
    impl std::fmt::Display for MockError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    #[derive(Debug)]
    struct MockClientConfigStreamBuilder {
        streams:
            Mutex<VecDeque<mpsc::Receiver<Result<Arc<ClientConfig>, ClientConfigStreamError>>>>,
        builds: Arc<AtomicUsize>,
    }

    impl MockClientConfigStreamBuilder {
        fn new(
            streams: Vec<mpsc::Receiver<Result<Arc<ClientConfig>, ClientConfigStreamError>>>,
        ) -> Self {
            let builds = Arc::from(AtomicUsize::new(0));
            let streams = Mutex::from(VecDeque::from(streams));
            Self { streams, builds }
        }
    }

    impl ClientConfigStreamBuilder for MockClientConfigStreamBuilder {
        type ConfigStream = ReceiverStream<Result<Arc<ClientConfig>, ClientConfigStreamError>>;

        async fn build(&mut self) -> Result<Self::ConfigStream, ClientConfigStreamError> {
            self.builds.fetch_add(1, Ordering::SeqCst);
            let rx = self.streams.lock().await.pop_front().ok_or_else(|| {
                ClientConfigStreamError::StreamBuilderError(MockError("mock stream error").into())
            })?;
            Ok(ReceiverStream::new(rx))
        }
    }

    #[tokio::test]
    async fn config_swap() {
        let cs = CertStore::default();
        let pg = PostgresContainer::start(
            "config-stream-hot-swap",
            "./tests/support/sql_setup.sh",
            cs.root_pem,
            cs.server_pem,
            cs.server_key_pem,
        )
        .await;
        let mut pg_config = Config::new();
        pg_config
            .host("localhost")
            .port(pg.port().await)
            .dbname("postgres")
            .user("ssl_user")
            .ssl_mode(SslMode::Require);

        let (tx, rx) = mpsc::channel(1);
        let builder = MockClientConfigStreamBuilder::new(vec![rx]);

        // push a "bad" config onto the stream w/ certs other than what postgres is actually using
        let bad_cs = CertStore::default();
        tx.send(Ok(rustls::ClientConfig::builder()
            .with_root_certificates(bad_cs.rootstore)
            .with_client_auth_cert(bad_cs.client_certs, bad_cs.client_key)
            .expect("build bad rustls client config")
            .into()))
            .await
            .expect("push bad config onto stream");

        let provider = ClientConfigProvider::start(builder).await.unwrap().into();
        let tls = MakeDynamicRustlsConnect::new(provider);

        // connecting with "bad" config should fail
        let Err(_) = pg_config.connect(tls.clone()).await else {
            panic!("connect to postgres as ssl_user with bad tls config should fail");
        };

        // push a "good" config with actual certs onto stream
        tx.send(Ok(rustls::ClientConfig::builder()
            .with_root_certificates(cs.rootstore)
            .with_client_auth_cert(cs.client_certs, cs.client_key)
            .expect("build good rustls client config")
            .into()))
            .await
            .expect("push good config onto stream");

        // connection should work now with same tls provider
        let (client, conn) = pg_config.connect(tls).await.expect("connect");
        tokio::spawn(async move { conn.await.map_err(|e| panic!("{:?}", e)) });

        let stmt = client.prepare("SELECT 1::INT4").await.expect("prepare");
        let rows = client.query(&stmt, &[]).await.expect("query");
        assert_eq!(1, rows.len());
        let res: i32 = (&rows[0]).get(0);
        assert_eq!(1, res);
    }
}
