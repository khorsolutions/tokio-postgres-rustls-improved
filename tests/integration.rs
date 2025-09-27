use tokio_postgres::config::{ChannelBinding, SslMode, SslNegotiation};
use tokio_postgres::Config;
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

    if err.to_string() != "db error: FATAL: connection requires a valid client certificate" {
        panic!("connect to postgres as ssl_user without client auth failed with unexpected error: {:?}", err);
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
