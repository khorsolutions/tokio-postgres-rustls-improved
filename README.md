# tokio-postgres-rustls-improved

[![crate](https://img.shields.io/crates/v/tokio-postgres-rustls-improved.svg)](https://crates.io/crates/tokio-postgres-rustls-improved/)
[![codecov](https://codecov.io/gh/khorsolutions/tokio-postgres-rustls-improved/graph/badge.svg?token=8ZYN7O2K5V)](https://codecov.io/gh/khorsolutions/tokio-postgres-rustls-improved)
[![tests](https://github.com/khorsolutions/tokio-postgres-rustls-improved/actions/workflows/test.yml/badge.svg)](https://github.com/khorsolutions/tokio-postgres-rustls-improved/actions/workflows/test.yml)
[![docs.rs](https://img.shields.io/docsrs/tokio-postgres-rustls-improved)](https://docs.rs/tokio-postgres-rustls-improved/)
[![msrv](https://img.shields.io/crates/msrv/tokio-postgres-rustls-improved)](https://crates.io/crates/tokio-postgres-rustls-improved/)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=khorsolutions_tokio-postgres-rustls-improved&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=khorsolutions_tokio-postgres-rustls-improved)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=khorsolutions_tokio-postgres-rustls-improved&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=khorsolutions_tokio-postgres-rustls-improved)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=khorsolutions_tokio-postgres-rustls-improved&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=khorsolutions_tokio-postgres-rustls-improved)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=khorsolutions_tokio-postgres-rustls-improved&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=khorsolutions_tokio-postgres-rustls-improved)

NOTE: This is a fork; the original [tokio-postgres-rustls](https://github.com/jbg/tokio-postgres-rustls) repo appears to be unmaintained and has known bugs with virtually no test coverage or CI pipeline.

NOTE: Channel binding is not supported with Ed25519 certificates. This appears to be a limitation of Postgres, including Postgres 18.

## Improvements over original [`tokio-postgres-rustls`](https://github.com/jbg/tokio-postgres-rustls):

0.15.2:

- Support for `ECDSA_WITH_SHA512` channel binding (i.e. ECDSA P-521, secp521r1, NIST P-521)
  NOTE: only supported by `aws-lc-rs` (default); unsupported with `ring` crypto provider
- Integration test matrix to validate Postgres 13 through 18 with rustc MSRV, stable, and nightly.

0.15.1:

- Removed unsafe code (thanks @conradludgate)
- Fixes SCRAM/SASL channel binding (was non-functional in all cases in original `tokio-postgres-rustls`)
- Support for `aws-lc-rs` instead of `ring` (defaults to `aws-lc-rs`; consistent with `rustls` defaults)
- Comprehensive integration test suite that runs with both `ring` and `aws-lc-rs`

This is an integration between the [rustls TLS stack](https://github.com/ctz/rustls)
and the [tokio-postgres asynchronous PostgreSQL client library](https://github.com/sfackler/rust-postgres).

[API Documentation](https://docs.rs/tokio-postgres-rustls-improved/)

## Use this crate directly:

With `aws-lc-rs` (default for `rustls`):

```sh
cargo add tokio-postgres-rustls-improved
```

With `ring`:

```sh
cargo add tokio-postgres-rustls-improved --no-default-features --features ring
```

### Have a 3rd-party dependency that relies on the original `tokio-postgres-rustls`?

Patch in our fork that maintains the original crate name like this:

With `aws-lc-rs` feature:

```toml
[patch.crates-io]
tokio-postgres-rustls = { git = "https://github.com/khorsolutions/tokio-postgres-rustls-patch.git", tag = "aws-lc-rs" }
```

With `ring` feature:

```toml
[patch.crates-io]
tokio-postgres-rustls = { git = "https://github.com/khorsolutions/tokio-postgres-rustls-patch.git", tag = "ring" }
```

## Example

See `tests/integration.rs` for actual usage examples, including SASL/SCRAM using Channel Binding.

```rust,ignore
    use tokio_postgres::config::{ChannelBinding, SslMode};
    use tokio_postgres_rustls_improved::MakeRustlsConnect;

    // Build a [`rustls::RootCertStore`] and client certs
    let roots = {
        let rs = rustls::RootCertStore::empty();
        rs.add(todo!("provide a [`rustls::pki_types::CertificateDer`]"));
        rs
    };
    let client_certs = todo!("provide client cert and any intermediate(s) required to chain back to roots if applicable");
    let client_key = todo!("provide private key for client cert");

    // Setup a `rustls::ClientConfig` (see Rustls docs for more info)
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(client_certs, client_key)
        .expect("build rustls client config");

    // MakeRustlsConnect is provided by this library; it wraps a `rustls::CLientConfig`
    let tls = MakeRustlsConnect::new(tls_config);

    // Connect as usual with `tokio-postgres`, providing our `MakeRustlsConnect` as the `tls` arg
    let mut pg_config = Config::new();
    pg_config
        .host("localhost")
        .port(5432)
        .dbname("postgres")
        .user("scram_user")
        .password("password")
        .ssl_mode(SslMode::Require)
        .channel_binding(ChannelBinding::Require);
    let (client, conn) = pg_config.connect(tls).await.expect("connect");
```

NOTE: please use proper error handling in production code, this is an excerpt from tests that are expected to panic in a failure

## License

tokio-postgres-rustls-improved is distributed under the MIT license
