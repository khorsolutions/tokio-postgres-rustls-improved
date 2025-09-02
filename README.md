# tokio-postgres-rustls

[![codecov](https://codecov.io/github/dsykes16/tokio-postgres-rustls/graph/badge.svg?token=PKUZQ62OP8)](https://codecov.io/github/dsykes16/tokio-postgres-rustls)
[![tests](https://github.com/dsykes16/tokio-postgres-rustls/actions/workflows/rust.yml/badge.svg)](https://github.com/dsykes16/tokio-postgres-rustls/actions/workflows/rust.yml)

NOTE: This is a fork; the original [tokio-postgres-rustls](https://github.com/jbg/tokio-postgres-rustls) repo appears to be unmaintained and has known bugs.

This fork strives to be actively maintained, and incorporates [Conrad Ludgate](https://github.com/conradludgate)'s fixes for [SCRAM channel binding](https://github.com/jbg/tokio-postgres-rustls/pull/32) and [removal of unsafe code](https://github.com/jbg/tokio-postgres-rustls/pull/33), this fork also adds comprehensive integration tests and a CI pipeline.

This is an integration between the [rustls TLS stack](https://github.com/ctz/rustls)
and the [tokio-postgres asynchronous PostgreSQL client library](https://github.com/sfackler/rust-postgres).

[API Documentation](https://docs.rs/tokio-postgres-rustls-improved/)

## Use this crate directly:

```sh
cargo add tokio-postgres-rustls-improved
```

### Have a 3rd-party dependency that relies on the original `tokio-postgres-rustls`?

Patch in our fork that maintains the original crate name like this:

```toml
[patch.crates-io]
tokio-postgres-rustls = { git = "https://github.com/khorsolutions/tokio-postgres-rustls.git", tag = "0.14.0" }
```

## Example

See `tests/integration.rs` for actual usage examples, including SASL/SCRAM using Channel Binding.

```rust
    // Setup a `rustls::ClientConfig` (see Rustls docs for more info)
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(certs.roots)
        .with_client_auth_cert(certs.client_certs, certs.client_key)
        .expect("build rustls client config");

    // MakeRustlsConnect is provided by this library; it wraps a `rustls::CLientConfig`
    let tls = MakeRustlsConnect::new(tls_config);

    // Connect as usual with `tokio-postgres`, providing our `MakeRustlsConnect` as the `tls` arg
    let mut pg_config = Config::new();
    pg_config
        .host("localhost")
        .port(pg.port)
        .dbname("postgres")
        .user("ssl_user")
        .ssl_mode(SslMode::Require);
    let (client, conn) = pg_config.connect(tls).await.expect("connect");
```
NOTE: please use proper error handling in production code, this is an excerpt from tests that are expected to panic in a failure

## License

tokio-postgres-rustls-improved is distributed under the MIT license
