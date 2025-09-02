# tokio-postgres-rustls

[![crate](https://img.shields.io/crates/v/tokio-postgres-rustls-improved.svg)](https://crates.io/crates/tokio-postgres-rustls-improved/)
[![codecov](https://codecov.io/gh/khorsolutions/tokio-postgres-rustls-improved/graph/badge.svg?token=8ZYN7O2K5V)](https://codecov.io/gh/khorsolutions/tokio-postgres-rustls-improved)
[![tests](https://github.com/khorsolutions/tokio-postgres-rustls-improved/actions/workflows/test.yml/badge.svg)](https://github.com/khorsolutions/tokio-postgres-rustls-improved/actions/workflows/test.yml)

NOTE: This is a fork; the original [tokio-postgres-rustls](https://github.com/jbg/tokio-postgres-rustls) repo appears to be unmaintained and has known bugs with virtually no test coverage or CI pipeline.

## Improvements over original [`tokio-postgres-rustls`](https://github.com/jbg/tokio-postgres-rustls):

- Removed unsafe code (thanks @conradludgate)
- Fixes SCRAM/SASL channel binding
- Add support for `aws-lc-rs` instead of `ring` (defaults to `aws-lc-rs`; consistent with `rustls` defaults)
- Added comprehensive integration test suite that runs with both `ring` and `aws-lc-rs`

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

```toml
[patch.crates-io]
tokio-postgres-rustls = { git = "https://github.com/khorsolutions/tokio-postgres-rustls.git", tag = "0.15.0" }
```

Please note that backports to this repo are not currently automated, so using `tokio-postgres-rustls-improved` is preferred when possible.

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
