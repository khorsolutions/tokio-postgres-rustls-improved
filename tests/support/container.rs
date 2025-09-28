use tokio::time::{Duration, Instant};

use testcontainers::{
    ContainerAsync, GenericImage, Healthcheck, ImageExt,
    core::{AccessMode, IntoContainerPort, Mount, WaitFor},
    runners::AsyncRunner,
};
use tokio_postgres::{Config, NoTls};

pub(crate) struct PostgresContainer(ContainerAsync<GenericImage>);

impl PostgresContainer {
    pub(crate) async fn start(
        test_name: &str,
        setup_script: &str,
        ca_cert: String,
        server_cert: String,
        server_key: String,
    ) -> Self {
        let postgres_version = std::env::var("POSTGRES_VERSION").unwrap_or(String::from("17"));
        let container = GenericImage::new("postgres", &postgres_version)
            .with_exposed_port(5433.tcp())
            .with_wait_for(WaitFor::healthcheck())
            // 4s timeout on initial healthcheck
            .with_health_check(
                Healthcheck::cmd(vec!["pg_isready", "-U startup_probe", "-p 5433"])
                    .with_interval(Duration::from_millis(200))
                    .with_timeout(Duration::from_millis(100))
                    .with_retries(20),
            )
            .with_container_name(test_name)
            .with_env_var("POSTGRES_PASSWORD", "postgres")
            .with_env_var("POSTGRES_USER", "postgres")
            .with_env_var("POSTGRES_DB", "postgres")
            .with_copy_to("/etc/postgresql/certs/ca.crt", ca_cert.as_bytes().to_vec())
            .with_copy_to(
                "/etc/postgresql/certs/server.crt",
                server_cert.as_bytes().to_vec(),
            )
            .with_copy_to(
                "/etc/postgresql/certs/server.key",
                server_key.as_bytes().to_vec(),
            )
            .with_mount(
                Mount::bind_mount(
                    format!("{}/{}", env!("CARGO_MANIFEST_DIR"), setup_script),
                    "/docker-entrypoint-initdb.d/sql_setup.sh",
                )
                .with_access_mode(AccessMode::ReadOnly),
            )
            .start()
            .await
            .unwrap();
        Self::wait_for_ready(container.get_host_port_ipv4(5433.tcp()).await.unwrap())
            .await
            .unwrap();
        Self(container)
    }

    pub(crate) async fn port(&self) -> u16 {
        self.0.get_host_port_ipv4(5433.tcp()).await.unwrap()
    }

    async fn wait_for_ready(port: u16) -> Result<(), &'static str> {
        let max_wait = Duration::from_secs(5);
        let mut cfg = Config::new();
        cfg.host("localhost")
            .port(port)
            .user("startup_probe")
            .dbname("postgres")
            .ssl_mode(tokio_postgres::config::SslMode::Disable)
            .connect_timeout(Duration::from_secs(2));

        let deadline = Instant::now() + max_wait;

        loop {
            let Ok((client, conn)) = cfg.connect(NoTls).await else {
                if Instant::now() >= deadline {
                    panic!("timed out waiting for postgres to be ready")
                }
                tokio::time::sleep(Duration::from_millis(150)).await;
                continue;
            };

            let conn_task = tokio::spawn(async move {
                let _ = conn.await;
            });

            let ok = tokio::time::timeout(Duration::from_secs(2), client.simple_query("SELECT 1"))
                .await
                .ok()
                .and_then(|r| r.ok())
                .is_some();

            conn_task.abort();

            if ok {
                return Ok(());
            }

            if Instant::now() >= deadline {
                panic!("timed out waiting for postgres to be ready")
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }
}
