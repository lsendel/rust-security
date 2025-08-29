use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub bind_addr: SocketAddr,
}

impl AppConfig {
    pub fn from_env() -> Self {
        let _ = dotenvy::dotenv();

        let port: u16 = std::env::var("PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8081);

        let host: IpAddr = std::env::var("HOST")
            .ok()
            .and_then(|s| {
                s.parse()
                    .map_err(|e| {
                        tracing::warn!("Invalid HOST value '{}': {}", s, e);
                        e
                    })
                    .ok()
            })
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

        tracing::info!("Configuration loaded: {}:{}", host, port);

        Self {
            bind_addr: SocketAddr::new(host, port),
        }
    }
}
