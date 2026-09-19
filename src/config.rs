//! Server configuration and process entry points (serve / key management).

use crate::auth::{self, Credentials};
use crate::s3::{self, AppState};
use crate::storage::Storage;
use std::path::Path;

pub fn add_key(data_dir: &Path, access_key: &str, secret_key: &str) {
    auth::add_key(data_dir, access_key, secret_key);
}

pub fn remove_key(data_dir: &Path, access_key: &str) {
    auth::remove_key(data_dir, access_key);
}

pub async fn serve(
    address: &str,
    data_dir: &Path,
    access_key: Option<String>,
    secret_key: Option<String>,
    tls_cert: Option<std::path::PathBuf>,
    tls_key: Option<std::path::PathBuf>,
) {
    let storage = match Storage::open(data_dir).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "failed to initialize data directory {}: {e}",
                data_dir.display()
            );
            std::process::exit(1);
        }
    };
    let access_key = access_key.or_else(|| std::env::var("LOS_CARA_ACCESS_KEY").ok());
    let secret_key = secret_key.or_else(|| std::env::var("LOS_CARA_SECRET_KEY").ok());
    let creds = match (access_key, secret_key) {
        (Some(a), Some(s)) if !a.is_empty() && !s.is_empty() => Credentials {
            access_key: a,
            secret_key: s,
        },
        _ => {
            // fall back to keys.json contents if present
            Credentials {
                access_key: String::new(),
                secret_key: String::new(),
            }
        }
    };
    let cred_store = auth::CredentialStore::new(data_dir, creds);
    let state = AppState::new(storage, cred_store);
    let app = s3::router(state);

    let addr: std::net::SocketAddr = address.parse().unwrap_or_else(|_| {
        eprintln!("invalid bind address: {address}");
        std::process::exit(1);
    });

    match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => {
            tracing::info!("los-cara listening on https://{addr}");
            let rustls_config = match load_tls(&cert, &key) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("failed to load TLS material: {e}");
                    std::process::exit(1);
                }
            };
            axum_server::bind_rustls(addr, rustls_config)
                .serve(app.into_make_service())
                .await
                .expect("server error");
        }
        _ => {
            let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
            tracing::info!("los-cara listening on http://{addr}");
            axum::serve(listener, app).await.expect("server error");
        }
    }
}

fn load_tls(cert: &Path, key: &Path) -> Result<axum_server::tls_rustls::RustlsConfig, String> {
    let _ = cert;
    let _ = key;
    // rustls config built from PEM files
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(cert).map_err(|e| e.to_string())?,
    ))
    .collect::<Result<_, _>>()
    .map_err(|e| e.to_string())?;
    let key_der = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        std::fs::File::open(key).map_err(|e| e.to_string())?,
    ))
    .map_err(|e| e.to_string())?
    .ok_or("no private key found")?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key_der)
        .map_err(|e| e.to_string())?;
    Ok(axum_server::tls_rustls::RustlsConfig::from_config(
        std::sync::Arc::new(config),
    ))
}
