//! Server configuration and process entry points (serve / key management).

use crate::auth::{self, Credentials};
use crate::s3::{self, AppState};
use crate::storage::Storage;
use std::path::Path;

/// Parse one exact HTTP(S) origin without repairing malformed URL syntax.
pub fn parse_cors_origin(value: &str) -> Result<axum::http::HeaderValue, String> {
    let invalid = || {
        format!(
            "invalid CORS origin {value:?}: expected an HTTP(S) origin with no user information, path, query, fragment, or wildcard"
        )
    };
    let (scheme, rest) = value.split_once("://").ok_or_else(invalid)?;
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"))
        || authority.is_empty()
        || authority.ends_with(':')
        || authority.contains(['/', '\\', '@', '?', '#', '*'])
        || value.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(invalid());
    }
    let url = url::Url::parse(value).map_err(|_| invalid())?;
    if url.host_str().is_none() || url.host_str().is_some_and(|host| host.contains('*')) {
        return Err(invalid());
    }
    axum::http::HeaderValue::from_str(&url.origin().ascii_serialization()).map_err(|_| invalid())
}

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
    serve_with_cors(
        address,
        data_dir,
        access_key,
        secret_key,
        tls_cert,
        tls_key,
        Vec::new(),
    )
    .await;
}

/// Start HTTP or HTTPS with origins validated by `parse_cors_origin`.
pub async fn serve_with_cors(
    address: &str,
    data_dir: &Path,
    access_key: Option<String>,
    secret_key: Option<String>,
    tls_cert: Option<std::path::PathBuf>,
    tls_key: Option<std::path::PathBuf>,
    allowed_origins: Vec<axum::http::HeaderValue>,
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
    let access_key = access_key
        .or_else(|| std::env::var("LC_ACCESS_KEY").ok())
        .or_else(|| std::env::var("LOS_CARA_ACCESS_KEY").ok());
    let secret_key = secret_key
        .or_else(|| std::env::var("LC_SECRET_KEY").ok())
        .or_else(|| std::env::var("LOS_CARA_SECRET_KEY").ok());
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
    let app = s3::router_with_cors(state, allowed_origins);

    let addr: std::net::SocketAddr = address.parse().unwrap_or_else(|_| {
        eprintln!("invalid bind address: {address}");
        std::process::exit(1);
    });

    match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => {
            tracing::info!("lc listening on https://{addr}");
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
            tracing::info!("lc listening on http://{addr}");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cors_origin_validation() {
        for (input, expected) in [
            ("http://localhost:5173", "http://localhost:5173"),
            ("https://APP.example:443/", "https://app.example"),
            ("HTTP://APP.example:80/", "http://app.example"),
            ("https://app.example:8443", "https://app.example:8443"),
            ("http://[::1]:80/", "http://[::1]"),
            ("https://[::1]:8443/", "https://[::1]:8443"),
        ] {
            assert_eq!(parse_cors_origin(input).unwrap(), expected, "{input}");
        }
        assert_eq!(
            parse_cors_origin("https://APP.example:443/").unwrap(),
            parse_cors_origin("https://app.example").unwrap()
        );
        for input in [
            "",
            "*",
            "null",
            "https://*.example",
            "https://%2A.example",
            "https://user:pass@app.example",
            "https://@app.example",
            "https://app.example/path",
            "https://app.example/..",
            "https://app.example/%2e",
            "https://app.example//",
            "https://app.example?",
            "https://app.example/?query",
            "https://app.example#",
            "ftp://app.example",
            "app.example",
            "https:app.example",
            "https:///app.example",
            "https://",
            "https://app.example:",
            "https://app.example:65536",
            "https://[::1",
            "https://app.example\\",
            " https://app.example",
            "https://app.example ",
            "https://app.\nexample",
            "https://app.example\t",
            "https://app.example\r",
            "https://app.example\0",
        ] {
            assert!(parse_cors_origin(input).is_err(), "accepted {input:?}");
        }
    }
}

#[cfg(test)]
mod env_tests {
    /// The env-var precedence test runs in a subprocess-free way: we can't
    /// safely mutate process env in parallel tests, so just document the
    /// contract here and verify the vars the systemd template uses.
    #[test]
    fn env_names_match_systemd_template() {
        let template = include_str!("../../packaging/systemd/lc.env.example");
        assert!(template.contains("LC_ACCESS_KEY="));
        assert!(template.contains("LC_SECRET_KEY="));
    }
}
