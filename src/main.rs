//! los-cara binary: CLI over the library.

use clap::{Parser, Subcommand};
use los_cara::config;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "los-cara", about = "S3-compatible object storage server")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run the S3-compatible server
    Serve {
        /// Bind address, e.g. 127.0.0.1:9000
        #[arg(long, default_value = "127.0.0.1:9000")]
        address: String,
        /// Data directory
        #[arg(long, default_value = "./data")]
        data: PathBuf,
        /// Root access key (or set LOS_CARA_ACCESS_KEY)
        #[arg(long)]
        access_key: Option<String>,
        /// Root secret key (or set LOS_CARA_SECRET_KEY)
        #[arg(long)]
        secret_key: Option<String>,
        /// TLS certificate PEM file (enables HTTPS)
        #[arg(long)]
        tls_cert: Option<PathBuf>,
        /// TLS private key PEM file
        #[arg(long)]
        tls_key: Option<PathBuf>,
    },
    /// Add or replace an access key in the data directory key store
    AddKey {
        /// Data directory
        #[arg(long, default_value = "./data")]
        data: PathBuf,
        #[arg(long)]
        access_key: String,
        #[arg(long)]
        secret_key: String,
    },
    /// Remove an access key from the data directory key store
    RemoveKey {
        /// Data directory
        #[arg(long, default_value = "./data")]
        data: PathBuf,
        #[arg(long)]
        access_key: String,
    },
}

fn main() {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "los_cara=info,tower=warn".into()),
        )
        .init();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    match cli.command {
        Command::Serve {
            address,
            data,
            access_key,
            secret_key,
            tls_cert,
            tls_key,
        } => {
            rt.block_on(config::serve(
                &address, &data, access_key, secret_key, tls_cert, tls_key,
            ));
        }
        Command::AddKey {
            data,
            access_key,
            secret_key,
        } => {
            config::add_key(&data, &access_key, &secret_key);
            println!(
                "key {access_key} added to {}",
                data.join("keys.json").display()
            );
        }
        Command::RemoveKey { data, access_key } => {
            config::remove_key(&data, &access_key);
            println!(
                "key {access_key} removed from {}",
                data.join("keys.json").display()
            );
        }
    }
}
