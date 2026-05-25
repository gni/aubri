#![allow(deprecated)]

mod core;
mod gui;

use clap::{Parser, Subcommand};
use tracing::{error, warn};

#[derive(Parser, Clone)]
#[command(author, version, about = "Secure P2P Audio Streamer (Zero-Trust)")]
pub struct Cli {
    #[command(subcommand)]
    pub mode: Option<Mode>,
}

#[derive(Subcommand, Clone)]
pub enum Mode {
    Server {
        #[arg(short, long, default_value = "0.0.0.0:8080")]
        bind: String,
        
        #[arg(short, long, env = "AUBRI_SECRET", hide_env_values = true)]
        secret: Option<String>,
        
        #[arg(short, long)]
        device: Option<String>,
        
        #[arg(short = 'H', long)]
        headless: bool,
        
        #[arg(short = 'r', long)]
        sample_rate: Option<u32>,
        
        #[arg(short = 'P', long, default_value = "udp")]
        protocol: String,
    },
    Client {
        #[arg(short, long)]
        address: String,
        
        #[arg(short, long, env = "AUBRI_SECRET", hide_env_values = true)]
        secret: Option<String>,
        
        #[arg(short, long)]
        device: Option<String>,
        
        #[arg(short = 'H', long)]
        headless: bool,
        
        #[arg(short = 'r', long)]
        sample_rate: Option<u32>,
        
        #[arg(short = 'P', long, default_value = "udp")]
        protocol: String,
        
        #[arg(short = 'l', long)]
        latency: Option<usize>,
        
        #[arg(short = 'p', long)]
        prebuffer: Option<usize>,
    },
    ListDevices,
    Gui,
}

fn resolve_secret(secret_arg: Option<String>, headless: bool) -> String {
    if let Some(s) = secret_arg {
        if headless {
            warn!("SECURITY WARNING: You have passed the secret key as a CLI argument. This exposes your key to the process table (e.g., `ps aux`). Use the AUBRI_SECRET environment variable or run without the --secret flag to be prompted securely.");
        }
        return s;
    }
    
    match rpassword::prompt_password("Enter cryptographic session secret: ") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => {
            error!("CRITICAL: Cryptographic secret cannot be empty. Aborting execution state to prevent unauthenticated access.");
            std::process::exit(1);
        }
    }
}

fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    let cli = Cli::parse();
    let host = cpal::default_host();

    match cli.mode {
        Some(Mode::Server { bind, secret, device, headless, sample_rate, protocol }) => {
            let final_secret = resolve_secret(secret, headless);
            if headless {
                let tel = std::sync::Arc::new(std::sync::Mutex::new(core::Telemetry::default()));
                core::run_server(host, &bind, &final_secret, device, sample_rate, &protocol, tel.clone());
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    if let Ok(guard) = tel.lock() {
                        if !guard.is_running { break; }
                    }
                }
            } else {
                gui::launch_gui(Some(Mode::Server { bind, secret: Some(final_secret), device, headless, sample_rate, protocol }));
            }
        }
        Some(Mode::Client { address, secret, device, headless, sample_rate, protocol, latency, prebuffer }) => {
            let final_secret = resolve_secret(secret, headless);
            if headless {
                let tel = std::sync::Arc::new(std::sync::Mutex::new(core::Telemetry::default()));
                core::run_client(host, &address, &final_secret, device, sample_rate, &protocol, latency, prebuffer, tel.clone());
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    if let Ok(guard) = tel.lock() {
                        if !guard.is_running { break; }
                    }
                }
            } else {
                gui::launch_gui(Some(Mode::Client { address, secret: Some(final_secret), device, headless, sample_rate, protocol, latency, prebuffer }));
            }
        }
        Some(Mode::ListDevices) => {
            core::list_devices(host);
        }
        Some(Mode::Gui) | None => gui::launch_gui(None),
    }
}