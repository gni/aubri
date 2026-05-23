#![allow(deprecated)]

mod core;
mod gui;

use clap::{Parser, Subcommand};

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
        #[arg(short, long)]
        secret: String,
        #[arg(short, long)]
        device: Option<String>,
        #[arg(short = 'H', long)]
        headless: bool,
        #[arg(short = 'r', long)]
        sample_rate: Option<u32>,
    },
    Client {
        #[arg(short, long)]
        address: String,
        #[arg(short, long)]
        secret: String,
        #[arg(short, long)]
        device: Option<String>,
        #[arg(short = 'H', long)]
        headless: bool,
        #[arg(short = 'r', long)]
        sample_rate: Option<u32>,
    },
    ListDevices,
    Gui,
}

fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    let cli = Cli::parse();
    let host = cpal::default_host();

    match cli.mode {
        Some(Mode::Server { bind, secret, device, headless, sample_rate }) => {
            if headless {
                let tel = std::sync::Arc::new(std::sync::Mutex::new(core::Telemetry::default()));
                core::run_server(host, &bind, &secret, device, sample_rate, tel.clone());
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    if let Ok(guard) = tel.lock() {
                        if !guard.is_running { break; }
                    }
                }
            } else {
                gui::launch_gui(Some(Mode::Server { bind, secret, device, headless, sample_rate }));
            }
        }
        Some(Mode::Client { address, secret, device, headless, sample_rate }) => {
            if headless {
                let tel = std::sync::Arc::new(std::sync::Mutex::new(core::Telemetry::default()));
                core::run_client(host, &address, &secret, device, sample_rate, tel.clone());
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    if let Ok(guard) = tel.lock() {
                        if !guard.is_running { break; }
                    }
                }
            } else {
                gui::launch_gui(Some(Mode::Client { address, secret, device, headless, sample_rate }));
            }
        }
        Some(Mode::ListDevices) => {
            core::list_devices(host);
        }
        Some(Mode::Gui) | None => gui::launch_gui(None),
    }
}