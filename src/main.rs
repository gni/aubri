#![allow(deprecated)]
#![allow(clippy::collapsible_if)]

mod core;

#[cfg(feature = "gui")]
mod gui;

use clap::{Parser, Subcommand};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{error, info, warn};

#[derive(Parser, Clone)]
#[command(author, version, about = "secure p2p audio streamer")]
pub struct Cli {
    #[arg(long, global = true, help = "output telemetry as raw json to stdout")]
    pub json: bool,

    #[command(subcommand)]
    pub mode: Option<Mode>,
}

#[derive(Subcommand, Clone)]
pub enum Mode {
    Server {
        #[arg(short, long, default_value = "0.0.0.0:8080")]
        bind: String,

        #[arg(short, long)]
        secret: Option<String>,

        #[arg(short, long)]
        device: Option<String>,

        #[arg(short = 'r', long)]
        sample_rate: Option<u32>,

        #[arg(short = 'P', long, default_value = "udp")]
        protocol: String,
    },
    Client {
        #[arg(short, long)]
        address: String,

        #[arg(short, long)]
        secret: Option<String>,

        #[arg(short, long)]
        device: Option<String>,

        #[arg(short = 'r', long)]
        sample_rate: Option<u32>,

        #[arg(short = 'P', long, default_value = "udp")]
        protocol: String,

        #[arg(short = 'l', long)]
        latency: Option<usize>,

        #[arg(short = 'p', long)]
        prebuffer: Option<usize>,

        #[arg(short = 'k', long)]
        keep_alive: bool,
    },
    ListDevices,

    #[cfg(feature = "gui")]
    Gui,
}

fn resolve_secret(secret_arg: Option<String>) -> String {
    if let Some(s) = secret_arg {
        warn!(
            "security warning: you have passed the secret key as a cli argument. this exposes your key to the process table. use the AUBRI_SECRET environment variable or run without the --secret flag to be prompted securely."
        );
        return s;
    }

    if let Ok(env_secret) = std::env::var("AUBRI_SECRET") {
        if !env_secret.trim().is_empty() {
            return env_secret;
        }
    }

    match rpassword::prompt_password("enter cryptographic session secret: ") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => {
            error!(
                "critical: cryptographic secret cannot be empty. aborting execution state to prevent unauthenticated access."
            );
            std::process::exit(1);
        }
    }
}

fn monitor_telemetry(tel: Arc<Mutex<core::Telemetry>>, use_json: bool) {
    std::thread::spawn(move || {
        let mut last_status = String::new();
        loop {
            std::thread::sleep(Duration::from_millis(500));
            if let Ok(guard) = tel.lock() {
                if use_json {
                    println!("{}", serde_json::to_string(&*guard).unwrap_or_default());
                    if !guard.is_running {
                        break;
                    }
                } else {
                    if !guard.is_running && !guard.status.is_empty() {
                        if guard.status != last_status {
                            info!("status: {}", guard.status);
                        }
                        break;
                    }
                    if guard.status != last_status {
                        info!("status: {}", guard.status);
                        last_status = guard.status.clone();
                    }
                }
            }
        }
    });
}

fn main() {
    let cli = Cli::parse();

    if !cli.json {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .init();
    }

    match cli.mode {
        Some(Mode::Server {
            bind,
            secret,
            device,
            sample_rate,
            protocol,
        }) => {
            #[cfg(target_os = "linux")]
            {
                core::ensure_virtual_sink();
                // SAFETY: Executed synchronously at the start of the application before thread spawning.
                unsafe {
                    std::env::set_var("PULSE_SOURCE", "aubri.monitor");
                }
            }

            let host = cpal::default_host();
            let final_secret = resolve_secret(secret);
            let tel = Arc::new(Mutex::new(core::Telemetry::default()));

            let target_device = device.or_else(|| {
                #[cfg(target_os = "linux")]
                return Some("pulse".to_string());
                #[cfg(not(target_os = "linux"))]
                return None;
            });

            monitor_telemetry(tel.clone(), cli.json);
            core::run_server(
                host,
                &bind,
                &final_secret,
                target_device,
                sample_rate,
                &protocol,
                tel.clone(),
            );

            loop {
                std::thread::sleep(Duration::from_secs(1));
                if let Ok(guard) = tel.lock() {
                    if !guard.is_running {
                        break;
                    }
                }
            }
        }
        Some(Mode::Client {
            address,
            secret,
            device,
            sample_rate,
            protocol,
            latency,
            prebuffer,
            keep_alive,
        }) => {
            let host = cpal::default_host();
            let final_secret = resolve_secret(secret);
            let tel = Arc::new(Mutex::new(core::Telemetry::default()));

            monitor_telemetry(tel.clone(), cli.json);
            core::run_client(
                host,
                &address,
                &final_secret,
                device,
                sample_rate,
                &protocol,
                latency,
                prebuffer,
                keep_alive,
                tel.clone(),
            );

            loop {
                std::thread::sleep(Duration::from_secs(1));
                if let Ok(guard) = tel.lock() {
                    if !guard.is_running {
                        break;
                    }
                }
            }
        }
        Some(Mode::ListDevices) => {
            let host = cpal::default_host();
            core::list_devices(host);
        }
        #[cfg(feature = "gui")]
        Some(Mode::Gui) | None => {
            gui::launch_gui(None);
        }
        #[cfg(not(feature = "gui"))]
        None => {
            println!("no execution mode specified. run with --help for usage instructions.");
            std::process::exit(1);
        }
    }
}
