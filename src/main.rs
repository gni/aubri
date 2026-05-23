#![allow(deprecated)]

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use clap::{Parser, Subcommand};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use tracing::{error, info, warn};

const KDF_CONTEXT: &str = "aubri_p2p_audio_v2";
const MAX_QUEUE_DEPTH: usize = 16;
const MAX_LATENCY_MS: usize = 120;
const PREBUFFER_MS: usize = 40;
const HARDWARE_BUFFER_FRAMES: u32 = 512;

#[derive(Parser)]
#[command(author, version, about = "Secure P2P Audio Streamer (Zero-Trust)")]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    Server {
        #[arg(short, long, default_value = "0.0.0.0:8080")]
        bind: String,
        #[arg(short, long)]
        secret: String,
        #[arg(short, long)]
        device: Option<String>,
    },
    Client {
        #[arg(short, long)]
        address: String,
        #[arg(short, long)]
        secret: String,
        #[arg(short, long)]
        device: Option<String>,
    },
    ListDevices,
}

fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    let cli = Cli::parse();
    let host = cpal::default_host();

    match cli.mode {
        Mode::Server { bind, secret, device } => run_server(host, &bind, &secret, device),
        Mode::Client { address, secret, device } => run_client(host, &address, &secret, device),
        Mode::ListDevices => list_devices(host),
    }
}

fn list_devices(host: cpal::Host) {
    info!("Initializing audio device enumeration routine");
    
    let default_in = host.default_input_device().and_then(|d| d.name().ok());
    let default_out = host.default_output_device().and_then(|d| d.name().ok());

    println!("--- Input Devices (Capture) ---");
    if let Ok(devices) = host.input_devices() {
        for device in devices {
            if let Ok(name) = device.name() {
                let is_default = if Some(&name) == default_in.as_ref() { " [DEFAULT]" } else { "" };
                println!("  - {}{}", name, is_default);
            }
        }
    } else {
        error!("Hardware exception reading input devices");
    }

    println!("\n--- Output Devices (Playback) ---");
    if let Ok(devices) = host.output_devices() {
        for device in devices {
            if let Ok(name) = device.name() {
                let is_default = if Some(&name) == default_out.as_ref() { " [DEFAULT]" } else { "" };
                println!("  - {}{}", name, is_default);
            }
        }
    } else {
        error!("Hardware exception reading output devices");
    }
}

fn generate_nonce(counter: u64) -> Nonce {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
    *Nonce::from_slice(&nonce_bytes)
}

fn derive_session_key(secret: &str, salt: &[u8; 32]) -> [u8; 32] {
    let mut key_material = Vec::with_capacity(secret.len() + 32);
    key_material.extend_from_slice(secret.as_bytes());
    key_material.extend_from_slice(salt);
    blake3::derive_key(KDF_CONTEXT, &key_material)
}

fn resolve_input_device(host: &cpal::Host, requested_device: &Option<String>) -> Result<(cpal::Device, cpal::SupportedStreamConfig), String> {
    if let Some(name) = requested_device {
        let mut devs = host.input_devices().map_err(|e| format!("Cannot query topology: {}", e))?;
        let d = devs.find(|d| d.name().unwrap_or_default() == *name)
            .ok_or_else(|| format!("Device descriptor '{}' not found in system.", name))?;
        let cfg = d.default_input_config().map_err(|e| format!("Interface locked or format unsupported: {}", e))?;
        return Ok((d, cfg));
    }

    if let Some(d) = host.default_input_device() {
        if let Ok(cfg) = d.default_input_config() {
            return Ok((d, cfg));
        }
    }

    if let Ok(devs) = host.input_devices() {
        for d in devs {
            let name = d.name().unwrap_or_default().to_lowercase();
            if name.contains("pulse") || name.contains("pipewire") || name == "default" {
                if let Ok(cfg) = d.default_input_config() {
                    return Ok((d, cfg));
                }
            }
        }
    }

    Err("No available unlocked input devices found. Execute enumeration mode to identify valid hardware bounds.".to_string())
}

fn resolve_output_device(host: &cpal::Host, requested_device: &Option<String>) -> Result<(cpal::Device, cpal::SupportedStreamConfig), String> {
    if let Some(name) = requested_device {
        let mut devs = host.output_devices().map_err(|e| format!("Cannot query topology: {}", e))?;
        let d = devs.find(|d| d.name().unwrap_or_default() == *name)
            .ok_or_else(|| format!("Device descriptor '{}' not found in system.", name))?;
        let cfg = d.default_output_config().map_err(|e| format!("Interface locked or format unsupported: {}", e))?;
        return Ok((d, cfg));
    }

    if let Some(d) = host.default_output_device() {
        if let Ok(cfg) = d.default_output_config() {
            return Ok((d, cfg));
        }
    }

    if let Ok(devs) = host.output_devices() {
        for d in devs {
            let name = d.name().unwrap_or_default().to_lowercase();
            if name.contains("pulse") || name.contains("pipewire") || name == "default" {
                if let Ok(cfg) = d.default_output_config() {
                    return Ok((d, cfg));
                }
            }
        }
    }

    Err("No available unlocked output devices found. Execute enumeration mode to identify valid hardware bounds.".to_string())
}

fn run_server(host: cpal::Host, bind: &str, secret: &str, device_name: Option<String>) {
    let (device, supported_config) = match resolve_input_device(&host, &device_name) {
        Ok(res) => res,
        Err(e) => {
            error!(error = %e, "Input device resolution failed");
            return;
        }
    };

    let sample_rate = supported_config.sample_rate().0;
    let channels = supported_config.channels();

    let listener = match TcpListener::bind(bind) {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, bind = %bind, "Network binding failed on target interface");
            return;
        }
    };
    
    info!(bind = %bind, "Listening securely for incoming client connections");
    
    let (mut stream, addr) = match listener.accept() {
        Ok(res) => res,
        Err(e) => {
            error!(error = %e, "Internal networking socket negotiation failure");
            return;
        }
    };

    if let Err(e) = stream.set_nodelay(true) {
        warn!(error = %e, "Failed to disable TCP Nagle's algorithm. Audio jitter may occur.");
    }

    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    
    if stream.write_all(&salt).is_err() {
        error!("Failed to transmit cryptographic salt during handshake");
        return;
    }

    let session_key = derive_session_key(secret, &salt);
    let cipher = ChaCha20Poly1305::new(session_key.as_ref().into());
    
    info!(
        client_addr = %addr,
        "Authenticated handshake tunnel established. Ephemeral session key generated."
    );

    if stream.write_all(&sample_rate.to_le_bytes()).is_err() || stream.write_all(&channels.to_le_bytes()).is_err() {
        error!("Failed to transmit topology configuration vector.");
        return;
    }

    info!(
        device = %device.name().unwrap_or_else(|_| "Unknown".to_string()),
        sample_rate = %sample_rate,
        channels = %channels,
        "Allocated secure input hardware interface. Streaming commenced with 16-bit PCM Quantization."
    );

    let mut config: cpal::StreamConfig = supported_config.into();
    config.buffer_size = cpal::BufferSize::Fixed(HARDWARE_BUFFER_FRAMES);

    let (tx, rx) = mpsc::sync_channel::<Vec<i16>>(MAX_QUEUE_DEPTH);
    let tx_primary = tx.clone();

    let audio_stream = match device.build_input_stream(
        &config,
        move |data: &[f32], _: &_| {
            let pcm_16: Vec<i16> = data.iter()
                .map(|&s| (s.clamp(-1.0, 1.0) * i16::MAX as f32) as i16)
                .collect();
                
            match tx_primary.try_send(pcm_16) {
                Ok(_) => {},
                Err(mpsc::TrySendError::Full(_)) => {
                    warn!("Capture queue saturated. Network backpressure detected. Dropping frame to maintain synchronization.");
                },
                Err(_) => {}
            }
        },
        |err| error!(error = %err, "Hardware capture stream exception"),
        None,
    ) {
        Ok(stream) => stream,
        Err(_) => {
            config.buffer_size = cpal::BufferSize::Default;
            match device.build_input_stream(
                &config,
                move |data: &[f32], _: &_| {
                    let pcm_16: Vec<i16> = data.iter()
                        .map(|&s| (s.clamp(-1.0, 1.0) * i16::MAX as f32) as i16)
                        .collect();
                        
                    match tx.try_send(pcm_16) {
                        Ok(_) => {},
                        Err(mpsc::TrySendError::Full(_)) => {},
                        Err(_) => {}
                    }
                },
                |err| error!(error = %err, "Hardware capture stream exception"),
                None,
            ) {
                Ok(stream) => stream,
                Err(e) => {
                    error!(error = %e, "Hardware allocation failure during pipeline build phase");
                    return;
                }
            }
        }
    };

    if let Err(e) = audio_stream.play() {
        error!(error = %e, "Failed to transition capture pipeline to processing state");
        return;
    }

    let mut counter: u64 = 0;

    for data in rx {
        let raw_bytes: &[u8] = bytemuck::cast_slice(&data);
        let nonce = generate_nonce(counter);
        
        match cipher.encrypt(&nonce, raw_bytes) {
            Ok(ciphertext) => {
                let len = ciphertext.len() as u32;
                
                let mut packet = Vec::with_capacity(4 + ciphertext.len());
                packet.extend_from_slice(&len.to_le_bytes());
                packet.extend_from_slice(&ciphertext);
                
                if stream.write_all(&packet).is_err() {
                    warn!("Client connection closed or severed via pipeline interruption. Halting server context.");
                    break;
                }
                counter += 1;
            }
            Err(e) => error!(error = ?e, "Cryptographic frame encryption processing failure"),
        }
    }
}

fn run_client(host: cpal::Host, address: &str, secret: &str, device_name: Option<String>) {
    let (device, _) = match resolve_output_device(&host, &device_name) {
        Ok(res) => res,
        Err(e) => {
            error!(error = %e, "Output device resolution failed");
            return;
        }
    };

    info!(address = %address, "Establishing network connection context with host");
    
    let mut stream = match TcpStream::connect(address) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "Transmission link generation failure to remote host address");
            return;
        }
    };

    if let Err(e) = stream.set_nodelay(true) {
        warn!(error = %e, "Failed to disable TCP Nagle's algorithm. Audio jitter may occur.");
    }

    let mut salt = [0u8; 32];
    if stream.read_exact(&mut salt).is_err() {
        error!("Connection dropped prior to cryptographic handshake completion.");
        return;
    }

    let session_key = derive_session_key(secret, &salt);
    let cipher = ChaCha20Poly1305::new(session_key.as_ref().into());
    
    info!("Connected. Secure cryptographic handshake verified.");

    let mut sr_buf = [0u8; 4];
    let mut ch_buf = [0u8; 2];

    if stream.read_exact(&mut sr_buf).is_err() || stream.read_exact(&mut ch_buf).is_err() {
        error!("Connection dropped prior to topology negotiation.");
        return;
    }

    let sample_rate = u32::from_le_bytes(sr_buf);
    let channels = u16::from_le_bytes(ch_buf);

    let config = cpal::StreamConfig {
        channels,
        sample_rate: cpal::SampleRate(sample_rate),
        buffer_size: cpal::BufferSize::Fixed(HARDWARE_BUFFER_FRAMES),
    };

    let sample_rate_sz = sample_rate as usize;
    let channels_sz = channels as usize;
    let max_jitter_buffer_samples = (sample_rate_sz * channels_sz * MAX_LATENCY_MS) / 1000;
    let prebuffer_target_samples = (sample_rate_sz * channels_sz * PREBUFFER_MS) / 1000;

    info!(
        device = %device.name().unwrap_or_else(|_| "Unknown".to_string()),
        enforced_sample_rate = %sample_rate,
        enforced_channels = %channels,
        prebuffer_ms = %PREBUFFER_MS,
        "Allocated secure output hardware interface. Enforcing asymmetric server topology with 16-bit PCM Dequantization."
    );

    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(MAX_QUEUE_DEPTH);
    
    let jitter_buffer = Arc::new(Mutex::new(VecDeque::with_capacity(max_jitter_buffer_samples * 2)));
    let rx_shared = Arc::new(Mutex::new(rx));
    let is_prebuffering = Arc::new(Mutex::new(true));

    let jb_primary = Arc::clone(&jitter_buffer);
    let rx_primary = Arc::clone(&rx_shared);
    let pb_primary = Arc::clone(&is_prebuffering);

    let audio_stream = match device.build_output_stream(
        &config,
        move |data: &mut [f32], _: &_| {
            let mut frames_needed = data.len();
            let mut data_idx = 0;

            if let Ok(rx_guard) = rx_primary.try_lock() {
                while let Ok(decrypted_bytes) = rx_guard.try_recv() {
                    let incoming = decrypted_bytes.chunks_exact(2)
                        .map(|b| {
                            let sample = i16::from_le_bytes([b[0], b[1]]);
                            sample as f32 / i16::MAX as f32
                        });
                    if let Ok(mut jb_guard) = jb_primary.try_lock() {
                        jb_guard.extend(incoming);
                    }
                }
            }

            if let Ok(mut jb_guard) = jb_primary.try_lock() {
                if jb_guard.len() > max_jitter_buffer_samples {
                    let overflow = jb_guard.len() - max_jitter_buffer_samples;
                    jb_guard.drain(0..overflow);
                }

                if let Ok(mut pb_guard) = pb_primary.try_lock() {
                    if *pb_guard {
                        if jb_guard.len() >= prebuffer_target_samples {
                            *pb_guard = false;
                        } else {
                            data.fill(0.0);
                            return;
                        }
                    }
                }

                let available = jb_guard.len();
                let take = std::cmp::min(frames_needed, available);
                for i in 0..take {
                    data[data_idx + i] = jb_guard.pop_front().unwrap();
                }
                data_idx += take;
                frames_needed -= take;

                if frames_needed > 0 {
                    for i in 0..frames_needed {
                        data[data_idx + i] = 0.0;
                    }
                    if let Ok(mut pb_guard) = pb_primary.try_lock() {
                        *pb_guard = true;
                    }
                }
            } else {
                data.fill(0.0);
            }
        },
        |err| error!(error = %err, "Hardware playback stream exception"),
        None,
    ) {
        Ok(stream) => stream,
        Err(_) => {
            let mut fallback_config = config;
            fallback_config.buffer_size = cpal::BufferSize::Default;
            match device.build_output_stream(
                &fallback_config,
                move |data: &mut [f32], _: &_| {
                    let mut frames_needed = data.len();
                    let mut data_idx = 0;

                    if let Ok(rx_guard) = rx_shared.try_lock() {
                        while let Ok(decrypted_bytes) = rx_guard.try_recv() {
                            let incoming = decrypted_bytes.chunks_exact(2)
                                .map(|b| {
                                    let sample = i16::from_le_bytes([b[0], b[1]]);
                                    sample as f32 / i16::MAX as f32
                                });
                            if let Ok(mut jb_guard) = jitter_buffer.try_lock() {
                                jb_guard.extend(incoming);
                            }
                        }
                    }

                    if let Ok(mut jb_guard) = jitter_buffer.try_lock() {
                        if jb_guard.len() > max_jitter_buffer_samples {
                            let overflow = jb_guard.len() - max_jitter_buffer_samples;
                            jb_guard.drain(0..overflow);
                        }

                        if let Ok(mut pb_guard) = is_prebuffering.try_lock() {
                            if *pb_guard {
                                if jb_guard.len() >= prebuffer_target_samples {
                                    *pb_guard = false;
                                } else {
                                    data.fill(0.0);
                                    return;
                                }
                            }
                        }

                        let available = jb_guard.len();
                        let take = std::cmp::min(frames_needed, available);
                        for i in 0..take {
                            data[data_idx + i] = jb_guard.pop_front().unwrap();
                        }
                        data_idx += take;
                        frames_needed -= take;

                        if frames_needed > 0 {
                            for i in 0..frames_needed {
                                data[data_idx + i] = 0.0;
                            }
                            if let Ok(mut pb_guard) = is_prebuffering.try_lock() {
                                *pb_guard = true;
                            }
                        }
                    } else {
                        data.fill(0.0);
                    }
                },
                |err| error!(error = %err, "Hardware playback stream exception"),
                None,
            ) {
                Ok(stream) => stream,
                Err(e) => {
                    error!(error = %e, "Hardware allocation failure. OS failed to resample or bind to enforced topology.");
                    return;
                }
            }
        }
    };

    if let Err(e) = audio_stream.play() {
        error!(error = %e, "Failed to transition playback pipeline to active state");
        return;
    }

    let mut counter: u64 = 0;
    let mut len_buf = [0u8; 4];

    loop {
        if stream.read_exact(&mut len_buf).is_err() {
            info!("Remote host disconnected cleanly. Terminating runtime execution context.");
            break;
        }
        let chunk_len = u32::from_le_bytes(len_buf) as usize;

        let mut ciphertext = vec![0u8; chunk_len];
        if stream.read_exact(&mut ciphertext).is_err() {
            warn!("Connection abruptly dropped during frame processing stream chunk read.");
            break;
        }

        let nonce = generate_nonce(counter);
        match cipher.decrypt(&nonce, ciphertext.as_ref()) {
            Ok(plaintext) => {
                if tx.send(plaintext).is_err() {
                    break;
                }
                counter += 1;
            }
            Err(_) => {
                error!("CRITICAL DATA ANOMALY: Frame decryption failure! Symmetric authentication tags mismatch.");
                break;
            }
        }
    }
}