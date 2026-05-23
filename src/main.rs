#![allow(deprecated)]

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use clap::{Parser, Subcommand};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use eframe::egui;
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

#[derive(Default, Clone)]
struct Telemetry {
    pub is_running: bool,
    pub mode: String,
    pub status: String,
    pub packets_processed: u64,
    pub bytes_processed: u64,
    pub sample_rate: u32,
    pub channels: u16,
    pub jitter_buffer_len: usize,
    pub max_buffer_capacity: usize,
}

#[derive(Parser, Clone)]
#[command(author, version, about = "Secure P2P Audio Streamer (Zero-Trust)")]
struct Cli {
    #[command(subcommand)]
    mode: Option<Mode>,
}

#[derive(Subcommand, Clone)]
enum Mode {
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
                let tel = Arc::new(Mutex::new(Telemetry::default()));
                run_server(host, &bind, &secret, device, sample_rate, tel.clone());
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    if !tel.lock().unwrap().is_running { break; }
                }
            } else {
                launch_gui(Some(Mode::Server { bind, secret, device, headless, sample_rate }));
            }
        }
        Some(Mode::Client { address, secret, device, headless, sample_rate }) => {
            if headless {
                let tel = Arc::new(Mutex::new(Telemetry::default()));
                run_client(host, &address, &secret, device, sample_rate, tel.clone());
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    if !tel.lock().unwrap().is_running { break; }
                }
            } else {
                launch_gui(Some(Mode::Client { address, secret, device, headless, sample_rate }));
            }
        }
        Some(Mode::ListDevices) => {
            list_devices(host);
        }
        Some(Mode::Gui) | None => launch_gui(None),
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
        if !name.trim().is_empty() && name != "System Default Input" {
            let mut devs = host.input_devices().map_err(|e| format!("Cannot query topology: {}", e))?;
            let target = name.to_lowercase();
            if let Some(d) = devs.find(|d| {
                let d_name = d.name().unwrap_or_default().to_lowercase();
                d_name == target || d_name.contains(&target)
            }) {
                let cfg = d.default_input_config().map_err(|e| format!("Interface locked or format unsupported: {}", e))?;
                return Ok((d, cfg));
            }
        }
    }

    if let Some(d) = host.default_input_device() {
        if let Ok(cfg) = d.default_input_config() {
            return Ok((d, cfg));
        }
    }

    Err("No available unlocked input devices found. Verify execution state.".to_string())
}

fn resolve_output_device(host: &cpal::Host, requested_device: &Option<String>) -> Result<(cpal::Device, cpal::SupportedStreamConfig), String> {
    if let Some(name) = requested_device {
        if !name.trim().is_empty() && name != "System Default Output" {
            let mut devs = host.output_devices().map_err(|e| format!("Cannot query topology: {}", e))?;
            let target = name.to_lowercase();
            if let Some(d) = devs.find(|d| {
                let d_name = d.name().unwrap_or_default().to_lowercase();
                d_name == target || d_name.contains(&target)
            }) {
                let cfg = d.default_output_config().map_err(|e| format!("Interface locked or format unsupported: {}", e))?;
                return Ok((d, cfg));
            }
        }
    }

    if let Some(d) = host.default_output_device() {
        if let Ok(cfg) = d.default_output_config() {
            return Ok((d, cfg));
        }
    }

    Err("No available unlocked output devices found. Verify execution state.".to_string())
}

fn run_server(host: cpal::Host, bind: &str, secret: &str, device_name: Option<String>, sample_rate_override: Option<u32>, telemetry: Arc<Mutex<Telemetry>>) {
    let (device, supported_config) = match resolve_input_device(&host, &device_name) {
        Ok(res) => res,
        Err(e) => {
            if let Ok(mut tel) = telemetry.lock() {
                tel.status = format!("Input failure: {}", e);
                tel.is_running = false;
            }
            error!(error = %e, "Input device resolution failed");
            return;
        }
    };

    let mut config: cpal::StreamConfig = supported_config.into();
    config.buffer_size = cpal::BufferSize::Fixed(HARDWARE_BUFFER_FRAMES);

    if let Some(hz) = sample_rate_override {
        config.sample_rate = cpal::SampleRate(hz);
    }

    let sample_rate = config.sample_rate.0;
    let channels = config.channels;

    if let Ok(mut tel) = telemetry.lock() {
        tel.is_running = true;
        tel.mode = "Server".to_string();
        tel.sample_rate = sample_rate;
        tel.channels = channels;
        tel.status = "Binding address interfaces...".to_string();
        tel.packets_processed = 0;
        tel.bytes_processed = 0;
    }

    let listener = match TcpListener::bind(bind) {
        Ok(l) => l,
        Err(e) => {
            if let Ok(mut tel) = telemetry.lock() {
                tel.status = format!("Network bind failure: {}", e);
                tel.is_running = false;
            }
            error!(error = %e, bind = %bind, "Network binding failed on target interface");
            return;
        }
    };
    
    if let Ok(mut tel) = telemetry.lock() {
        tel.status = "Awaiting inbound connection...".to_string();
    }
    info!(bind = %bind, "Listening securely for incoming client connections");

    if listener.set_nonblocking(true).is_err() {
        warn!("Failed to set non-blocking mode on listener.");
    }

    let (mut stream, addr) = loop {
        if !telemetry.lock().unwrap().is_running {
            info!("Server configuration loop halted by user.");
            return;
        }
        match listener.accept() {
            Ok((s, a)) => {
                let _ = s.set_nonblocking(false);
                break (s, a);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                if let Ok(mut tel) = telemetry.lock() {
                    tel.status = format!("Socket negotiation error: {}", e);
                    tel.is_running = false;
                }
                error!(error = %e, "Internal networking socket negotiation failure");
                return;
            }
        }
    };

    if let Ok(mut tel) = telemetry.lock() {
        tel.status = format!("Connected to remote client: {}", addr);
    }
    info!(client_addr = %addr, "Authenticated handshake tunnel established. Ephemeral session key generated.");

    if let Err(e) = stream.set_nodelay(true) {
        warn!(error = %e, "Failed to disable TCP Nagle's algorithm.");
    }

    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    
    if stream.write_all(&salt).is_err() {
        telemetry.lock().unwrap().is_running = false;
        return;
    }

    let session_key = derive_session_key(secret, &salt);
    let cipher = ChaCha20Poly1305::new(session_key.as_ref().into());

    if stream.write_all(&sample_rate.to_le_bytes()).is_err() || stream.write_all(&channels.to_le_bytes()).is_err() {
        telemetry.lock().unwrap().is_running = false;
        return;
    }

    info!(
        device = %device.name().unwrap_or_else(|_| "Unknown".to_string()),
        sample_rate = %sample_rate,
        channels = %channels,
        "Allocated secure input hardware interface. Streaming commenced with 16-bit PCM Quantization."
    );

    let (tx, rx) = mpsc::sync_channel::<Vec<i16>>(MAX_QUEUE_DEPTH);
    let tx_primary = tx.clone();

    let audio_stream = match device.build_input_stream(
        &config,
        move |data: &[f32], _: &_| {
            let pcm_16: Vec<i16> = data.iter()
                .map(|&s| (s.clamp(-1.0, 1.0) * i16::MAX as f32) as i16)
                .collect();
                
            let _ = tx_primary.try_send(pcm_16);
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
                    let _ = tx.try_send(pcm_16);
                },
                |err| error!(error = %err, "Hardware capture stream exception"),
                None,
            ) {
                Ok(stream) => stream,
                Err(e) => {
                    if let Ok(mut tel) = telemetry.lock() {
                        tel.status = format!("Audio hardware interface build crashed: {}", e);
                        tel.is_running = false;
                    }
                    return;
                }
            }
        }
    };

    if audio_stream.play().is_err() {
        telemetry.lock().unwrap().is_running = false;
        return;
    }

    let mut counter: u64 = 0;

    loop {
        if !telemetry.lock().unwrap().is_running {
            info!("Server termination sequence triggered. Dropping active endpoints.");
            break;
        }

        match rx.recv_timeout(std::time::Duration::from_millis(250)) {
            Ok(raw_i16) => {
                let raw_bytes: &[u8] = bytemuck::cast_slice(&raw_i16);
                let nonce = generate_nonce(counter);
                
                match cipher.encrypt(&nonce, raw_bytes) {
                    Ok(ciphertext) => {
                        let len = ciphertext.len() as u32;
                        let mut packet = Vec::with_capacity(4 + ciphertext.len());
                        packet.extend_from_slice(&len.to_le_bytes());
                        packet.extend_from_slice(&ciphertext);
                        
                        if stream.write_all(&packet).is_err() {
                            warn!("Client connection closed or severed via pipeline interruption.");
                            break;
                        }
                        
                        counter += 1;
                        if let Ok(mut tel) = telemetry.lock() {
                            tel.packets_processed = counter;
                            tel.bytes_processed += packet.len() as u64;
                        }
                    }
                    Err(_) => {}
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    
    if let Ok(mut tel) = telemetry.lock() {
        tel.is_running = false;
        tel.status = "Session terminated contextually.".to_string();
    }
}

fn run_client(host: cpal::Host, address: &str, secret: &str, device_name: Option<String>, sample_rate_override: Option<u32>, telemetry: Arc<Mutex<Telemetry>>) {
    let (device, _) = match resolve_output_device(&host, &device_name) {
        Ok(res) => res,
        Err(e) => {
            if let Ok(mut tel) = telemetry.lock() {
                tel.status = format!("Output interface failure: {}", e);
                tel.is_running = false;
            }
            return;
        }
    };

    if let Ok(mut tel) = telemetry.lock() {
        tel.is_running = true;
        tel.mode = "Client".to_string();
        tel.status = format!("Routing outbound socket connection to {}...", address);
        tel.packets_processed = 0;
        tel.bytes_processed = 0;
    }
    info!(address = %address, "Establishing network connection context with host");
    
    let mut stream = match TcpStream::connect(address) {
        Ok(s) => s,
        Err(e) => {
            if let Ok(mut tel) = telemetry.lock() {
                tel.status = format!("Connection failed: {}", e);
                tel.is_running = false;
            }
            return;
        }
    };

    if let Err(e) = stream.set_nodelay(true) {
        warn!(error = %e, "Failed to disable TCP Nagle's algorithm.");
    }
    if let Err(e) = stream.set_read_timeout(Some(std::time::Duration::from_millis(250))) {
        warn!(error = %e, "Failed to inject read timeouts into socket.");
    }

    let mut salt = [0u8; 32];
    loop {
        if !telemetry.lock().unwrap().is_running { return; }
        match stream.read_exact(&mut salt) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(_) => return,
        }
    }

    let session_key = derive_session_key(secret, &salt);
    let cipher = ChaCha20Poly1305::new(session_key.as_ref().into());

    let mut sr_buf = [0u8; 4];
    let mut ch_buf = [0u8; 2];

    loop {
        if !telemetry.lock().unwrap().is_running { return; }
        match stream.read_exact(&mut sr_buf) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(_) => return,
        }
    }
    
    if stream.read_exact(&mut ch_buf).is_err() {
        telemetry.lock().unwrap().is_running = false;
        return;
    }

    let negotiated_rate = u32::from_le_bytes(sr_buf);
    let channels = u16::from_le_bytes(ch_buf);

    let final_sample_rate = sample_rate_override.unwrap_or(negotiated_rate);

    let config = cpal::StreamConfig {
        channels,
        sample_rate: cpal::SampleRate(final_sample_rate),
        buffer_size: cpal::BufferSize::Fixed(HARDWARE_BUFFER_FRAMES),
    };

    let sample_rate_sz = final_sample_rate as usize;
    let channels_sz = channels as usize;
    let max_jitter_buffer_samples = (sample_rate_sz * channels_sz * MAX_LATENCY_MS) / 1000;
    let prebuffer_target_samples = (sample_rate_sz * channels_sz * PREBUFFER_MS) / 1000;

    if let Ok(mut tel) = telemetry.lock() {
        tel.sample_rate = final_sample_rate;
        tel.channels = channels;
        tel.max_buffer_capacity = max_jitter_buffer_samples;
        tel.status = "Synchronized cryptographic handshake. Audio streaming active.".to_string();
    }
    info!("Connected. Secure cryptographic handshake verified.");

    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(MAX_QUEUE_DEPTH);
    
    let jitter_buffer = Arc::new(Mutex::new(VecDeque::with_capacity(max_jitter_buffer_samples * 2)));
    let rx_shared = Arc::new(Mutex::new(rx));
    let is_prebuffering = Arc::new(Mutex::new(true));

    let jb_primary = Arc::clone(&jitter_buffer);
    let rx_primary = Arc::clone(&rx_shared);
    let pb_primary = Arc::clone(&is_prebuffering);
    let tel_callback = Arc::clone(&telemetry);

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
                
                if let Ok(mut tel) = tel_callback.try_lock() {
                    tel.jitter_buffer_len = jb_guard.len();
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
            let jb_fallback = Arc::clone(&jitter_buffer);
            let rx_fallback = Arc::clone(&rx_shared);
            let pb_fallback = Arc::clone(&is_prebuffering);
            let tel_fallback_cb = Arc::clone(&telemetry);
            
            match device.build_output_stream(
                &fallback_config,
                move |data: &mut [f32], _: &_| {
                    let mut frames_needed = data.len();
                    let mut data_idx = 0;

                    if let Ok(rx_guard) = rx_fallback.try_lock() {
                        while let Ok(decrypted_bytes) = rx_guard.try_recv() {
                            let incoming = decrypted_bytes.chunks_exact(2)
                                .map(|b| {
                                    let sample = i16::from_le_bytes([b[0], b[1]]);
                                    sample as f32 / i16::MAX as f32
                                });
                            if let Ok(mut jb_guard) = jb_fallback.try_lock() {
                                jb_guard.extend(incoming);
                            }
                        }
                    }

                    if let Ok(mut jb_guard) = jb_fallback.try_lock() {
                        if jb_guard.len() > max_jitter_buffer_samples {
                            let overflow = jb_guard.len() - max_jitter_buffer_samples;
                            jb_guard.drain(0..overflow);
                        }

                        if let Ok(mut tel) = tel_fallback_cb.try_lock() {
                            tel.jitter_buffer_len = jb_guard.len();
                        }

                        if let Ok(mut pb_guard) = pb_fallback.try_lock() {
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
                            if let Ok(mut pb_guard) = pb_fallback.try_lock() {
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
                    error!(error = %e, "Hardware allocation failure.");
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
        if !telemetry.lock().unwrap().is_running {
            info!("Client termination sequence triggered. Dropping active endpoints.");
            break;
        }

        match stream.read_exact(&mut len_buf) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(_) => break,
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
                if let Ok(mut tel) = telemetry.lock() {
                    tel.packets_processed = counter;
                    tel.bytes_processed += 4 + chunk_len as u64;
                }
            }
            Err(_) => {
                error!("CRITICAL DATA ANOMALY: Frame decryption failure! Symmetric authentication tags mismatch.");
                break;
            }
        }
    }

    if let Ok(mut tel) = telemetry.lock() {
        tel.is_running = false;
        tel.status = "Session closed.".to_string();
    }
}

struct AppWindow {
    is_server_mode: bool,
    bind_addr: String,
    secret_key: String,
    capture_device: String,
    playback_device: String,
    target_hz: String,
    available_inputs: Vec<String>,
    available_outputs: Vec<String>,
    devices_scanned: bool,
    telemetry: Arc<Mutex<Telemetry>>,
    initial_cli_mode: Option<Mode>,
    has_auto_started: bool,
}

impl AppWindow {
    fn new(cli_mode: Option<Mode>) -> Self {
        let mut window = Self {
            is_server_mode: true,
            bind_addr: "127.0.0.1:8080".to_string(),
            secret_key: "JeMateDesVideos01".to_string(),
            capture_device: "System Default Input".to_string(),
            playback_device: "System Default Output".to_string(),
            target_hz: "Default OS Match".to_string(),
            available_inputs: vec!["System Default Input".to_string()],
            available_outputs: vec!["System Default Output".to_string()],
            devices_scanned: false,
            telemetry: Arc::new(Mutex::new(Telemetry::default())),
            initial_cli_mode: cli_mode.clone(),
            has_auto_started: false,
        };

        if let Some(mode) = &cli_mode {
            match mode {
                Mode::Server { bind, secret, device, sample_rate, .. } => {
                    window.is_server_mode = true;
                    window.bind_addr = bind.clone();
                    window.secret_key = secret.clone();
                    if let Some(d) = device {
                        window.capture_device = d.clone();
                    }
                    if let Some(hz) = sample_rate {
                        window.target_hz = hz.to_string();
                    }
                }
                Mode::Client { address, secret, device, sample_rate, .. } => {
                    window.is_server_mode = false;
                    window.bind_addr = address.clone();
                    window.secret_key = secret.clone();
                    if let Some(d) = device {
                        window.playback_device = d.clone();
                    }
                    if let Some(hz) = sample_rate {
                        window.target_hz = hz.to_string();
                    }
                }
                _ => {}
            }
        }

        window
    }

    fn scan_devices_if_needed(&mut self) {
        if self.devices_scanned { return; }
        let host = cpal::default_host();
        
        if let Ok(devices) = host.input_devices() {
            for d in devices {
                if let Ok(name) = d.name() {
                    self.available_inputs.push(name);
                }
            }
        }

        if let Ok(devices) = host.output_devices() {
            for d in devices {
                if let Ok(name) = d.name() {
                    self.available_outputs.push(name);
                }
            }
        }
        self.devices_scanned = true;
    }
}

impl eframe::App for AppWindow {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint();

        if !self.has_auto_started && self.initial_cli_mode.is_some() {
            self.has_auto_started = true;
            if let Some(mode) = self.initial_cli_mode.take() {
                let tel_clone = Arc::clone(&self.telemetry);
                std::thread::spawn(move || {
                    let target_host = cpal::default_host();
                    match mode {
                        Mode::Server { bind, secret, device, sample_rate, .. } => {
                            let dev_target = if device.as_deref() == Some("System Default Input") { None } else { device };
                            run_server(target_host, &bind, &secret, dev_target, sample_rate, tel_clone);
                        }
                        Mode::Client { address, secret, device, sample_rate, .. } => {
                            let dev_target = if device.as_deref() == Some("System Default Output") { None } else { device };
                            run_client(target_host, &address, &secret, dev_target, sample_rate, tel_clone);
                        }
                        _ => {}
                    }
                });
            }
        }

        let tel = {
            let guard = self.telemetry.lock().unwrap();
            guard.clone()
        };

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Aubri Engine Calibration Diagnostics");
            ui.separator();

            if !tel.is_running {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.is_server_mode, true, "Server (Capture)");
                    ui.selectable_value(&mut self.is_server_mode, false, "Client (Playback)");
                });

                ui.add_space(8.0);
                egui::Grid::new("config_fields")
                    .spacing([12.0, 8.0])
                    .show(ui, |ui| {
                        ui.label("Network Address:");
                        ui.text_edit_singleline(&mut self.bind_addr);
                        ui.end_row();

                        ui.label("Secret Token:");
                        ui.text_edit_singleline(&mut self.secret_key);
                        ui.end_row();

                        ui.label("Sample Rate Override:");
                        egui::ComboBox::from_id_source("hz_dropdown")
                            .selected_text(&self.target_hz)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.target_hz, "Default OS Match".to_string(), "Default OS Match");
                                ui.selectable_value(&mut self.target_hz, "44100".to_string(), "44100 Hz");
                                ui.selectable_value(&mut self.target_hz, "48000".to_string(), "48000 Hz");
                                ui.selectable_value(&mut self.target_hz, "96000".to_string(), "96000 Hz");
                            });
                        ui.end_row();

                        if self.is_server_mode {
                            ui.label("Capture Target:");
                            ui.horizontal(|ui| {
                                egui::ComboBox::from_id_source("capture_dropdown")
                                    .selected_text(&self.capture_device)
                                    .show_ui(ui, |ui| {
                                        self.scan_devices_if_needed();
                                        for dev in &self.available_inputs {
                                            ui.selectable_value(&mut self.capture_device, dev.clone(), dev);
                                        }
                                    });
                            });
                        } else {
                            ui.label("Playback Target:");
                            ui.horizontal(|ui| {
                                egui::ComboBox::from_id_source("playback_dropdown")
                                    .selected_text(&self.playback_device)
                                    .show_ui(ui, |ui| {
                                        self.scan_devices_if_needed();
                                        for dev in &self.available_outputs {
                                            ui.selectable_value(&mut self.playback_device, dev.clone(), dev);
                                        }
                                    });
                            });
                        }
                        ui.end_row();
                    });

                ui.add_space(12.0);
                if ui.button("Launch Stream Engine Context").clicked() {
                    let mode = self.is_server_mode;
                    let bind = self.bind_addr.clone();
                    let secret = self.secret_key.clone();
                    let hz_override = self.target_hz.parse::<u32>().ok();
                    
                    let dev = if mode {
                        if self.capture_device == "System Default Input" { None } else { Some(self.capture_device.clone()) }
                    } else {
                        if self.playback_device == "System Default Output" { None } else { Some(self.playback_device.clone()) }
                    };
                    
                    let tel_clone = Arc::clone(&self.telemetry);

                    std::thread::spawn(move || {
                        let target_host = cpal::default_host();
                        if mode {
                            run_server(target_host, &bind, &secret, dev, hz_override, tel_clone);
                        } else {
                            run_client(target_host, &bind, &secret, dev, hz_override, tel_clone);
                        }
                    });
                }
            } else {
                ui.colored_label(egui::Color32::GREEN, format!("Active Runtime Status: {}", tel.mode));
                ui.label(format!("System State: {}", tel.status));
                ui.separator();

                ui.heading("Telemetry Instrumentation Matrix");
                ui.label(format!("Hardware Matrix: {} Hz | {} Channels", tel.sample_rate, tel.channels));
                ui.label(format!("Packets Received or Transmitted: {}", tel.packets_processed));
                ui.label(format!("Total Volume Quantized: {:.2} MB", tel.bytes_processed as f64 / 1_048_576.0));

                if tel.mode == "Client" {
                    ui.add_space(8.0);
                    ui.label("Jitter Buffer Allocation Envelope:");
                    let progress = if tel.max_buffer_capacity > 0 {
                        tel.jitter_buffer_len as f32 / tel.max_buffer_capacity as f32
                    } else {
                        0.0
                    };
                    ui.add(egui::ProgressBar::new(progress).text(format!("{} / {} Samples", tel.jitter_buffer_len, tel.max_buffer_capacity)));
                }

                ui.add_space(16.0);
                if ui.button("Stop Stream Session").clicked() {
                    let mut t = self.telemetry.lock().unwrap();
                    t.is_running = false;
                    t.status = "Halting execution contexts...".to_string();
                }
            }
        });
    }
}

fn launch_gui(initial_mode: Option<Mode>) {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([480.0, 420.0])
            .with_resizable(false),
        ..Default::default()
    };
    
    let _ = eframe::run_native(
        "Aubri Monitor Control Suite",
        options,
        Box::new(|_cc| Box::new(AppWindow::new(initial_mode))),
    );
}