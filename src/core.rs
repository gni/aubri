use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use rand::Rng;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use tracing::{error, info, warn};

const KDF_CONTEXT: &str = "aubri_p2p_audio_v2";
const MAX_QUEUE_DEPTH: usize = 128;
const HARDWARE_BUFFER_FRAMES: u32 = 256;
const MAX_SAFE_PAYLOAD_BYTES: usize = 16384;

const HANDSHAKE_REQ: &[u8] = b"AUBRI_REQ";
const HANDSHAKE_ACK: &[u8] = b"AUBRI_ACK";

#[derive(Default, Clone)]
pub struct Telemetry {
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

pub fn list_devices(host: cpal::Host) {
    info!("Initializing audio device enumeration routine");
    
    let default_in = host.default_input_device().and_then(|d| d.name().ok());
    let default_out = host.default_output_device().and_then(|d| d.name().ok());

    println!("Input interfaces (capture):");
    if let Ok(devices) = host.input_devices() {
        for device in devices {
            if let Ok(name) = device.name() {
                let is_default = if Some(&name) == default_in.as_ref() { " [DEFAULT]" } else { "" };
                let is_monitor = if name.to_lowercase().contains("monitor") { " [VIRTUAL LOOPBACK]" } else { "" };
                println!("  * {}{}{}", name, is_default, is_monitor);
            }
        }
    } else {
        error!("Hardware exception reading input devices");
    }

    println!("\nOutput interfaces (playback):");
    if let Ok(devices) = host.output_devices() {
        for device in devices {
            if let Ok(name) = device.name() {
                let is_default = if Some(&name) == default_out.as_ref() { " [DEFAULT]" } else { "" };
                let is_null_sink = if name.to_lowercase().contains("aubri") { " [VIRTUAL SINK]" } else { "" };
                println!("  * {}{}{}", name, is_default, is_null_sink);
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
            return Err(format!("Strict matching failed. No input device contains the identifier '{}'.", name));
        }
    }

    if let Some(d) = host.default_input_device() {
        if let Ok(cfg) = d.default_input_config() {
            return Ok((d, cfg));
        }
    }

    if let Ok(mut devs) = host.input_devices() {
        if let Some(d) = devs.find(|d| d.default_input_config().is_ok()) {
            let cfg = d.default_input_config().unwrap();
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
            return Err(format!("Strict matching failed. No output device contains the identifier '{}'.", name));
        }
    }

    if let Some(d) = host.default_output_device() {
        if let Ok(cfg) = d.default_output_config() {
            return Ok((d, cfg));
        }
    }

    if let Ok(mut devs) = host.output_devices() {
        if let Some(d) = devs.find(|d| d.default_output_config().is_ok()) {
            let cfg = d.default_output_config().unwrap();
            return Ok((d, cfg));
        }
    }

    Err("No available unlocked output devices found. Verify execution state.".to_string())
}

pub fn run_server(host: cpal::Host, bind: &str, secret: &str, device_name: Option<String>, sample_rate_override: Option<u32>, protocol: &str, telemetry: Arc<Mutex<Telemetry>>) {
    if protocol.to_lowercase() == "tcp" {
        run_server_tcp(host, bind, secret, device_name, sample_rate_override, telemetry);
    } else {
        run_server_udp(host, bind, secret, device_name, sample_rate_override, telemetry);
    }
}

pub fn run_client(host: cpal::Host, address: &str, secret: &str, device_name: Option<String>, sample_rate_override: Option<u32>, protocol: &str, latency: Option<usize>, prebuffer: Option<usize>, telemetry: Arc<Mutex<Telemetry>>) {
    if protocol.to_lowercase() == "tcp" {
        run_client_tcp(host, address, secret, device_name, sample_rate_override, latency, prebuffer, telemetry);
    } else {
        run_client_udp(host, address, secret, device_name, sample_rate_override, latency, prebuffer, telemetry);
    }
}

fn run_server_tcp(host: cpal::Host, bind: &str, secret: &str, device_name: Option<String>, sample_rate_override: Option<u32>, telemetry: Arc<Mutex<Telemetry>>) {
    let (device, supported_config) = match resolve_input_device(&host, &device_name) {
        Ok(res) => res,
        Err(e) => {
            if let Ok(mut tel) = telemetry.lock() { tel.status = format!("Input failure: {}", e); tel.is_running = false; }
            error!(error = %e, "Input device resolution failed");
            return;
        }
    };

    let mut config: cpal::StreamConfig = supported_config.into();
    config.buffer_size = cpal::BufferSize::Fixed(HARDWARE_BUFFER_FRAMES);
    if let Some(hz) = sample_rate_override { config.sample_rate = hz; }

    let sample_rate = config.sample_rate;
    let channels = config.channels;

    if let Ok(mut tel) = telemetry.lock() {
        tel.is_running = true;
        tel.mode = "Server (TCP)".to_string();
        tel.sample_rate = sample_rate;
        tel.channels = channels;
        tel.status = "Binding address interfaces...".to_string();
        tel.packets_processed = 0;
        tel.bytes_processed = 0;
    }

    let listener = match TcpListener::bind(bind) {
        Ok(l) => l,
        Err(e) => {
            if let Ok(mut tel) = telemetry.lock() { tel.status = format!("Network bind failure: {}", e); tel.is_running = false; }
            error!(error = %e, bind = %bind, "Network binding failed");
            return;
        }
    };
    
    if let Ok(mut tel) = telemetry.lock() { tel.status = "Awaiting inbound connection...".to_string(); }
    info!(bind = %bind, "Listening securely for incoming client connections (TCP)");

    let _ = listener.set_nonblocking(true);

    let (mut stream, addr) = loop {
        if let Ok(guard) = telemetry.lock() { if !guard.is_running { return; } }
        match listener.accept() {
            Ok((s, a)) => { let _ = s.set_nonblocking(false); break (s, a); }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(std::time::Duration::from_millis(100)),
            Err(e) => {
                if let Ok(mut tel) = telemetry.lock() { tel.status = format!("Socket error: {}", e); tel.is_running = false; }
                return;
            }
        }
    };

    if let Ok(mut tel) = telemetry.lock() { tel.status = format!("Connected to remote client: {}", addr); }
    let _ = stream.set_nodelay(true);

    let mut salt = [0u8; 32];
    rand::rng().fill_bytes(&mut salt);
    if stream.write_all(&salt).is_err() { if let Ok(mut tel) = telemetry.lock() { tel.is_running = false; } return; }

    let session_key = derive_session_key(secret, &salt);
    let cipher = ChaCha20Poly1305::new(session_key.as_ref().into());

    if stream.write_all(&sample_rate.to_le_bytes()).is_err() || stream.write_all(&channels.to_le_bytes()).is_err() {
        if let Ok(mut tel) = telemetry.lock() { tel.is_running = false; }
        return;
    }

    let (tx, rx) = mpsc::sync_channel::<Vec<i16>>(MAX_QUEUE_DEPTH);
    let tx_primary = tx.clone();

    let audio_stream = device.build_input_stream(
        &config,
        move |data: &[f32], _: &_| {
            let pcm_16: Vec<i16> = data.iter().map(|&s| (s.clamp(-1.0, 1.0) * i16::MAX as f32) as i16).collect();
            let _ = tx_primary.try_send(pcm_16);
        },
        |err| error!(error = %err, "Hardware capture exception"),
        None,
    ).unwrap();

    if audio_stream.play().is_err() { if let Ok(mut tel) = telemetry.lock() { tel.is_running = false; } return; }

    let mut counter: u64 = 0;
    loop {
        if let Ok(guard) = telemetry.lock() { if !guard.is_running { break; } }
        match rx.recv_timeout(std::time::Duration::from_millis(250)) {
            Ok(raw_i16) => {
                let raw_bytes: &[u8] = bytemuck::cast_slice(&raw_i16);
                let nonce = generate_nonce(counter);
                if let Ok(ciphertext) = cipher.encrypt(&nonce, raw_bytes) {
                    let len = ciphertext.len() as u32;
                    let mut packet = Vec::with_capacity(4 + ciphertext.len());
                    packet.extend_from_slice(&len.to_le_bytes());
                    packet.extend_from_slice(&ciphertext);
                    
                    if stream.write_all(&packet).is_err() { break; }
                    counter += 1;
                    if let Ok(mut tel) = telemetry.lock() { tel.packets_processed = counter; tel.bytes_processed += packet.len() as u64; }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        }
    }
    if let Ok(mut tel) = telemetry.lock() { tel.is_running = false; tel.status = "Session closed.".to_string(); }
}

fn run_client_tcp(host: cpal::Host, address: &str, secret: &str, device_name: Option<String>, sample_rate_override: Option<u32>, latency: Option<usize>, prebuffer: Option<usize>, telemetry: Arc<Mutex<Telemetry>>) {
    let (device, _) = match resolve_output_device(&host, &device_name) {
        Ok(res) => res,
        Err(e) => {
            if let Ok(mut tel) = telemetry.lock() { tel.status = format!("Output interface failure: {}", e); tel.is_running = false; }
            return;
        }
    };

    if let Ok(mut tel) = telemetry.lock() {
        tel.is_running = true;
        tel.mode = "Client (TCP)".to_string();
        tel.status = format!("Routing outbound socket connection to {}...", address);
        tel.packets_processed = 0;
        tel.bytes_processed = 0;
    }
    
    let mut stream = match TcpStream::connect(address) {
        Ok(s) => s,
        Err(e) => {
            if let Ok(mut tel) = telemetry.lock() { tel.status = format!("Connection failed: {}", e); tel.is_running = false; }
            return;
        }
    };

    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(250)));

    let mut salt = [0u8; 32];
    loop {
        if let Ok(guard) = telemetry.lock() { if !guard.is_running { return; } }
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
        if let Ok(guard) = telemetry.lock() { if !guard.is_running { return; } }
        match stream.read_exact(&mut sr_buf) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(_) => return,
        }
    }
    if stream.read_exact(&mut ch_buf).is_err() { if let Ok(mut tel) = telemetry.lock() { tel.is_running = false; } return; }

    let negotiated_rate = u32::from_le_bytes(sr_buf);
    let channels = u16::from_le_bytes(ch_buf);
    let final_sample_rate = sample_rate_override.unwrap_or(negotiated_rate);

    let config = cpal::StreamConfig {
        channels,
        sample_rate: final_sample_rate,
        buffer_size: cpal::BufferSize::Fixed(HARDWARE_BUFFER_FRAMES),
    };

    let actual_latency = latency.unwrap_or(350);
    let actual_prebuffer = prebuffer.unwrap_or(120);

    let sample_rate_sz = final_sample_rate as usize;
    let channels_sz = channels as usize;
    let max_jitter_buffer_samples = (sample_rate_sz * channels_sz * actual_latency) / 1000;
    let prebuffer_target_samples = (sample_rate_sz * channels_sz * actual_prebuffer) / 1000;

    if let Ok(mut tel) = telemetry.lock() {
        tel.sample_rate = final_sample_rate;
        tel.channels = channels;
        tel.max_buffer_capacity = max_jitter_buffer_samples;
        tel.status = "Synchronized cryptographic handshake. Audio streaming active.".to_string();
    }

    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(MAX_QUEUE_DEPTH);
    let jitter_buffer = Arc::new(Mutex::new(VecDeque::with_capacity(max_jitter_buffer_samples * 2)));
    let rx_shared = Arc::new(Mutex::new(rx));
    let is_prebuffering = Arc::new(Mutex::new(true));

    let jb_primary = Arc::clone(&jitter_buffer);
    let rx_primary = Arc::clone(&rx_shared);
    let pb_primary = Arc::clone(&is_prebuffering);
    let tel_callback = Arc::clone(&telemetry);

    let audio_stream = device.build_output_stream(
        &config,
        move |data: &mut [f32], _: &_| {
            let frames_needed = data.len();
            let data_idx = 0;

            if let Ok(rx_guard) = rx_primary.try_lock() {
                while let Ok(decrypted_bytes) = rx_guard.try_recv() {
                    let incoming = decrypted_bytes.chunks_exact(2).map(|b| i16::from_le_bytes([b[0], b[1]]) as f32 / i16::MAX as f32);
                    if let Ok(mut jb_guard) = jb_primary.try_lock() { jb_guard.extend(incoming); }
                }
            }

            if let Ok(mut jb_guard) = jb_primary.try_lock() {
                if jb_guard.len() > max_jitter_buffer_samples {
                    let overflow = jb_guard.len() - max_jitter_buffer_samples;
                    jb_guard.drain(0..overflow);
                }
                if let Ok(mut tel) = tel_callback.try_lock() { tel.jitter_buffer_len = jb_guard.len(); }

                if let Ok(mut pb_guard) = pb_primary.try_lock() {
                    if *pb_guard {
                        if jb_guard.len() >= prebuffer_target_samples {
                            *pb_guard = false;
                        } else {
                            data.fill(0.0);
                            return;
                        }
                    } else if jb_guard.len() < frames_needed {
                        *pb_guard = true;
                        data.fill(0.0);
                        return;
                    }
                }

                let take = frames_needed;
                for i in 0..take { data[data_idx + i] = jb_guard.pop_front().unwrap(); }
            } else { data.fill(0.0); }
        },
        |err| error!(error = %err, "Playback stream exception"),
        None,
    ).unwrap();

    if audio_stream.play().is_err() { if let Ok(mut tel) = telemetry.lock() { tel.is_running = false; } return; }

    let mut counter: u64 = 0;
    let mut len_buf = [0u8; 4];

    loop {
        if let Ok(guard) = telemetry.lock() { if !guard.is_running { break; } }
        match stream.read_exact(&mut len_buf) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(_) => break,
        }
        
        let chunk_len = u32::from_le_bytes(len_buf) as usize;
        if chunk_len > MAX_SAFE_PAYLOAD_BYTES { break; }

        let mut ciphertext = vec![0u8; chunk_len];
        if stream.read_exact(&mut ciphertext).is_err() { break; }

        let nonce = generate_nonce(counter);
        match cipher.decrypt(&nonce, ciphertext.as_ref()) {
            Ok(plaintext) => {
                let _ = tx.try_send(plaintext);
                counter += 1;
                if let Ok(mut tel) = telemetry.lock() {
                    tel.packets_processed = counter;
                    tel.bytes_processed += 4 + chunk_len as u64;
                }
            }
            Err(_) => break,
        }
    }
    if let Ok(mut tel) = telemetry.lock() { tel.is_running = false; tel.status = "Session closed.".to_string(); }
}

fn run_server_udp(host: cpal::Host, bind: &str, secret: &str, device_name: Option<String>, sample_rate_override: Option<u32>, telemetry: Arc<Mutex<Telemetry>>) {
    let (device, supported_config) = match resolve_input_device(&host, &device_name) {
        Ok(res) => res,
        Err(e) => {
            if let Ok(mut tel) = telemetry.lock() { tel.status = format!("Input failure: {}", e); tel.is_running = false; }
            error!(error = %e, "Input device resolution failed");
            return;
        }
    };

    let mut config: cpal::StreamConfig = supported_config.into();
    config.buffer_size = cpal::BufferSize::Fixed(HARDWARE_BUFFER_FRAMES);

    if let Some(hz) = sample_rate_override {
        config.sample_rate = hz;
    }

    let sample_rate = config.sample_rate;
    let channels = config.channels;

    if let Ok(mut tel) = telemetry.lock() {
        tel.is_running = true;
        tel.mode = "Server (UDP)".to_string();
        tel.sample_rate = sample_rate;
        tel.channels = channels;
        tel.status = "Binding address interfaces...".to_string();
        tel.packets_processed = 0;
        tel.bytes_processed = 0;
    }

    let socket = match UdpSocket::bind(bind) {
        Ok(s) => s,
        Err(e) => {
            if let Ok(mut tel) = telemetry.lock() { tel.status = format!("Network bind failure: {}", e); tel.is_running = false; }
            error!(error = %e, bind = %bind, "Network binding failed on target interface");
            return;
        }
    };
    
    if let Ok(mut tel) = telemetry.lock() { tel.status = "Awaiting inbound UDP handshake...".to_string(); }
    info!(bind = %bind, "Listening securely for incoming UDP connection requests");

    if let Err(e) = socket.set_read_timeout(Some(std::time::Duration::from_millis(250))) { warn!(error = %e, "Failed to apply non-blocking timeouts to socket"); }

    let mut buf = [0u8; 1024];
    
    let client_addr = loop {
        if let Ok(guard) = telemetry.lock() { if !guard.is_running { info!("Server configuration loop halted by user."); return; } }
        match socket.recv_from(&mut buf) {
            Ok((size, addr)) => {
                if size == HANDSHAKE_REQ.len() && &buf[0..size] == HANDSHAKE_REQ {
                    break addr;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => { error!(error = %e, "Socket read exception during handshake"); }
        }
    };

    if let Ok(mut tel) = telemetry.lock() { tel.status = format!("Connected to remote client: {}", client_addr); }
    info!(client_addr = %client_addr, "Handshake request verified. Deriving ephemeral session key.");

    let mut salt = [0u8; 32];
    rand::rng().fill_bytes(&mut salt);
    let session_key = derive_session_key(secret, &salt);
    let cipher = ChaCha20Poly1305::new(session_key.as_ref().into());

    let mut ack_packet = Vec::with_capacity(HANDSHAKE_ACK.len() + 32 + 4 + 2);
    ack_packet.extend_from_slice(HANDSHAKE_ACK);
    ack_packet.extend_from_slice(&salt);
    ack_packet.extend_from_slice(&sample_rate.to_le_bytes());
    ack_packet.extend_from_slice(&channels.to_le_bytes());

    for _ in 0..5 { let _ = socket.send_to(&ack_packet, client_addr); std::thread::sleep(std::time::Duration::from_millis(10)); }

    let (tx, rx) = mpsc::sync_channel::<Vec<i16>>(MAX_QUEUE_DEPTH);
    let tx_primary = tx.clone();

    let audio_stream = match device.build_input_stream(
        &config,
        move |data: &[f32], _: &_| {
            let pcm_16: Vec<i16> = data.iter().map(|&s| (s.clamp(-1.0, 1.0) * i16::MAX as f32) as i16).collect();
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
                    let pcm_16: Vec<i16> = data.iter().map(|&s| (s.clamp(-1.0, 1.0) * i16::MAX as f32) as i16).collect();
                    let _ = tx.try_send(pcm_16);
                },
                |err| error!(error = %err, "Hardware capture stream exception"),
                None,
            ) {
                Ok(stream) => stream,
                Err(e) => {
                    if let Ok(mut tel) = telemetry.lock() { tel.status = format!("Audio hardware interface build crashed: {}", e); tel.is_running = false; }
                    return;
                }
            }
        }
    };

    if audio_stream.play().is_err() { if let Ok(mut tel) = telemetry.lock() { tel.is_running = false; } return; }

    let mut counter: u64 = 0;

    loop {
        if let Ok(guard) = telemetry.lock() { if !guard.is_running { break; } }
        match rx.recv_timeout(std::time::Duration::from_millis(250)) {
            Ok(raw_i16) => {
                let raw_bytes: &[u8] = bytemuck::cast_slice(&raw_i16);
                counter += 1;
                let nonce = generate_nonce(counter);
                
                match cipher.encrypt(&nonce, raw_bytes) {
                    Ok(ciphertext) => {
                        let mut packet = Vec::with_capacity(8 + ciphertext.len());
                        packet.extend_from_slice(&counter.to_le_bytes());
                        packet.extend_from_slice(&ciphertext);
                        let _ = socket.send_to(&packet, client_addr);
                        
                        if let Ok(mut tel) = telemetry.lock() { tel.packets_processed = counter; tel.bytes_processed += packet.len() as u64; }
                    }
                    Err(_) => {}
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    
    if let Ok(mut tel) = telemetry.lock() { tel.is_running = false; tel.status = "Session terminated contextually.".to_string(); }
}

fn run_client_udp(host: cpal::Host, address: &str, secret: &str, device_name: Option<String>, sample_rate_override: Option<u32>, latency: Option<usize>, prebuffer: Option<usize>, telemetry: Arc<Mutex<Telemetry>>) {
    let (device, _) = match resolve_output_device(&host, &device_name) {
        Ok(res) => res,
        Err(e) => {
            if let Ok(mut tel) = telemetry.lock() { tel.status = format!("Output interface failure: {}", e); tel.is_running = false; }
            return;
        }
    };

    if let Ok(mut tel) = telemetry.lock() {
        tel.is_running = true;
        tel.mode = "Client (UDP)".to_string();
        tel.status = format!("Routing outbound socket connection to {}...", address);
        tel.packets_processed = 0;
        tel.bytes_processed = 0;
    }
    
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            if let Ok(mut tel) = telemetry.lock() { tel.status = format!("Local socket bind failed: {}", e); tel.is_running = false; }
            return;
        }
    };

    if let Err(e) = socket.connect(address) {
        if let Ok(mut tel) = telemetry.lock() { tel.status = format!("Failed to route UDP to target address: {}", e); tel.is_running = false; }
        return;
    }

    if let Err(e) = socket.set_read_timeout(Some(std::time::Duration::from_millis(500))) { warn!(error = %e, "Failed to inject read timeouts into socket."); }

    let mut buf = [0u8; MAX_SAFE_PAYLOAD_BYTES];
    let expected_ack_size = HANDSHAKE_ACK.len() + 32 + 4 + 2;

    let (salt, negotiated_rate, channels) = loop {
        if let Ok(guard) = telemetry.lock() { if !guard.is_running { return; } }
        let _ = socket.send(HANDSHAKE_REQ);

        match socket.recv(&mut buf) {
            Ok(size) => {
                if size == expected_ack_size && &buf[0..HANDSHAKE_ACK.len()] == HANDSHAKE_ACK {
                    let mut offset = HANDSHAKE_ACK.len();
                    
                    let mut s = [0u8; 32];
                    s.copy_from_slice(&buf[offset..offset + 32]); 
                    offset += 32;
                    
                    let mut sr_buf = [0u8; 4]; 
                    sr_buf.copy_from_slice(&buf[offset..offset + 4]); 
                    let nr = u32::from_le_bytes(sr_buf); 
                    offset += 4;
                    
                    let mut ch_buf = [0u8; 2]; 
                    ch_buf.copy_from_slice(&buf[offset..offset + 2]); 
                    let ch = u16::from_le_bytes(ch_buf);
                    
                    break (s, nr, ch);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(_) => return,
        }
    };

    let session_key = derive_session_key(secret, &salt);
    let cipher = ChaCha20Poly1305::new(session_key.as_ref().into());
    let final_sample_rate = sample_rate_override.unwrap_or(negotiated_rate);

    let config = cpal::StreamConfig { channels, sample_rate: final_sample_rate, buffer_size: cpal::BufferSize::Fixed(HARDWARE_BUFFER_FRAMES) };
    
    let actual_latency = latency.unwrap_or(350);
    let actual_prebuffer = prebuffer.unwrap_or(120);

    let sample_rate_sz = final_sample_rate as usize;
    let channels_sz = channels as usize;
    let max_jitter_buffer_samples = (sample_rate_sz * channels_sz * actual_latency) / 1000;
    let prebuffer_target_samples = (sample_rate_sz * channels_sz * actual_prebuffer) / 1000;

    if let Ok(mut tel) = telemetry.lock() {
        tel.sample_rate = final_sample_rate;
        tel.channels = channels;
        tel.max_buffer_capacity = max_jitter_buffer_samples;
        tel.status = "Synchronized UDP cryptographic handshake. Audio streaming active.".to_string();
    }

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
            let frames_needed = data.len();
            let data_idx = 0;

            if let Ok(rx_guard) = rx_primary.try_lock() {
                while let Ok(decrypted_bytes) = rx_guard.try_recv() {
                    let incoming = decrypted_bytes.chunks_exact(2).map(|b| i16::from_le_bytes([b[0], b[1]]) as f32 / i16::MAX as f32);
                    if let Ok(mut jb_guard) = jb_primary.try_lock() { jb_guard.extend(incoming); }
                }
            }

            if let Ok(mut jb_guard) = jb_primary.try_lock() {
                if jb_guard.len() > max_jitter_buffer_samples {
                    let overflow = jb_guard.len() - max_jitter_buffer_samples;
                    jb_guard.drain(0..overflow);
                }
                
                if let Ok(mut tel) = tel_callback.try_lock() { tel.jitter_buffer_len = jb_guard.len(); }

                if let Ok(mut pb_guard) = pb_primary.try_lock() {
                    if *pb_guard {
                        if jb_guard.len() >= prebuffer_target_samples {
                            *pb_guard = false;
                        } else {
                            data.fill(0.0);
                            return;
                        }
                    } else if jb_guard.len() < frames_needed {
                        *pb_guard = true;
                        data.fill(0.0);
                        return;
                    }
                }

                let take = frames_needed;
                for i in 0..take { data[data_idx + i] = jb_guard.pop_front().unwrap(); }
            } else { data.fill(0.0); }
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
            
            device.build_output_stream(
                &fallback_config,
                move |data: &mut [f32], _: &_| {
                    let frames_needed = data.len();
                    let data_idx = 0;

                    if let Ok(rx_guard) = rx_fallback.try_lock() {
                        while let Ok(decrypted_bytes) = rx_guard.try_recv() {
                            let incoming = decrypted_bytes.chunks_exact(2).map(|b| i16::from_le_bytes([b[0], b[1]]) as f32 / i16::MAX as f32);
                            if let Ok(mut jb_guard) = jb_fallback.try_lock() { jb_guard.extend(incoming); }
                        }
                    }

                    if let Ok(mut jb_guard) = jb_fallback.try_lock() {
                        if jb_guard.len() > max_jitter_buffer_samples {
                            let overflow = jb_guard.len() - max_jitter_buffer_samples;
                            jb_guard.drain(0..overflow);
                        }

                        if let Ok(mut tel) = tel_fallback_cb.try_lock() { tel.jitter_buffer_len = jb_guard.len(); }

                        if let Ok(mut pb_guard) = pb_fallback.try_lock() {
                            if *pb_guard {
                                if jb_guard.len() >= prebuffer_target_samples {
                                    *pb_guard = false;
                                } else {
                                    data.fill(0.0);
                                    return;
                                }
                            } else if jb_guard.len() < frames_needed {
                                *pb_guard = true;
                                data.fill(0.0);
                                return;
                            }
                        }

                        let take = frames_needed;
                        for i in 0..take { data[data_idx + i] = jb_fallback.try_lock().unwrap().pop_front().unwrap(); }
                    } else { data.fill(0.0); }
                },
                |err| error!(error = %err, "Hardware playback stream exception"),
                None,
            ).unwrap()
        }
    };

    if let Err(e) = audio_stream.play() { error!(error = %e, "Failed to transition playback pipeline to active state"); return; }

    let mut internal_packet_count: u64 = 0;
    let mut last_seen_counter: u64 = 0;

    loop {
        if let Ok(guard) = telemetry.lock() { if !guard.is_running { break; } }
        match socket.recv(&mut buf) {
            Ok(size) => {
                if size < 8 { continue; }
                
                if size >= HANDSHAKE_ACK.len() && &buf[0..HANDSHAKE_ACK.len()] == HANDSHAKE_ACK {
                    warn!("Intercepted redundant AUBRI_ACK handshake packet. Dropping to prevent pipeline desynchronization.");
                    continue;
                }

                let mut counter_buf = [0u8; 8];
                counter_buf.copy_from_slice(&buf[0..8]);
                let packet_counter = u64::from_le_bytes(counter_buf);

                if packet_counter <= last_seen_counter && last_seen_counter > 0 { continue; }
                last_seen_counter = packet_counter;

                let ciphertext = &buf[8..size];
                let nonce = generate_nonce(packet_counter);

                match cipher.decrypt(&nonce, ciphertext) {
                    Ok(plaintext) => {
                        let _ = tx.try_send(plaintext);
                        internal_packet_count += 1;
                        if let Ok(mut tel) = telemetry.lock() {
                            tel.packets_processed = internal_packet_count;
                            tel.bytes_processed += size as u64;
                        }
                    }
                    Err(_) => { error!("CRITICAL DATA ANOMALY: Frame decryption failure! Symmetric authentication tags mismatch."); }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(_) => break,
        }
    }
    if let Ok(mut tel) = telemetry.lock() { tel.is_running = false; tel.status = "Session closed.".to_string(); }
}