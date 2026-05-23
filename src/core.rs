use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
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
const MAX_LATENCY_MS: usize = 100; 
const PREBUFFER_MS: usize = 60;
const HARDWARE_BUFFER_FRAMES: u32 = 512;
const MAX_SAFE_PAYLOAD_BYTES: usize = 1_000_000;

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

pub fn run_server(host: cpal::Host, bind: &str, secret: &str, device_name: Option<String>, sample_rate_override: Option<u32>, telemetry: Arc<Mutex<Telemetry>>) {
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
        if let Ok(guard) = telemetry.lock() {
            if !guard.is_running {
                info!("Server configuration loop halted by user.");
                return;
            }
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
        if let Ok(mut tel) = telemetry.lock() { tel.is_running = false; }
        return;
    }

    let session_key = derive_session_key(secret, &salt);
    let cipher = ChaCha20Poly1305::new(session_key.as_ref().into());

    if stream.write_all(&sample_rate.to_le_bytes()).is_err() || stream.write_all(&channels.to_le_bytes()).is_err() {
        if let Ok(mut tel) = telemetry.lock() { tel.is_running = false; }
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
        if let Ok(mut tel) = telemetry.lock() { tel.is_running = false; }
        return;
    }

    let mut counter: u64 = 0;

    loop {
        if let Ok(guard) = telemetry.lock() {
            if !guard.is_running {
                info!("Server termination sequence triggered. Dropping active endpoints.");
                break;
            }
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

pub fn run_client(host: cpal::Host, address: &str, secret: &str, device_name: Option<String>, sample_rate_override: Option<u32>, telemetry: Arc<Mutex<Telemetry>>) {
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
    
    if stream.read_exact(&mut ch_buf).is_err() {
        if let Ok(mut tel) = telemetry.lock() { tel.is_running = false; }
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
                            data[data_idx + i] = jb_fallback.try_lock().unwrap().pop_front().unwrap();
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
        if let Ok(guard) = telemetry.lock() {
            if !guard.is_running {
                info!("Client termination sequence triggered. Dropping active endpoints.");
                break;
            }
        }

        match stream.read_exact(&mut len_buf) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(_) => break,
        }
        
        let chunk_len = u32::from_le_bytes(len_buf) as usize;
        
        if chunk_len > MAX_SAFE_PAYLOAD_BYTES {
            error!("CRITICAL: Network payload desynchronization detected. Refusing massive RAM allocation.");
            break;
        }

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