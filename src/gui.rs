use crate::Mode;
use crate::core::Telemetry;
use eframe::egui;
use egui::{Color32, Stroke, vec2};
use cpal::traits::{DeviceTrait, HostTrait};
use std::sync::{Arc, Mutex};

pub struct AppWindow {
    is_server_mode: bool,
    bind_addr: String,
    secret_key: String,
    capture_device: String,
    playback_device: String,
    target_hz: String,
    protocol: String,
    target_latency: usize,
    target_prebuffer: usize,
    available_inputs: Vec<String>,
    available_outputs: Vec<String>,
    devices_scanned: bool,
    telemetry: Arc<Mutex<Telemetry>>,
    initial_cli_mode: Option<Mode>,
    has_auto_started: bool,
}

impl AppWindow {
    pub fn new(cli_mode: Option<Mode>) -> Self {
        let mut is_server = true;
        let mut bind_addr = "127.0.0.1:8080".to_string();
        let mut secret_key = "JeMateDesVideos01".to_string();
        let mut cap_dev = "System Default Input".to_string();
        let mut play_dev = "System Default Output".to_string();
        let mut target_hz = "Default OS Match".to_string();
        let mut protocol = "UDP".to_string();
        let mut target_latency = 350;
        let mut target_prebuffer = 120;

        if let Some(ref mode) = cli_mode {
            match mode {
                Mode::Server { bind, secret, device, sample_rate, protocol: cli_proto, .. } => {
                    is_server = true;
                    bind_addr = bind.clone();
                    if let Some(s) = secret { secret_key = s.clone(); }
                    if let Some(d) = device { cap_dev = d.clone(); }
                    if let Some(hz) = sample_rate { target_hz = hz.to_string(); }
                    protocol = cli_proto.to_uppercase();
                }
                Mode::Client { address, secret, device, sample_rate, protocol: cli_proto, latency, prebuffer, .. } => {
                    is_server = false;
                    bind_addr = address.clone();
                    if let Some(s) = secret { secret_key = s.clone(); }
                    if let Some(d) = device { play_dev = d.clone(); }
                    if let Some(hz) = sample_rate { target_hz = hz.to_string(); }
                    if let Some(l) = latency { target_latency = *l; }
                    if let Some(p) = prebuffer { target_prebuffer = *p; }
                    protocol = cli_proto.to_uppercase();
                }
                _ => {}
            }
        }

        Self {
            is_server_mode: is_server,
            bind_addr,
            secret_key,
            capture_device: cap_dev,
            playback_device: play_dev,
            target_hz,
            protocol,
            target_latency,
            target_prebuffer,
            available_inputs: vec!["System Default Input".to_string()],
            available_outputs: vec!["System Default Output".to_string()],
            devices_scanned: false,
            telemetry: Arc::new(Mutex::new(Telemetry::default())),
            initial_cli_mode: cli_mode,
            has_auto_started: false,
        }
    }

    fn scan_devices_if_needed(&mut self) {
        if self.devices_scanned { return; }
        let host = cpal::default_host();
        if let Ok(devices) = host.input_devices() {
            for d in devices { if let Ok(name) = d.name() { self.available_inputs.push(name); } }
        }
        if let Ok(devices) = host.output_devices() {
            for d in devices { if let Ok(name) = d.name() { self.available_outputs.push(name); } }
        }
        self.devices_scanned = true;
    }
}

impl eframe::App for AppWindow {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let tel = self.telemetry.lock().unwrap().clone();

        if tel.is_running {
            ctx.request_repaint_after(std::time::Duration::from_millis(250));
        }

        if !self.has_auto_started && self.initial_cli_mode.is_some() {
            self.has_auto_started = true;
            if let Some(mode) = self.initial_cli_mode.take() {
                let tel_clone = Arc::clone(&self.telemetry);
                std::thread::spawn(move || {
                    let target_host = cpal::default_host();
                    match mode {
                        Mode::Server { bind, secret, device, sample_rate, protocol, .. } => {
                            let dev_target = if device.as_deref() == Some("System Default Input") { None } else { device };
                            let fallback_secret = secret.unwrap_or_else(|| "JeMateDesVideos01".to_string());
                            crate::core::run_server(target_host, &bind, &fallback_secret, dev_target, sample_rate, &protocol, tel_clone);
                        }
                        Mode::Client { address, secret, device, sample_rate, protocol, latency, prebuffer, .. } => {
                            let dev_target = if device.as_deref() == Some("System Default Output") { None } else { device };
                            let fallback_secret = secret.unwrap_or_else(|| "JeMateDesVideos01".to_string());
                            crate::core::run_client(target_host, &address, &fallback_secret, dev_target, sample_rate, &protocol, latency, prebuffer, tel_clone);
                        }
                        _ => {}
                    }
                });
            }
        }

        if self.target_prebuffer > self.target_latency {
            self.target_prebuffer = self.target_latency;
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                ui.add_space(8.0);
                ui.heading(egui::RichText::new("Aubri Stream Engine").size(24.0).strong());
                ui.add_space(4.0);
                ui.label(egui::RichText::new("Cryptographic Real-Time Audio Diagnostics").color(Color32::from_rgb(150, 160, 170)));
                ui.add_space(16.0);

                if !tel.is_running {
                    egui::Frame::none()
                        .fill(Color32::from_rgb(26, 28, 30))
                        .rounding(8.0)
                        .inner_margin(16.0)
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            
                            ui.horizontal(|ui| {
                                ui.selectable_value(&mut self.is_server_mode, true, "Capture Interface (Server)");
                                ui.add_space(12.0);
                                ui.selectable_value(&mut self.is_server_mode, false, "Playback Interface (Client)");
                            });

                            ui.add_space(16.0);
                            
                            egui::Grid::new("config_fields")
                                .num_columns(2)
                                .spacing([24.0, 16.0])
                                .min_col_width(ui.available_width() * 0.3)
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new("Network Target").color(Color32::from_rgb(180, 190, 200)));
                                    ui.add(egui::TextEdit::singleline(&mut self.bind_addr).desired_width(f32::INFINITY));
                                    ui.end_row();

                                    ui.label(egui::RichText::new("Authentication Secret").color(Color32::from_rgb(180, 190, 200)));
                                    ui.add(egui::TextEdit::singleline(&mut self.secret_key).password(true).desired_width(f32::INFINITY));
                                    ui.end_row();

                                    ui.label(egui::RichText::new("Transport Protocol").color(Color32::from_rgb(180, 190, 200)));
                                    ui.horizontal(|ui| {
                                        ui.selectable_value(&mut self.protocol, "UDP".to_string(), "UDP (Low Latency)");
                                        ui.selectable_value(&mut self.protocol, "TCP".to_string(), "TCP (High Reliability)");
                                    });
                                    ui.end_row();

                                    ui.label(egui::RichText::new("Sample Rate").color(Color32::from_rgb(180, 190, 200)));
                                    egui::ComboBox::from_id_source("hz_dropdown")
                                        .width(ui.available_width())
                                        .selected_text(&self.target_hz)
                                        .show_ui(ui, |ui| {
                                            ui.selectable_value(&mut self.target_hz, "Default OS Match".to_string(), "Default OS Match");
                                            ui.selectable_value(&mut self.target_hz, "44100".to_string(), "44100 Hz");
                                            ui.selectable_value(&mut self.target_hz, "48000".to_string(), "48000 Hz");
                                            ui.selectable_value(&mut self.target_hz, "96000".to_string(), "96000 Hz");
                                        });
                                    ui.end_row();

                                    if self.is_server_mode {
                                        ui.label(egui::RichText::new("Capture Hardware").color(Color32::from_rgb(180, 190, 200)));
                                        egui::ComboBox::from_id_source("capture_dropdown")
                                            .width(ui.available_width())
                                            .selected_text(&self.capture_device)
                                            .show_ui(ui, |ui| {
                                                self.scan_devices_if_needed();
                                                for dev in &self.available_inputs {
                                                    ui.selectable_value(&mut self.capture_device, dev.clone(), dev);
                                                }
                                            });
                                        ui.end_row();
                                    } else {
                                        ui.label(egui::RichText::new("Playback Hardware").color(Color32::from_rgb(180, 190, 200)));
                                        egui::ComboBox::from_id_source("playback_dropdown")
                                            .width(ui.available_width())
                                            .selected_text(&self.playback_device)
                                            .show_ui(ui, |ui| {
                                                self.scan_devices_if_needed();
                                                for dev in &self.available_outputs {
                                                    ui.selectable_value(&mut self.playback_device, dev.clone(), dev);
                                                }
                                            });
                                        ui.end_row();

                                        ui.label(egui::RichText::new("Latency Tolerance").color(Color32::from_rgb(180, 190, 200)));
                                        ui.add(egui::Slider::new(&mut self.target_latency, 50..=2000).suffix(" ms").clamp_to_range(true));
                                        ui.end_row();

                                        ui.label(egui::RichText::new("Prebuffer Size").color(Color32::from_rgb(180, 190, 200)));
                                        ui.add(egui::Slider::new(&mut self.target_prebuffer, 10..=1000).suffix(" ms").clamp_to_range(true));
                                        ui.end_row();
                                    }
                                });
                        });

                    ui.add_space(24.0);
                    if ui.add_sized(
                        [ui.available_width(), 36.0], 
                        egui::Button::new(egui::RichText::new("Initialize Stream Context").size(16.0))
                    ).clicked() {
                        let mode = self.is_server_mode;
                        let bind = self.bind_addr.clone();
                        let secret = self.secret_key.clone();
                        let protocol = self.protocol.clone();
                        let hz_override = self.target_hz.parse::<u32>().ok();
                        let lat_override = Some(self.target_latency);
                        let pre_override = Some(self.target_prebuffer);
                        
                        let dev = if mode {
                            if self.capture_device == "System Default Input" { None } else { Some(self.capture_device.clone()) }
                        } else {
                            if self.playback_device == "System Default Output" { None } else { Some(self.playback_device.clone()) }
                        };
                        
                        let tel_clone = Arc::clone(&self.telemetry);

                        std::thread::spawn(move || {
                            let target_host = cpal::default_host();
                            if mode {
                                crate::core::run_server(target_host, &bind, &secret, dev, hz_override, &protocol, tel_clone);
                            } else {
                                crate::core::run_client(target_host, &bind, &secret, dev, hz_override, &protocol, lat_override, pre_override, tel_clone);
                            }
                        });
                    }
                } else {
                    egui::Frame::none()
                        .fill(Color32::from_rgb(22, 28, 26))
                        .stroke(Stroke::new(1.0, Color32::from_rgb(45, 80, 70)))
                        .rounding(8.0)
                        .inner_margin(16.0)
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new("●").color(Color32::from_rgb(80, 200, 150)));
                                ui.label(egui::RichText::new(format!("{} Active", tel.mode)).strong());
                            });
                            ui.add_space(8.0);
                            ui.label(egui::RichText::new(&tel.status).color(Color32::from_rgb(160, 175, 170)));
                        });

                    ui.add_space(24.0);
                    ui.label(egui::RichText::new("Telemetry Data").strong());
                    ui.add_space(8.0);

                    egui::Grid::new("telemetry_grid")
                        .spacing([40.0, 12.0])
                        .min_col_width(ui.available_width() * 0.4)
                        .show(ui, |ui| {
                            ui.label("Hardware Clock:");
                            ui.label(format!("{} Hz / {} Ch", tel.sample_rate, tel.channels));
                            ui.end_row();

                            ui.label("Data Frames:");
                            ui.label(format!("{}", tel.packets_processed));
                            ui.end_row();

                            ui.label("Total Volume:");
                            ui.label(format!("{:.2} MB", tel.bytes_processed as f64 / 1_048_576.0));
                            ui.end_row();
                        });

                    if tel.mode.contains("Client") {
                        ui.add_space(24.0);
                        ui.label(egui::RichText::new("Jitter Buffer Latency Tolerance").strong());
                        ui.add_space(8.0);
                        
                        let progress_pct = if tel.max_buffer_capacity > 0 {
                            (tel.jitter_buffer_len as f32 / tel.max_buffer_capacity as f32) * 100.0
                        } else {
                            0.0
                        };
                        
                        ui.label(format!(
                            "Buffer Fill: {} / {} Samples ({:.1}%)",
                            tel.jitter_buffer_len,
                            tel.max_buffer_capacity,
                            progress_pct
                        ));
                    }

                    ui.add_space(32.0);
                    if ui.add_sized(
                        [ui.available_width(), 32.0], 
                        egui::Button::new(egui::RichText::new("Halt Sequence and Disconnect").size(14.0).color(Color32::from_rgb(220, 100, 100)))
                    ).clicked() {
                        if let Ok(mut t) = self.telemetry.lock() {
                            t.is_running = false;
                            t.status = "Disconnect signal dispatched. Releasing network locks...".to_string();
                        }
                    }
                }
            });
        });
    }

    fn ui(&mut self, _ui: &mut egui::Ui, _frame: &mut eframe::Frame) {}
}

pub fn launch_gui(initial_mode: Option<Mode>) {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([540.0, 540.0])
            .with_min_inner_size([500.0, 420.0])
            .with_resizable(true),
        ..Default::default()
    };
    
    let _ = eframe::run_native(
        "Aubri Diagnostic Suite",
        options,
        Box::new(|cc| {
            let mut visuals = egui::Visuals::dark();
            visuals.panel_fill = Color32::from_rgb(18, 18, 20);
            visuals.window_fill = Color32::from_rgb(24, 24, 26);
            visuals.selection.bg_fill = Color32::from_rgb(60, 120, 105);
            visuals.widgets.inactive.corner_radius = 6.0.into();
            visuals.widgets.hovered.corner_radius = 6.0.into();
            visuals.widgets.active.corner_radius = 6.0.into();
            visuals.widgets.noninteractive.corner_radius = 6.0.into();
            visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(32, 34, 36);

            let mut style = egui::Style::default();
            style.visuals = visuals;
            style.spacing.item_spacing = vec2(12.0, 12.0);
            style.spacing.button_padding = vec2(12.0, 8.0);
            style.spacing.slider_width = 250.0;
            cc.egui_ctx.set_style(style);

            Ok(Box::new(AppWindow::new(initial_mode)))
        }),
    );
}