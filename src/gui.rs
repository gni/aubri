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
    keep_alive: bool,
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
        let mut keep_alive = false;

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
                Mode::Client { address, secret, device, sample_rate, protocol: cli_proto, latency, prebuffer, keep_alive: cli_keep_alive, .. } => {
                    is_server = false;
                    bind_addr = address.clone();
                    if let Some(s) = secret { secret_key = s.clone(); }
                    if let Some(d) = device { play_dev = d.clone(); }
                    if let Some(hz) = sample_rate { target_hz = hz.to_string(); }
                    if let Some(l) = latency { target_latency = *l; }
                    if let Some(p) = prebuffer { target_prebuffer = *p; }
                    keep_alive = *cli_keep_alive;
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
            keep_alive,
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

        ctx.request_repaint_after(std::time::Duration::from_millis(100));

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
                        Mode::Client { address, secret, device, sample_rate, protocol, latency, prebuffer, keep_alive, .. } => {
                            let dev_target = if device.as_deref() == Some("System Default Output") { None } else { device };
                            let fallback_secret = secret.unwrap_or_else(|| "JeMateDesVideos01".to_string());
                            crate::core::run_client(target_host, &address, &fallback_secret, dev_target, sample_rate, &protocol, latency, prebuffer, keep_alive, tel_clone);
                        }
                        _ => {}
                    }
                });
            }
        }

        if self.target_prebuffer > self.target_latency {
            self.target_prebuffer = self.target_latency;
        }

        let status_lower = tel.status.to_lowercase();
        
        let is_error = status_lower.contains("error")
            || status_lower.contains("fail")
            || status_lower.contains("timeout")
            || status_lower.contains("lost")
            || status_lower.contains("exception")
            || status_lower.contains("unreachable")
            || status_lower.contains("closed");

        let is_connected = status_lower.contains("connected to remote")
            || status_lower.contains("streaming active");

        let is_awaiting = status_lower.contains("awaiting")
            || status_lower.contains("listening");

        let is_routing = status_lower.contains("routing")
            || status_lower.contains("binding")
            || status_lower.contains("handshake");

        let show_status = tel.is_running || is_error;

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                ui.add_space(8.0);
                ui.heading(egui::RichText::new("aubri stream engine").size(24.0).strong());
                ui.add_space(4.0);
                ui.label(egui::RichText::new("secure peer-to-peer audio").color(Color32::from_rgb(150, 160, 170)));
                ui.add_space(16.0);

                if !show_status {
                    egui::Frame::none()
                        .fill(Color32::from_rgb(26, 28, 30))
                        .rounding(8.0)
                        .inner_margin(16.0)
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            
                            ui.horizontal(|ui| {
                                ui.selectable_value(&mut self.is_server_mode, true, "capture (server)");
                                ui.add_space(12.0);
                                ui.selectable_value(&mut self.is_server_mode, false, "playback (client)");
                            });

                            ui.add_space(16.0);
                            
                            egui::Grid::new("config_fields")
                                .num_columns(2)
                                .spacing([24.0, 16.0])
                                .min_col_width(ui.available_width() * 0.3)
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new("network target").color(Color32::from_rgb(180, 190, 200)));
                                    ui.add(egui::TextEdit::singleline(&mut self.bind_addr).desired_width(f32::INFINITY));
                                    ui.end_row();

                                    ui.label(egui::RichText::new("secret key").color(Color32::from_rgb(180, 190, 200)));
                                    ui.add(egui::TextEdit::singleline(&mut self.secret_key).password(true).desired_width(f32::INFINITY));
                                    ui.end_row();

                                    ui.label(egui::RichText::new("protocol").color(Color32::from_rgb(180, 190, 200)));
                                    ui.horizontal(|ui| {
                                        ui.selectable_value(&mut self.protocol, "UDP".to_string(), "udp (low latency)");
                                        ui.selectable_value(&mut self.protocol, "TCP".to_string(), "tcp (reliable)");
                                    });
                                    ui.end_row();

                                    ui.label(egui::RichText::new("sample rate").color(Color32::from_rgb(180, 190, 200)));
                                    egui::ComboBox::from_id_source("hz_dropdown")
                                        .width(ui.available_width())
                                        .selected_text(self.target_hz.replace("Default OS Match", "os default"))
                                        .show_ui(ui, |ui| {
                                            ui.selectable_value(&mut self.target_hz, "Default OS Match".to_string(), "os default");
                                            ui.selectable_value(&mut self.target_hz, "44100".to_string(), "44100 hz");
                                            ui.selectable_value(&mut self.target_hz, "48000".to_string(), "48000 hz");
                                            ui.selectable_value(&mut self.target_hz, "96000".to_string(), "96000 hz");
                                        });
                                    ui.end_row();

                                    if self.is_server_mode {
                                        ui.label(egui::RichText::new("capture device").color(Color32::from_rgb(180, 190, 200)));
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
                                        ui.label(egui::RichText::new("playback device").color(Color32::from_rgb(180, 190, 200)));
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

                                        ui.label(egui::RichText::new("latency target").color(Color32::from_rgb(180, 190, 200)));
                                        ui.add(egui::Slider::new(&mut self.target_latency, 50..=2000).suffix(" ms").clamp_to_range(true));
                                        ui.end_row();

                                        ui.label(egui::RichText::new("prebuffer target").color(Color32::from_rgb(180, 190, 200)));
                                        ui.add(egui::Slider::new(&mut self.target_prebuffer, 10..=1000).suffix(" ms").clamp_to_range(true));
                                        ui.end_row();

                                        ui.label(egui::RichText::new("auto reconnect").color(Color32::from_rgb(180, 190, 200)));
                                        ui.checkbox(&mut self.keep_alive, "enable keep-alive");
                                        ui.end_row();
                                    }
                                });
                        });

                    ui.add_space(24.0);
                    if ui.add_sized(
                        [ui.available_width(), 36.0], 
                        egui::Button::new(egui::RichText::new("start stream").size(16.0))
                    ).clicked() {
                        let mode = self.is_server_mode;
                        let bind = self.bind_addr.clone();
                        let secret = self.secret_key.clone();
                        let protocol = self.protocol.clone();
                        let hz_override = self.target_hz.parse::<u32>().ok();
                        let lat_override = Some(self.target_latency);
                        let pre_override = Some(self.target_prebuffer);
                        let keep_alive = self.keep_alive;
                        
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
                                crate::core::run_client(target_host, &bind, &secret, dev, hz_override, &protocol, lat_override, pre_override, keep_alive, tel_clone);
                            }
                        });
                    }
                } else {
                    let (frame_fill, frame_stroke, dot_color, text_color) = if is_error {
                        (
                            Color32::from_rgb(35, 20, 20),
                            Stroke::new(1.0, Color32::from_rgb(200, 50, 50)),
                            Color32::from_rgb(255, 60, 60),
                            Color32::from_rgb(255, 100, 100),
                        )
                    } else if is_connected {
                        (
                            Color32::from_rgb(22, 28, 26),
                            Stroke::new(1.0, Color32::from_rgb(45, 80, 70)),
                            Color32::from_rgb(80, 200, 150),
                            Color32::from_rgb(160, 200, 170),
                        )
                    } else if is_awaiting {
                        (
                            Color32::from_rgb(26, 28, 30),
                            Stroke::new(1.0, Color32::from_rgb(50, 50, 50)),
                            Color32::from_rgb(80, 200, 150),
                            Color32::from_rgb(150, 150, 150),
                        )
                    } else if is_routing {
                        (
                            Color32::from_rgb(30, 26, 20),
                            Stroke::new(1.0, Color32::from_rgb(100, 80, 40)),
                            Color32::from_rgb(220, 160, 60),
                            Color32::from_rgb(200, 170, 120),
                        )
                    } else {
                        (
                            Color32::from_rgb(26, 28, 30),
                            Stroke::new(1.0, Color32::from_rgb(50, 50, 50)),
                            Color32::from_rgb(100, 100, 100),
                            Color32::from_rgb(150, 150, 150),
                        )
                    };

                    egui::Frame::none()
                        .fill(frame_fill)
                        .stroke(frame_stroke)
                        .rounding(8.0)
                        .inner_margin(16.0)
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new("●").color(dot_color));
                                let mode_text = if is_error && !tel.is_running { "error state".to_string() } else { format!("{} active", tel.mode.to_lowercase()) };
                                ui.label(egui::RichText::new(mode_text).strong());
                            });
                            ui.add_space(8.0);
                            ui.label(egui::RichText::new(&tel.status).color(text_color));
                        });

                    ui.add_space(24.0);
                    ui.label(egui::RichText::new("telemetry data").strong());
                    ui.add_space(8.0);

                    egui::Grid::new("telemetry_grid")
                        .spacing([40.0, 12.0])
                        .min_col_width(ui.available_width() * 0.4)
                        .show(ui, |ui| {
                            ui.label("hardware clock:");
                            ui.label(format!("{} hz / {} ch", tel.sample_rate, tel.channels));
                            ui.end_row();

                            ui.label("data frames:");
                            ui.label(format!("{}", tel.packets_processed));
                            ui.end_row();

                            ui.label("total volume:");
                            ui.label(format!("{:.2} mb", tel.bytes_processed as f64 / 1_048_576.0));
                            ui.end_row();
                        });

                    if tel.mode.contains("Client") {
                        ui.add_space(24.0);
                        ui.label(egui::RichText::new("jitter buffer").strong());
                        ui.add_space(8.0);
                        
                        let progress_pct = if tel.max_buffer_capacity > 0 {
                            (tel.jitter_buffer_len as f32 / tel.max_buffer_capacity as f32) * 100.0
                        } else {
                            0.0
                        };
                        
                        ui.label(format!(
                            "fill: {} / {} samples ({:.1}%)",
                            tel.jitter_buffer_len,
                            tel.max_buffer_capacity,
                            progress_pct
                        ));
                    }

                    ui.add_space(32.0);
                    let btn_text = if is_error && !tel.is_running { "dismiss and return" } else { "stop and disconnect" };
                    if ui.add_sized(
                        [ui.available_width(), 32.0], 
                        egui::Button::new(egui::RichText::new(btn_text).size(14.0).color(Color32::from_rgb(220, 100, 100)))
                    ).clicked() {
                        if let Ok(mut t) = self.telemetry.lock() {
                            t.is_running = false;
                            t.status = String::new();
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
        "aubri suite",
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