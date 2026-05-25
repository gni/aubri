# audio + bridge = aubri

Encrypted peer-to-peer audio streamer.
aubri establishes a secure audio pipeline using ChaCha20Poly1305 AEAD over UDP or TCP. 

By default, the package compiles as a headless command-line interface to minimize the attack surface on server deployments. A graphical diagnostic suite is available via cargo feature flags.

## Motivation

Heavy headsets cause physical fatigue during long sessions. I switched to lightweight earbuds, but my desktop lacks bluetooth. aubri bridges this gap by streaming audio from my workstation to a secondary device that handles the connection. No dongles, no complex drivers just a simple, direct bridge.

```bash
+---------------------+       +---------------------+       +-----------+
|      desktop        |       |      laptop         |       |  earbuds  |
|    (workstation)    |       |     (bridge)        |       |           |
|                     |       |                     |       |           |
| [ audio source ] ---|------>| [ aubri client ] ---|------>| (pods/BT) |
+---------------------+       +---------------------+       +-----------+
           |                             |
           +---- Encrypted Stream -------+
```

## Install from crates

cli:
```bash
cargo install aubri
```

gui:
```bash
cargo install aubri --features gui
```

## Build instructions

Compile the headless CLI:
```bash
cargo build --release

```

Compile with the graphical diagnostic suite:

```bash
cargo build --release --features gui

```

## Global options

These options can be appended before any subcommand.

`--json`: Mute standard human-readable logs and output raw JSON telemetry to stdout every 500ms. Designed for pipeline integrations.

## Commands and usage

### List devices

Enumerate all available audio capture and playback interfaces recognized by the system.

```bash
aubri list-devices

```

### Server mode (capture)

Binds to a network interface, awaits a secure handshake, and streams captured hardware audio.

**Arguments:**

* `-b, --bind <BIND>`: Network interface and port to bind (default: `0.0.0.0:8080`).
* `-s, --secret <SECRET>`: Cryptographic session secret. If omitted, prompts securely. Can also be set via `AUBRI_SECRET` environment variable.
* `-P, --protocol <PROTOCOL>`: Transport protocol `udp` or `tcp` (default: `udp`).
* `-d, --device <DEVICE>`: Partial or exact name of the capture hardware. On Linux, this defaults to `pulse` to capture the automatically provisioned virtual sink.
* `-r, --sample-rate <SAMPLE_RATE>`: Override hardware sample rate (e.g., `48000`).

**Examples:**

```bash
# standard execution using environment variable for security
AUBRI_SECRET="your_secure_password" aubri server --bind 0.0.0.0:8080

# force tcp protocol and target a specific input device
aubri server --bind 127.0.0.1:9000 --protocol tcp --device "USB Audio"

# output json telemetry for external monitoring
aubri --json server --bind 0.0.0.0:8080

```

### Client mode (playback)

Connects to a remote server, negotiates the cryptographic session, and plays the received audio stream through a jitter buffer.

**Arguments:**

* `-a, --address <ADDRESS>`: Target server IP and port (required).
* `-s, --secret <SECRET>`: Cryptographic session secret.
* `-P, --protocol <PROTOCOL>`: Transport protocol `udp` or `tcp` (default: `udp`).
* `-d, --device <DEVICE>`: Partial or exact name of the playback hardware.
* `-r, --sample-rate <SAMPLE_RATE>`: Override hardware sample rate.
* `-l, --latency <LATENCY>`: Jitter buffer capacity in milliseconds (default: `350`).
* `-p, --prebuffer <PREBUFFER>`: Milliseconds of audio to accumulate before starting playback to prevent stuttering (default: `120`).
* `-k, --keep-alive`: Enable watchdog resilience. Automatically attempts reconnection if the socket drops or the server stops responding.

**Examples:**

```bash
# standard execution
AUBRI_SECRET="your_secure_password" aubri client --address 192.168.1.50:8080

# optimize for low latency networks (reduce buffer sizes)
AUBRI_SECRET="your_secure_password" aubri client --address 10.0.0.5:8080 --latency 150 --prebuffer 50

# highly resilient tcp connection
AUBRI_SECRET="your_secure_password" aubri client --address 10.0.0.5:8080 --protocol tcp --keep-alive

```

### Graphical interface

If compiled with `--features gui`, launches the visual diagnostic suite.

```bash
aubri gui

```

## Tests

Validated stream stability and audio across the following cross-distribution scenarios

| source (server) | target (client) | status |
| --- | --- | --- |
| Ubuntu 24.04 | Arch Linux | ok |
| Arch Linux | Ubuntu 24.04 | ok |

## Automatic configuration

aubri handles the Linux audio stack

**Server:** creates and selects the `aubri` virtual sink.

**Client:** detects and connects to your pipewire for client or pulseaudio backend no manual device configuration required.