# 🐙 OCtopus

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-informational?style=flat-square&logo=linux&logoColor=white&color=0a0c10"/>
  <img src="https://img.shields.io/badge/Category-OForensics%20%2F%20Network%20Analysis-cyan?style=flat-square"/>
  <img src="https://img.shields.io/badge/Dependencies-Scapy-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-Proprietary-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-v1.0-cyan?style=flat-square"/>
</p>

> **OCtopus** is a tactical network traffic dissector and plaintext credential hunter. It captures live traffic and extracts credentials from unencrypted protocols such as HTTP Basic Auth, FTP, Telnet, SMTP, POP3, and IMAP.

---

## 📌 Overview

OCtopus performs real-time packet sniffing with protocol-specific parsing to detect and log sensitive information transmitted in cleartext. It is designed for authorized security testing and forensic network analysis.

**Requires root privileges** to capture packets.

---

## 🖥️ Modules

| # | Module              | Description |
|---|---------------------|-------------|
| **[1]** | **Start Capture**   | Begin live sniffing on selected interface |
| **[H]** | **Help**            | Show usage, supported protocols and output tags |

---

## 📊 Key Features

- **Live Packet Capture** using Scapy with optimized BPF filter
- **Protocol Dissection**:
  - **DNS** — Query logging (UDP/53)
  - **HTTP** — Method, Host, Path, URL
  - **Basic Auth** — Automatic Base64 decoding
  - **FTP** — USER and PASS commands
  - **Telnet** — Credential keyword detection
  - **SMTP** — AUTH LOGIN, AUTH PLAIN, Base64
  - **POP3** — USER/PASS/APOP
  - **IMAP** — LOGIN command
- **Generic Credential Hunter** — Keyword-based detection across all traffic
- **Real-time Colored Logging** — Clear visual tags for each finding
- **Persistent Log File** — All events saved with timestamps (`octopus.log`)

---

## ⚙️ Requirements

- **Linux** (recommended)
- **Root / Administrator privileges**
- **Scapy** (`pip install scapy`)

---

## 🚀 Usage

```bash
sudo ./OCtopus

📁 Output

Live Terminal — Color-coded real-time detections with clear tags
Log File — octopus.log (or custom path) with full timestamped entries
Credential Highlights — Basic Auth decoded, FTP/Telnet/SMTP/POP3/IMAP credentials

Example output tags:

[DNS]
[HTTP]
[BASIC AUTH]
[FTP USER/PASS]
[TELNET CREDS?]
[SMTP AUTH *]
[POP3 USER/PASS]
[IMAP LOGIN]
[POSSIBLE CREDS]


📦 Part of OwlSec Toolkit
This tool is part of the OwlSec suite — a collection of 300+ security and privacy tools.
🔗 owlsec.org

©️ License
Proprietary — © Khaled S. Haddad
Tools are distributed as pre-built executables. Source code is proprietary.

AUTHORISED SECURITY TESTING & NETWORK ANALYSIS USE ONLY
