# 🦉 OCtopus

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-OForensics-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OCtopus** — Tactical protocol analysis, credential dissection and Base64/multi-codec decoding

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

OCtopus is a tactical traffic dissector and credential-oriented protocol hunter for authorised network monitoring. It inspects live interfaces or PCAPs, highlights interesting protocol behaviour, and can export structured results for later review. Built for defensive capture analysis rather than offensive exploitation.

---

## ✨ Features

- Live interface capture and offline PCAP read/write workflows
- Protocol-focused dissection with optional protocol filters
- Credential and sensitive-material oriented hunting in traffic
- JSON and other export paths with configurable output location
- Optional GeoIP enrichment and deduplication TTL controls
- Quiet/verbose modes for lab capture and operator terminals

---

## ⚙️ Requirements

- **Linux**
- **No Python installation needed** — runs as a standalone executable

---

## 🚀 Usage

```bash
./OCtopus -i eth0
./OCtopus --pcap capture.pcap --json --out findings.json
./OCtopus -i eth0 --write-pcap out.pcap --protocols http,dns
./OCtopus --help
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad

*Tools are distributed as pre-built executables. Source code is proprietary.*
