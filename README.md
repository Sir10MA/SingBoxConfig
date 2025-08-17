# 📱 Sing-Box Configurator

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Kivy](https://img.shields.io/badge/Kivy-2.2.1-green.svg)](https://kivy.org/)
[![KivyMD](https://img.shields.io/badge/KivyMD-1.1.1-lightgrey.svg)](https://kivymd.readthedocs.io/)
[![Telegram](https://img.shields.io/badge/Telegram-Join%20Chat-blue.svg)](https://t.me/Sir10ma)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Sing-Box Configurator** is a mobile-friendly tool built with **Kivy + KivyMD** that makes it easy to generate, edit, and manage Sing-Box configuration files.  
It provides a simple UI for creating configs without manually editing JSON, while still giving advanced users full control.  

## ✨ Features
- 📝 Create and edit Sing-Box configuration files easily  
- 📂 Import & export configs in JSON/YAML format  
- 🔍 Live validation to prevent errors before deployment  
- 🌐 Support for multiple outbound/inbound configurations  
- 📊 Clean Material Design UI (KivyMD)  
- 📱 Android APK support (via Buildozer)  
- 🪵 Crash-safe logging system (`singbox_log.txt` stored in app storage)  
- ⚡ **Proxy check & connectivity test** before saving configs  

## 📸 Screenshots
*(Add screenshots here when ready)*  

## 🚀 Installation

Clone the repository:  
```bash
git clone https://github.com/<your-username>/singboxconfig.git
cd singboxconfig
```

Run on desktop:  
```bash
python sing_config_maker.py
```

Build Android APK (with Buildozer):  
```bash
buildozer -v android debug
```

## 📡 Community & Support
Join our Telegram group for support, updates, and discussions:  
👉 [t.me/Sir10ma](https://t.me/Sir10ma)
