[app]
# Basic app info
title = Sing-Box Configurator
package.name = singboxconfig
package.domain = com.sirtenmaa

# Entrypoint
source.dir = .
source.main = main.py
source.include_exts = py,json,kv,png,jpg,atlas

# Version
version = 1.0.0

# Dependencies
requirements = python3,kivy==2.3.1,https://github.com/kivymd/KivyMD/archive/refs/heads/master.zip,requests,pyyaml

# Permissions
android.permissions = INTERNET, READ_EXTERNAL_STORAGE, WRITE_EXTERNAL_STORAGE

# Orientation
orientation = portrait

# Architecture (universal build)
android.archs = arm64-v8a,armeabi-v7a

# Android API / SDK / NDK
android.api = 34
android.sdk = 34
android.ndk = 25b
android.build_tools = 34.0.0

[buildozer]
log_level = 2
warn_on_root = 1
