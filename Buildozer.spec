[app]
title = SingBox Generator
package.name = singboxgenerator
package.domain = org.singbox.generator
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,ttf,xml,json,txt,md
version = 1.0.0
requirements = python3,kivy,kivymd,urllib3,requests,certifi,idna,chardet,charset-normalizer
orientation = portrait
fullscreen = 0

# Icon (optional, replace with your PNG path)
icon.filename = %(source.dir)s/icon.png

# Entry point
entrypoint = main.py

# Logcat filter
log_level = 2

# Permissions
android.permissions = INTERNET

# Universal APK
android.archs = armeabi-v7a,arm64-v8a

# Hide the title bar
android.hide_titlebar = 0

# API + SDK versions
android.api = 33
android.minapi = 21
android.sdk = 33
android.ndk = 25b
android.ndk_api = 21

# Packaging options
package.version = 1.0
package.version.code = 1

# Buildozer target
target = android

# Copy extra files if needed
# (uncomment if you want assets/fonts/configs to be bundled)
# source.include_patterns = assets/*,fonts/*,config/*

[buildozer]
log_level = 2
warn_on_root = 1
