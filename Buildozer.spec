[app]
title = Singbox Generator
package.name = singboxgenerator
package.domain = org.example
source.dir = .
source.include_exts = py,kv,png,jpg,atlas,json,txt
version = 1.0
requirements = python3,kivy,kivymd,requests
orientation = portrait
fullscreen = 0
android.permissions = INTERNET,WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE

# For KivyMD + Material Icons
android.presplash = presplash.png
android.icon = icon.png

[buildozer]
log_level = 2
warn_on_root = 0

# Android build settings
android.api = 33
android.minapi = 21
android.ndk = 25.2.9519653
android.sdk = 33
android.archs = arm64-v8a,armeabi-v7a
