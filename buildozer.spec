[app]
# Basic app info
title = Sing-Box Configurator
package.name = singboxconfig
package.domain = com.sirtenmaa

# Entrypoint
source.dir = .
source.include_exts = py,json,kv,png,jpg,atlas

# Version
version = 1.0.0

# Dependencies (use stable Kivy + KivyMD versions)
requirements = python3,kivy==2.2.1,kivymd==1.1.1,requests,pyyaml

# Permissions
android.permissions = INTERNET,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE,QUERY_ALL_PACKAGES

# Orientation
orientation = portrait

# Architecture (universal build)
android.archs = armeabi-v7a, arm64-v8a

# Android API / SDK / NDK
android.api = 27
android.sdk = 34
android.ndk = 25b
android.build_tools = 34.0.0

# Optional splash & icon
# presplash.filename = %(source.dir)s/data/presplash.png
# icon.filename = %(source.dir)s/data/icon.png

[buildozer]
log_level = 2
warn_on_root = 1
