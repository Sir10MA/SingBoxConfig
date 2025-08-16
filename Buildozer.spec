[app]
title = SingBox Generator
package.name = singboxgen
package.domain = org.example
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,json

version = 0.1
requirements = python3,kivy==2.3.0,kivymd,requests,pysocks
orientation = portrait
fullscreen = 0

[buildozer]
log_level = 2
warn_on_root = 1

[app:android]
android.api = 33
android.minapi = 21
android.sdk = 33
android.ndk = 25b
android.archs = arm64-v8a,armeabi-v7a
android.permissions = INTERNET

# optional icon settings
icon.filename = %(source.dir)s/icon.png
