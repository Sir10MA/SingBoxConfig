[app]

# App details
title = SingBox Generator
package.name = singboxgen
package.domain = org.example
source.dir = .
source.include_exts = py,png,jpg,kv,atlas

# Main script
main.py = main.py

# Icon (optional, replace with your image)
icon.filename = %(source.dir)s/icon.png

# Versioning
version = 0.1
requirements = python3,kivy,kivymd,requests,anytree,urllib3

# Orientation
orientation = portrait

# Permissions (expand if you need more)
android.permissions = INTERNET,WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE

# Package format
osx.python_version = 3
fullscreen = 0

# Android API & SDK
android.api = 33
android.minapi = 21
android.ndk = 25b
android.sdk = 33
android.ndk_api = 21
android.archs = arm64-v8a,armeabi-v7a,x86,x86_64

# AIDL path (workflow will patch if missing)
android.aidl = $ANDROID_HOME/build-tools/33.0.2/aidl

# (Optional) Reduce APK size by excluding tests/docs
source.exclude_exts = spec,md,txt,db
source.exclude_dirs = tests,bin,docs

# Logging
log_level = 2

[buildozer]

log_level = 2
warn_on_root = 1
