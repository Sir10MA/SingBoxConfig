[app]
title = SingBoxConfig
package.name = singboxconfig
package.domain = org.singbox.config
source.dir = .
source.include_exts = py,png,jpg,kv,atlas
version = 0.1
requirements = python3,kivy,kivymd
orientation = portrait
fullscreen = 0

# Universal APK (works on arm64-v8a, armeabi-v7a, x86, x86_64)
android.archs = armeabi-v7a,arm64-v8a,x86,x86_64
android.api = 33
android.minapi = 21
android.sdk = 33
android.ndk = 25b
android.ndk_api = 21
# Force Buildozer to use the SDK installed by the GitHub workflow
android.sdk_path = $HOME/android-sdk
android.ndk_path = $HOME/android-sdk/ndk/25.1.8937393

# Build tools version (matches GitHub Actions workflow)
android.build_tools_version = 33.0.2

# Permissions (add more if Singbox needs network)
android.permissions = INTERNET

# (Optional) enable logcat
log_level = 2

[buildozer]
log_level = 2
warn_on_root = 1
