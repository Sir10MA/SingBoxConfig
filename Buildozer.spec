[app]

# (str) Title of your application
title = SingConfigMaker

# (str) Package name
package.name = singconfig

# (str) Package domain (needed for android/ios packaging)
package.domain = org.example

# (str) Source code where the main.py live
source.dir = .

# (list) Source files to include (let empty to include all)
source.include_exts = py,png,jpg,kv,json

# (str) Application versioning
version = 1.0.0

# (str) Python version
requirements = python3,kivy,kivymd

# (bool) Indicate if the application should be fullscreen
fullscreen = 0

# (str) Orientation
orientation = portrait

# ----------------------------------------------------------------
# Android specific
# ----------------------------------------------------------------
[buildozer]

# (str) Android SDK path
android.sdk_path = /home/userland/android-sdk

# (str) Android NDK path (optional, can be auto-downloaded)
# android.ndk_path = /home/userland/android-ndk

# (str) Android API to use
android.api = 31

# (str) Android build-tools version
android.build_tools = 33.0.2

# (str) Minimum Android API required
android.minapi = 21

# (str) Target Android API
android.target = 31

# (str) Package format
android.arch = arm64-v8a

# ----------------------------------------------------------------
# Permissions and features
# ----------------------------------------------------------------
android.permissions = INTERNET

# ----------------------------------------------------------------
# Additional settings
# ----------------------------------------------------------------
log_level = 2
warn_on_root = 1
