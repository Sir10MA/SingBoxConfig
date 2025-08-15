[app]

# (str) Title of your application
title = SingConfig Maker

# (str) Package name
package.name = singconfig

# (str) Package domain (needed for android/ios packaging)
package.domain = org.example

# (str) Source code where the main.py lives
source.dir = .

# (list) Source files to include (let empty to include all the files)
source.include_exts = py,kv,png,jpg,atlas

# (list) Source directories to exclude
source.exclude_dirs = tests, bin, venv

# (str) Application version
version = 1.0

# (list) Application requirements
requirements = python3,kivy==2.2.1,kivymd==1.1.1,requests

# (list) Supported orientations
orientation = portrait

# (bool) Indicate if the application should be fullscreen
fullscreen = 0

# (list) Android archs to build for
android.archs = arm64-v8a, armeabi-v7a

# (bool) Allow auto-backup feature
android.allow_backup = True

#
# Android specific
#
android.api = 31
android.minapi = 21
android.build_tools = 33.0.2
android.ndk = 23b
android.sdk_path = /data/data/com.termux/files/home/android-sdk
android.ndk_path = /data/data/com.termux/files/home/android-ndk
android.accept_sdk_license = True

# (str) Android entry point
android.entrypoint = org.kivy.android.PythonActivity

# (bool) Copy library instead of making a libpymodules.so
android.copy_libs = 1

#
# Python for Android (p4a) specific
#
p4a.branch = master
p4a.bootstrap = sdl2
p4a.extra_args = 

[buildozer]

# (int) Log level (0 = error only, 1 = info, 2 = debug)
log_level = 2

# (int) Display warning if buildozer is run as root (0 = False, 1 = True)
warn_on_root = 1

# (str) Path to build artifact storage, relative to spec file
build_dir = ./.buildozer

# (str) Path to build output (apk/aab)
bin_dir = ./bin