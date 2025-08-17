[app]

# (str) Title of your application
title = BoxConfig

# (str) Package name
package.name = BoxConfig

# (str) Package domain (needed for Android/iOS)
package.domain = org.sirtenma

# (str) Source code directory
source.dir = .
# (str) Main Python file (must exist in source.dir)
source.main = main.py

# (list) Source files to include
source.include_exts = py,png,jpg,kv,atlas

# (list) List of modules your app needs
# --- FIX: Added dependencies for requests (urllib3, idna, certifi) and optional pyyaml ---
requirements = python3,kivy,kivymd,requests,pysocks,urllib3,idna,certifi,pyyaml

# (str) Application version
version = 1.0

# (list) Android permissions required by the app
android.permissions = INTERNET, ACCESS_NETWORK_STATE, WRITE_EXTERNAL_STORAGE, READ_EXTERNAL_STORAGE

# (int) Target Android API level
android.api = 31

# (int) Minimum Android API level supported
android.minapi = 21

# (list) Architectures to build for (remove armeabi-v7a for faster build)
android.archs = arm64-v8a, armeabi-v7a

# (str) App orientation
orientation = portrait

# (Optional) If you have a presplash or icon image, uncomment and set:
# presplash.filename = %(source.dir)s/presplash.png
# icon.filename = %(source.dir)s/icon.png


[buildozer]

# (int) Log verbosity (0 = errors only, 1 = normal, 2 = debug)
log_level = 2

# (int) Warn if running as root (Termux runs as user, so safe)
warn_on_root = 1
