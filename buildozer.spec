[app]
title = Sing-Box Configurator
package.name = singboxconfig
package.domain = com.sirtenmaa

source.dir = .
source.include_exts = py,kv,json,yaml,conf,png,jpg,atlas

version = 1.0.0

requirements = python3,kivy==2.3.0,kivymd==1.2.0,requests,pyyaml

android.permissions = INTERNET,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE

orientation = portrait

android.archs = armeabi-v7a,arm64-v8a

android.api = 33
android.sdk = 33
android.ndk = 25b
android.build_tools = 33.0.2

[buildozer]
log_level = 2
warn_on_root = 1
