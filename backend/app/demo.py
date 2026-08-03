from __future__ import annotations

import zipfile
from pathlib import Path


DEMO_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.msw.demo"
    android:versionName="1.0-demo">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <application
        android:label="MSW Demo Bank"
        android:debuggable="true"
        android:allowBackup="true"
        android:usesCleartextTraffic="false">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="mswdemo" android:host="login" />
            </intent-filter>
        </activity>
        <receiver android:name=".DebugReceiver" android:exported="true" />
    </application>
</manifest>
"""

DEMO_CODE = """
package com.example.msw.demo;
import android.webkit.WebView;
import okhttp3.CertificatePinner;

class SecurityControls {
  static final String API = "https://api.demo.invalid/v1";
  static final String DEMO_TOKEN = "token=demo-token-not-a-real-secret";
  boolean isRooted() {
    return new java.io.File("/system/xbin/su").exists() || detectMagisk();
  }
  void configure(WebView view) {
    view.getSettings().setJavaScriptEnabled(true);
    view.addJavascriptInterface(new Object(), "DemoBridge");
  }
  void pin() {
    new CertificatePinner.Builder().add("api.demo.invalid", "sha256/AAAAAAAAAAAAAAAAAAAA");
  }
  boolean detectMagisk() { return false; }
}
"""


def create_demo_apk(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", DEMO_MANIFEST)
        archive.writestr(
            "sources/com/example/msw/demo/SecurityControls.java", DEMO_CODE
        )
        archive.writestr("assets/demo.json", '{"environment":"mock","safe":true}')
        archive.writestr("lib/arm64-v8a/libdemo.so", b"\x7fELFmock-native-library")
    return path

