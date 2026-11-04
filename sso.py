"""Browser sign-in for SSO-protected GeoServers (e.g. Azure / OpenID Connect behind a proxy).

QGIS's embedded browsers cannot run Microsoft's sign-in page (QtWebEngine has no Python
bindings in the standard QGIS build and QtWebKit renders it blank). So this opens a real
Microsoft Edge (or Google Chrome) window with its own profile and DevTools remote debugging
bound to 127.0.0.1, waits until the user is back on the GeoServer site, reads that site's
cookies through the Chrome DevTools Protocol, checks that GeoServer accepts them, and closes
the window.

The cookies are kept in memory only (per QGIS session) and are redacted from all logs.
The browser profile lives in <QGIS profile>/geoserver_publisher_sso/browser_profile so the
identity provider can remember the account between sign-ins.
"""
import base64
import hashlib
import json
import os
import socket
import struct
import subprocess
import time
import urllib.request
from urllib.parse import urlsplit

from . import gsp_log as L

# --------------------------------------------------------------- browser discovery
_CANDIDATES = [
    ("PROGRAMFILES(X86)", r"Microsoft\Edge\Application\msedge.exe"),
    ("PROGRAMFILES", r"Microsoft\Edge\Application\msedge.exe"),
    ("LOCALAPPDATA", r"Microsoft\Edge\Application\msedge.exe"),
    ("PROGRAMFILES", r"Google\Chrome\Application\chrome.exe"),
    ("PROGRAMFILES(X86)", r"Google\Chrome\Application\chrome.exe"),
    ("LOCALAPPDATA", r"Google\Chrome\Application\chrome.exe"),
]


def find_browser():
    for env, rel in _CANDIDATES:
        base = os.environ.get(env)
        if base:
            p = os.path.join(base, rel)
            if os.path.isfile(p):
                return p
    for exe in ("msedge.exe", "chrome.exe"):          # registry "App Paths"
        try:
            import winreg
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\\" + exe)
            p = winreg.QueryValue(k, None)
            if p and os.path.isfile(p):
                return p
        except Exception:
            pass
    return None


def host_of(url):
    try:
        return (urlsplit(url).hostname or "").lower()
    except Exception:
        return ""


def cookie_matches(cookie, url):
    """Would a browser send this cookie (CDP cookie dict) to url?"""
    u = urlsplit(url)
    host = (u.hostname or "").lower()
    dom = (cookie.get("domain") or "").lower()
    bare = dom.lstrip(".")
    if not bare or not (host == bare or host.endswith("." + bare)):
        return False
    if cookie.get("secure") and u.scheme != "https" and host not in ("localhost", "127.0.0.1"):
        return False
    cpath = cookie.get("path") or "/"
    path = u.path or "/"
    if not (path == cpath or path.startswith(cpath.rstrip("/") + "/") or cpath == "/"):
        return False
    exp = cookie.get("expires", -1)
    if exp not in (None, -1) and exp > 0 and exp < time.time():
        return False
    return True


def cookie_header(cookies):
    return "; ".join("%s=%s" % (c["name"], c["value"]) for c in cookies)


# --------------------------------------------------------- minimal websocket client
# (QGIS's Python has no websocket module and QtWebSockets is not shipped.)
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class WebSocket:
    def __init__(self, url, timeout=10):
        u = urlsplit(url)
        if u.scheme != "ws":
            raise ValueError("only ws:// is supported: " + url)
        self.sock = socket.create_connection((u.hostname, u.port or 80), timeout)
        self.sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        path = (u.path or "/") + ("?" + u.query if u.query else "")
        # No Origin header on purpose: DevTools only rejects connections that send one.
        req = ("GET %s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n"
               % (path, u.hostname, u.port or 80, key))
        self.sock.sendall(req.encode("ascii"))
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("websocket handshake: connection closed")
            data += chunk
        head, self._buf = data.split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1").split("\r\n")
        if " 101 " not in lines[0] + " ":
            raise ConnectionError("websocket handshake refused: " + lines[0])
        want = base64.b64encode(hashlib.sha1((key + _WS_GUID).encode()).digest()).decode()
        got = {l.split(":", 1)[0].strip().lower(): l.split(":", 1)[1].strip()
               for l in lines[1:] if ":" in l}.get("sec-websocket-accept")
        if got != want:
            raise ConnectionError("websocket handshake: bad Sec-WebSocket-Accept")

    def _exact(self, n):
        while len(self._buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("websocket closed")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def _send(self, opcode, payload):
        n = len(payload)
        hdr = bytearray([0x80 | opcode])
        if n < 126:
            hdr.append(0x80 | n)
        elif n < 65536:
            hdr.append(0x80 | 126)
            hdr += struct.pack(">H", n)
        else:
            hdr.append(0x80 | 127)
            hdr += struct.pack(">Q", n)
        mask = os.urandom(4)
        hdr += mask
        self.sock.sendall(bytes(hdr) + bytes(b ^ mask[i & 3] for i, b in enumerate(payload)))

    def send_text(self, text):
        self._send(0x1, text.encode("utf-8"))

    def recv_text(self):
        parts = []
        while True:
            b1, b2 = self._exact(2)
            op, n = b1 & 0x0F, b2 & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._exact(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._exact(8))[0]
            mask = self._exact(4) if b2 & 0x80 else None
            data = self._exact(n)
            if mask:
                data = bytes(b ^ mask[i & 3] for i, b in enumerate(data))
            if op == 0x8:
                raise ConnectionError("websocket closed by the browser")
            if op == 0x9:
                self._send(0xA, data)
                continue
            if op == 0xA:
                continue
            parts.append(data)
            if b1 & 0x80:
                return b"".join(parts).decode("utf-8", "replace")

    def close(self):
        try:
            self._send(0x8, b"")
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


# ------------------------------------------------------------ browser session (CDP)
_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class BrowserSession:
    """A dedicated browser window with DevTools on 127.0.0.1 (random port)."""

    def __init__(self, browser, profile_dir, start_url):
        self.browser, self.profile_dir, self.start_url = browser, profile_dir, start_url
        self.proc = None
        self.port = None
        self.ws = None
        self._id = 0

    def launch(self):
        os.makedirs(self.profile_dir, exist_ok=True)
        marker = os.path.join(self.profile_dir, "DevToolsActivePort")
        try:
            os.remove(marker)       # stale file from an earlier run
        except OSError:
            pass
        args = [self.browser,
                "--remote-debugging-address=127.0.0.1",
                "--remote-debugging-port=0",           # browser picks a free port, written to marker
                "--user-data-dir=" + self.profile_dir,
                "--no-first-run", "--no-default-browser-check",
                "--new-window", self.start_url]
        L.info("Launching browser for sign-in: %s (profile %s)" % (self.browser, self.profile_dir))
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self.proc = subprocess.Popen(args, creationflags=flags, close_fds=True)

    def try_connect(self):
        """Non-blocking-ish: True once the DevTools endpoint is up and connected."""
        if self.ws:
            return True
        marker = os.path.join(self.profile_dir, "DevToolsActivePort")
        try:
            with open(marker, "r", encoding="utf-8") as fh:
                port = int(fh.readline().strip())
        except (OSError, ValueError):
            return False
        try:
            info = json.loads(_NO_PROXY.open("http://127.0.0.1:%d/json/version" % port, timeout=3).read())
            self.ws = WebSocket(info["webSocketDebuggerUrl"], timeout=10)
        except Exception as e:
            L.debug("DevTools not ready yet: %s" % e)
            return False
        self.port = port
        L.info("Connected to the browser (%s) on 127.0.0.1:%d." % (info.get("Browser"), port))
        return True

    def call(self, method, params=None, timeout=10):
        self._id += 1
        mid = self._id
        self.ws.sock.settimeout(timeout)
        self.ws.send_text(json.dumps({"id": mid, "method": method, "params": params or {}}))
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = json.loads(self.ws.recv_text())
            if msg.get("id") == mid:
                if "error" in msg:
                    raise RuntimeError("%s: %s" % (method, msg["error"]))
                return msg.get("result", {})
        raise TimeoutError(method)

    def page_urls(self):
        res = self.call("Target.getTargets")
        return [t.get("url", "") for t in res.get("targetInfos", []) if t.get("type") == "page"]

    def cookies_for(self, url):
        allc = self.call("Storage.getCookies").get("cookies", [])
        return [c for c in allc if cookie_matches(c, url)]

    def close(self):
        if self.ws:
            try:
                self.call("Browser.close", timeout=3)
            except Exception:
                pass
            self.ws.close()
            self.ws = None
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.wait(5)
            except Exception:
                try:
                    self.proc.terminate()
                except Exception:
                    pass
