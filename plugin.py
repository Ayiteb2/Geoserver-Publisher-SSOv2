import os
import hashlib
import time
from urllib.parse import quote

from qgis.core import QgsMapLayerProxyModel, QgsSettings, QgsApplication
from qgis.gui import QgsAuthConfigSelect, QgsMapLayerComboBox
from qgis.PyQt.QtCore import Qt, QTimer, QUrl
from qgis.PyQt.QtGui import QDesktopServices, QIcon
from qgis.PyQt.QtWidgets import (QAction, QCheckBox, QComboBox, QDialog, QFormLayout, QHBoxLayout,
                                 QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton,
                                 QSpinBox, QVBoxLayout, QApplication)

from . import gsp_log as L
from . import sso
from .gs_client import GeoServerClient
from . import publisher

S = "GeoServerPublisherSSO/"          # separate from the non-SSO plugin's settings
MENU = "GeoServer Publisher SSO"
SIGNIN_TIMEOUT_S = 600

# SSO session cookies, in memory only, per normalised GeoServer URL
_SESSIONS = {}


def _norm(url):
    return (url or "").strip().rstrip("/").lower()


def browser_profile_dir():
    return os.path.join(QgsApplication.qgisSettingsDirPath(), "geoserver_publisher_sso",
                        "browser_profile")


# URL parts of the sign-in round trip itself (GeoServer OIDC plugin, Spring Security form login)
_SIGNIN_STEPS = ("/oauth2/", "/login/oauth2/code/", "j_spring_security_check", "/j_spring_oauth2")


class SignInDialog(QDialog):
    """Opens Edge/Chrome at the GeoServer, waits for the SSO sign-in, captures the cookies.

    validate(cookie_header) -> (ok, detail) decides when the captured session is usable.
    """

    def __init__(self, base_url, validate, start_url=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Sign in with Microsoft")
        self.resize(560, 220)
        self.base_url = base_url.rstrip("/")
        # Starting at the REST URL makes the sign-in go through GeoServer's REST filter chain,
        # so the session it ends with is one REST accepts (a /web/ sign-in may not be).
        self.start_url = start_url or (self.base_url + "/web/")
        self._steered = False
        self._last_paths = None
        self._checked = set()
        self.validate = validate
        self.cookie = None
        self.session = None
        self._busy = False
        self._t0 = time.time()
        self._last_check = 0
        self._last_detail = ""

        self.status = QLabel("Starting the browser ...")
        self.status.setWordWrap(True)
        self.detail = QLabel("")
        self.detail.setWordWrap(True)
        self.detail.setStyleSheet("color: #666;")
        help_ = QLabel("A browser window opens at your GeoServer. Sign in there as usual "
                       "(Microsoft account, MFA). This window closes by itself once GeoServer "
                       "accepts the session. Only cookies for %s are read." % sso.host_of(base_url))
        help_.setWordWrap(True)
        b_check = QPushButton("Check now")
        b_cancel = QPushButton("Cancel")
        b_check.clicked.connect(lambda: self._tick(force=True))
        b_cancel.clicked.connect(self.reject)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(b_check)
        row.addWidget(b_cancel)
        lay = QVBoxLayout(self)
        lay.addWidget(help_)
        lay.addWidget(self.status)
        lay.addWidget(self.detail)
        lay.addStretch(1)
        lay.addLayout(row)

        self.timer = QTimer(self)
        self.timer.setInterval(1500)
        self.timer.timeout.connect(self._tick)
        QTimer.singleShot(0, self._start)

    def _fail(self, msg):
        self.timer.stop()
        self.status.setText("<b>%s</b>" % msg)
        L.error("SSO sign-in: " + msg)

    def _start(self):
        browser = sso.find_browser()
        if not browser:
            self._fail("Microsoft Edge or Google Chrome was not found. Sign in with your normal "
                       "browser and paste the Cookie header instead (see README).")
            return
        self.session = sso.BrowserSession(browser, browser_profile_dir(), self.start_url)
        try:
            self.session.launch()
        except Exception as e:
            self._fail("Could not start %s: %s" % (browser, e))
            return
        self.timer.start()

    def _tick(self, force=False):
        if self._busy or not self.session:
            return
        self._busy = True
        try:
            self._step(force)
        except Exception as e:
            L.exception("SSO sign-in step failed")
            self._fail("Lost the connection to the browser window (%s). Was it closed?" % e)
        finally:
            self._busy = False

    def _step(self, force):
        elapsed = time.time() - self._t0
        if elapsed > SIGNIN_TIMEOUT_S:
            self._fail("Gave up after %d minutes. %s" % (SIGNIN_TIMEOUT_S // 60, self._last_detail))
            return
        s = self.session
        if not s.ws:
            if s.try_connect():
                self.status.setText("Browser opened. Sign in there ...")
            elif elapsed > 30:
                self._fail("The browser did not open its DevTools connection. If a sign-in window "
                           "from an earlier attempt is still open, close it and try again.")
            return
        urls = s.page_urls()
        if not urls:
            self._fail("The browser window was closed before the sign-in finished.")
            return
        host = sso.host_of(self.base_url)
        on_site = [u for u in urls if sso.host_of(u) == host]
        if not on_site:
            self.status.setText("Waiting for you to finish signing in ... (now at %s)"
                                % (sso.host_of(urls[0]) or urls[0][:60]))
            return
        cookies = s.cookies_for(self.start_url)
        if not cookies:
            self.status.setText("Back on %s, waiting for the session cookie ..." % host)
            return
        header = sso.cookie_header(cookies)
        fp = hashlib.sha256(header.encode()).hexdigest()[:8]   # identifies the session in the log
        paths = sorted(set(u.split("?")[0] for u in on_site))
        # Only check once the window has settled on a GeoServer page (same pages on two polls in a
        # row) that is not a step of the sign-in itself. With GeoServer's OIDC plugin a rejected
        # check follows the redirect and starts a new sign-in in that same session, replacing the
        # one the browser is completing (0.2.1/0.2.2 checked every 4 s from the first page load).
        # After signing in, GeoServer usually lands on its home page, not on the REST URL.
        settled = paths == self._last_paths
        self._last_paths = paths
        in_flow = [p for p in paths if any(m in p for m in _SIGNIN_STEPS)]
        if not force:
            if in_flow or not settled:
                self.status.setText("Signing in ... (waiting for the window to finish on a "
                                    "GeoServer page)")
                return
            if fp in self._checked:
                if not self._steered and self.start_url not in paths:
                    # the session on this page was rejected: show the REST page once, which makes
                    # the browser sign in through REST and may yield a session REST accepts
                    self._steered = True
                    L.info("SSO sign-in: opening %s in the sign-in window" % self.start_url)
                    try:
                        s.call("Target.createTarget", {"url": self.start_url})
                    except Exception as e:
                        L.warn("Could not open the REST page in the browser: %s" % e)
                return
        self._checked.add(fp)
        self.status.setText("Checking the session with GeoServer (%d cookie(s): %s) ..."
                            % (len(cookies), ", ".join(c["name"] for c in cookies)))
        QApplication.processEvents()
        ok, detail = self.validate(header)
        L.info("SSO sign-in: checked session #%s (cookies: %s; window at %s) -> %s"
               % (fp, ", ".join(c["name"] for c in cookies), paths, "accepted" if ok else "rejected"))
        if ok:
            self.cookie = header
            self.timer.stop()
            s.close()
            self.accept()
            return
        self._last_detail = ("Signed in to the website, but GeoServer did not accept the session: %s."
                             % detail)
        self.status.setText("Signed in? Still waiting for GeoServer to accept the session ...")
        self.detail.setText(self._last_detail + " If this persists, the REST API may not accept "
                            "the web session; use a username/password instead.")

    def done(self, r):
        self.timer.stop()
        if self.session:
            self.session.close()
        super().done(r)


class PublishDialog(QDialog):
    def __init__(self, iface, parent=None):
        super().__init__(parent)
        self.iface = iface
        self.setWindowTitle("Publish to GeoServer (SSO)")
        self.resize(780, 800)
        st = QgsSettings()

        self.url = QLineEdit(st.value(S + "url", "http://localhost:8080/geoserver"))
        self.user = QLineEdit(st.value(S + "user", ""))
        self.user.setPlaceholderText("optional when signed in with SSO")
        self.pwd = QLineEdit()
        self.pwd.setEchoMode(QLineEdit.Password)
        self.remember = QCheckBox("Remember password (stored UNENCRYPTED in QGIS settings)")
        if st.value(S + "remember", False, type=bool):
            self.remember.setChecked(True)
            self.pwd.setText(st.value(S + "pwd", ""))
        self.authcfg = QgsAuthConfigSelect()
        cfg = st.value(S + "authcfg", "")
        if cfg:
            self.authcfg.setConfigId(cfg)

        self.cookie = QLineEdit(_SESSIONS.get(_norm(self.url.text()), ""))
        self.cookie.setEchoMode(QLineEdit.Password)
        self.cookie.setPlaceholderText("click Sign in, or paste the browser's Cookie header")
        self.sso_state = QLabel()
        b_sso = QPushButton("Sign in with Microsoft...")
        b_sso_clear = QPushButton("Clear")
        b_sso.clicked.connect(self.on_sso)
        b_sso_clear.clicked.connect(self.on_sso_clear)
        self.cookie.textChanged.connect(self._sso_label)
        sso_row = QHBoxLayout()
        sso_row.addWidget(self.cookie, 1)
        sso_row.addWidget(b_sso)
        sso_row.addWidget(b_sso_clear)
        self._sso_label()

        self.timeout = QSpinBox()
        self.timeout.setRange(5, 3600)
        self.timeout.setValue(int(st.value(S + "timeout", 300)))
        self.timeout.setSuffix(" s")

        self.layer = QgsMapLayerComboBox()
        self.layer.setFilters(QgsMapLayerProxyModel.VectorLayer)
        self.mode = QComboBox()
        self.mode.addItem("REST upload - create/replace store + layer (shapefile)", "rest_shp")
        self.mode.addItem("REST upload - create/replace store + layer (GeoPackage ext. required)", "rest_gpkg")
        self.mode.addItem("WFS-T append to an EXISTING layer (no REST access needed)", "wfst")
        self.ws = QLineEdit(st.value(S + "ws", ""))
        self.store = QLineEdit()
        self.store.setPlaceholderText("default: layer name")
        self.name = QLineEdit()
        self.name.setPlaceholderText("default: layer name (sanitised)")
        self.selected = QCheckBox("Selected features only")
        self.style = QCheckBox("Also upload the QGIS style as SLD (experimental)")

        form = QFormLayout()
        form.addRow("GeoServer URL", self.url)
        form.addRow("Username", self.user)
        form.addRow("Password", self.pwd)
        form.addRow("", self.remember)
        form.addRow("or QGIS auth config", self.authcfg)
        form.addRow("or SSO session", sso_row)
        form.addRow("", self.sso_state)
        form.addRow("Timeout", self.timeout)
        form.addRow(QLabel("<hr>"))
        form.addRow("QGIS layer", self.layer)
        form.addRow("Mode", self.mode)
        form.addRow("Workspace", self.ws)
        form.addRow("Store (REST)", self.store)
        form.addRow("Layer name", self.name)
        form.addRow("", self.selected)
        form.addRow("", self.style)

        self.logview = QPlainTextEdit()
        self.logview.setReadOnly(True)
        self.logview.setMaximumBlockCount(20000)
        self.logview.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.logview.setStyleSheet("font-family: Consolas, monospace; font-size: 9pt;")

        b_test = QPushButton("Test connection")
        b_pub = QPushButton("Publish")
        b_logf = QPushButton("Open log file")
        b_clear = QPushButton("Clear view")
        b_test.clicked.connect(self.on_test)
        b_pub.clicked.connect(self.on_publish)
        b_logf.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(L.log_file_path())))
        b_clear.clicked.connect(self.logview.clear)
        row = QHBoxLayout()
        for b in (b_test, b_pub, b_logf, b_clear):
            row.addWidget(b)

        lay = QVBoxLayout(self)
        lay.addLayout(form)
        lay.addLayout(row)
        lay.addWidget(QLabel("Log (full detail also in the QGIS '%s' log tab and %s):"
                             % (L.TAG, L.log_file_path())))
        lay.addWidget(self.logview, 1)
        L.add_listener(self._on_log)

    def done(self, r):
        L.remove_listener(self._on_log)
        super().done(r)

    def _on_log(self, level, msg):
        self.logview.appendPlainText("[%s] %s" % (level, msg))
        QApplication.processEvents()

    def _sso_label(self, *_):
        c = self.cookie.text().strip()
        if c:
            names = [p.split("=", 1)[0].strip() for p in c.split(";") if "=" in p]
            self.sso_state.setText("SSO session set: %d cookie(s) (%s). Kept in memory only."
                                   % (len(names), ", ".join(names)[:120]))
        else:
            self.sso_state.setText("No SSO session.")

    def _save(self):
        st = QgsSettings()
        st.setValue(S + "url", self.url.text())
        st.setValue(S + "user", self.user.text())
        st.setValue(S + "ws", self.ws.text())
        st.setValue(S + "authcfg", self.authcfg.configId())
        st.setValue(S + "timeout", self.timeout.value())
        st.setValue(S + "remember", self.remember.isChecked())
        st.setValue(S + "pwd", self.pwd.text() if self.remember.isChecked() else "")
        c = self.cookie.text().strip()
        if c:
            _SESSIONS[_norm(self.url.text())] = c
        else:
            _SESSIONS.pop(_norm(self.url.text()), None)

    def _client(self, cookie=None, with_credentials=True):
        if not self.url.text().strip():
            QMessageBox.warning(self, "GeoServer Publisher SSO", "Enter the GeoServer URL.")
            return None
        self._save()
        return GeoServerClient(self.url.text(),
                               self.user.text() if with_credentials else "",
                               self.pwd.text() if with_credentials else "",
                               self.authcfg.configId() if with_credentials else "",
                               self.timeout.value(),
                               self.cookie.text() if cookie is None else cookie)

    # ------------------------------------------------------------------ SSO
    def on_sso(self):
        if not self.url.text().strip():
            QMessageBox.warning(self, "GeoServer Publisher SSO", "Enter the GeoServer URL first.")
            return
        ws = self.ws.text().strip()
        if not ws:
            # WFS is often anonymous, so only a REST call proves the session is signed in
            # (a WFS check accepted a not-yet-signed-in session cookie in 0.2.0).
            QMessageBox.warning(self, "GeoServer Publisher SSO",
                                "Enter the workspace first: the sign-in is checked against that "
                                "workspace's REST endpoint.")
            return
        L.info("=" * 70)
        L.info("SSO SIGN-IN for %s (checked on REST workspace '%s')" % (self.url.text().strip(), ws))

        anon = self._client(cookie="", with_credentials=False).get_workspace(ws)
        if anon.ok:
            L.warn("REST workspace '%s' is readable anonymously, so the check cannot prove the "
                   "sign-in worked; the session is accepted as soon as it exists." % ws)

        def validate(header):
            # cookie only: prove the SSO session itself works, without the username/password
            c = self._client(cookie=header, with_credentials=False)
            r = c.get_workspace(ws)
            return r.ok, "REST workspace '%s' -> HTTP %s%s" % (
                ws, r.status, " (%s)" % r.blocked if r.blocked else "")

        rest_url = "%s/rest/workspaces/%s.json" % (self.url.text().strip().rstrip("/"),
                                                    quote(ws, safe=""))
        dlg = SignInDialog(self.url.text().strip(), validate, start_url=rest_url, parent=self)
        if dlg.exec_() == QDialog.Accepted and dlg.cookie:
            self.cookie.setText(dlg.cookie)
            self._save()
            L.info("SSO session stored for this QGIS session. Publishing will use it.")
        else:
            L.warn("SSO sign-in cancelled or not completed.")

    def on_sso_clear(self):
        self.cookie.clear()
        self._save()
        L.info("SSO session cleared.")

    # ----------------------------------------------------------------- test
    def on_test(self):
        try:
            self._run_test()
        except Exception:
            L.exception("Unhandled exception during connection test")

    def _run_test(self):
        c = self._client()
        if not c:
            return
        ws = self.ws.text().strip()
        L.info("=" * 70)
        L.info("CONNECTION TEST")
        r = c.probe_root()
        if r.status == 0:
            L.error("RESULT: server not reachable.")
            return
        if r.blocked:
            L.error("RESULT: the server is reachable but answered with a sign-in page (%s). Requests "
                    "are not authenticated: enter credentials or sign in with SSO." % r.blocked)
            return
        L.info("Server answered HTTP %s on WFS GetCapabilities (reachable)." % r.status)
        if not ws:
            L.warn("Enter a workspace to test the workspace-scoped REST endpoints.")
            return
        r = c.get_workspace(ws)
        L.info("Workspace read: HTTP %s (%s)" % (r.status, "OK" if r.ok else "not available"))
        r = c.list_datastores(ws)
        L.info("Datastore list: HTTP %s (%s)" % (r.status, "OK - REST access works for this user"
                                                  if r.ok else "REST access NOT confirmed"))
        r = c.request("GET", "/%s/ows" % ws, query={"service": "WFS", "request": "GetCapabilities"},
                      ok_statuses=(401, 403))
        L.info("WFS GetCapabilities: HTTP %s (%s)" % (r.status, "OK - WFS-T mode possible" if r.ok else "failed"))

    # -------------------------------------------------------------- publish
    def on_publish(self):
        c = self._client()
        if not c:
            return
        layer = self.layer.currentLayer()
        ws = self.ws.text().strip()
        if layer is None or not ws:
            QMessageBox.warning(self, "GeoServer Publisher SSO", "Choose a vector layer and enter a workspace.")
            return
        name = publisher.sanitize(self.name.text().strip() or layer.name())
        store = publisher.sanitize(self.store.text().strip() or name)
        mode = self.mode.currentData()
        self.setEnabled(False)
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            if mode == "wfst":
                ok = publisher.publish_wfst(c, layer, ws, name, self.selected.isChecked())
            else:
                ok = publisher.publish_rest(
                    c, layer, ws, store, name, "shp" if mode == "rest_shp" else "gpkg",
                    self.selected.isChecked(), self.style.isChecked(), name)
        except Exception:
            L.exception("Unhandled exception during publish")
            ok = False
        finally:
            QApplication.restoreOverrideCursor()
            self.setEnabled(True)
        if ok:
            self.iface.messageBar().pushSuccess("GeoServer Publisher SSO", "Published %s:%s" % (ws, name))
        else:
            L.error("PUBLISH FAILED - nothing was confirmed on the server. See the errors above.")
            self.iface.messageBar().pushCritical(
                "GeoServer Publisher SSO", "Publish failed - see the log in the dialog / log file.")


class GeoServerPublisherSSOPlugin:
    def __init__(self, iface):
        self.iface = iface
        self.action = None
        self.dlg = None

    def initGui(self):
        icon = QIcon(os.path.join(os.path.dirname(__file__), "icon.svg"))
        self.action = QAction(icon, "Publish to GeoServer (SSO)...", self.iface.mainWindow())
        self.action.triggered.connect(self.run)
        self.iface.addPluginToWebMenu(MENU, self.action)
        self.iface.addToolBarIcon(self.action)
        L.info("Plugin loaded. Log file: " + L.log_file_path())

    def unload(self):
        self.iface.removePluginWebMenu(MENU, self.action)
        self.iface.removeToolBarIcon(self.action)

    def run(self):
        self.dlg = PublishDialog(self.iface, self.iface.mainWindow())
        self.dlg.show()
