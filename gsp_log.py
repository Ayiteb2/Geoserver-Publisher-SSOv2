"""Detailed logging: QGIS message log + rotating file + in-dialog listeners."""
# Separate tag/file/logger from the non-SSO "GeoServer Publisher" plugin so both can be installed.
import logging
import logging.handlers
import os
import re
import traceback

from qgis.core import Qgis, QgsApplication, QgsMessageLog

TAG = "GeoServer Publisher SSO"
_listeners = []
_file_logger = None
_log_path = None

_SECRET_PATTERNS = [
    (re.compile(r"(Authorization:\s*Basic\s+)\S+", re.I), r"\1***REDACTED***"),
    # whole value, also matches Set-Cookie (SSO session cookies are as good as a password)
    (re.compile(r"(Cookie:\s*)[^\r\n]+", re.I), r"\1***REDACTED***"),
    (re.compile(r"(password=)[^&\s]+", re.I), r"\1***REDACTED***"),
]


def redact(text):
    for rx, rep in _SECRET_PATTERNS:
        text = rx.sub(rep, text)
    return text


def log_file_path():
    global _log_path
    if _log_path is None:
        d = os.path.join(QgsApplication.qgisSettingsDirPath(), "geoserver_publisher_sso")
        os.makedirs(d, exist_ok=True)
        _log_path = os.path.join(d, "geoserver_publisher_sso.log")
    return _log_path


def _get_file_logger():
    global _file_logger
    if _file_logger is None:
        _file_logger = logging.getLogger("geoserver_publisher_sso")
        _file_logger.setLevel(logging.DEBUG)
        _file_logger.propagate = False
        # Plugin reloads re-import this module but logging.getLogger returns the same
        # logger, so drop handlers from a previous load (otherwise every line is doubled).
        for old in list(_file_logger.handlers):
            _file_logger.removeHandler(old)
            try:
                old.close()
            except Exception:
                pass
        try:
            h = logging.handlers.RotatingFileHandler(
                log_file_path(), maxBytes=5_000_000, backupCount=3, encoding="utf-8")
            h.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s"))
            _file_logger.addHandler(h)
        except Exception:
            pass
    return _file_logger


def add_listener(fn):
    if fn not in _listeners:
        _listeners.append(fn)


def remove_listener(fn):
    if fn in _listeners:
        _listeners.remove(fn)


_QGIS_LEVEL = {
    "DEBUG": Qgis.Info, "INFO": Qgis.Info,
    "WARNING": Qgis.Warning, "ERROR": Qgis.Critical,
}


def log(level, msg):
    msg = redact(str(msg))
    try:
        _get_file_logger().log(getattr(logging, level, logging.INFO), msg)
    except Exception:
        pass
    try:
        QgsMessageLog.logMessage("[%s] %s" % (level, msg), TAG, _QGIS_LEVEL.get(level, Qgis.Info))
    except Exception:
        pass
    for fn in list(_listeners):
        try:
            fn(level, msg)
        except Exception:
            pass


def debug(m): log("DEBUG", m)
def info(m): log("INFO", m)
def warn(m): log("WARNING", m)
def error(m): log("ERROR", m)


def exception(context):
    error("%s\n%s" % (context, traceback.format_exc()))
