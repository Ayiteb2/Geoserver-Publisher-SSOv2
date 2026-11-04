"""Publishing workflows: REST upload (shapefile/GeoPackage) and WFS-T append."""
import os
import re
import shutil
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from urllib.parse import quote

from qgis.core import QgsProject, QgsVectorFileWriter, NULL
from qgis.PyQt.QtCore import Qt
from qgis.PyQt.QtXml import QDomDocument

from . import gsp_log as L


def sanitize(name):
    s = re.sub(r"[^A-Za-z0-9_]", "_", name or "layer")
    if not s or s[0].isdigit():
        s = "l_" + s
    return s[:60]


# ------------------------------------------------------------------ export
def export_layer(layer, fmt, name, only_selected, workdir):
    """Export to a shapefile (returned as zip bytes) or GeoPackage (bytes). Returns (bytes, ext)."""
    L.info("Exporting layer '%s' (%s, %d features, CRS %s, selected-only=%s) as %s"
           % (layer.name(), layer.providerType(), layer.featureCount(), layer.crs().authid(),
              only_selected, fmt))
    opts = QgsVectorFileWriter.SaveVectorOptions()
    opts.fileEncoding = "UTF-8"
    opts.onlySelectedFeatures = bool(only_selected)
    if fmt == "shp":
        opts.driverName = "ESRI Shapefile"
        path = os.path.join(workdir, name + ".shp")
    else:
        opts.driverName = "GPKG"
        opts.layerName = name
        path = os.path.join(workdir, name + ".gpkg")
    ctx = QgsProject.instance().transformContext()
    try:
        res = QgsVectorFileWriter.writeAsVectorFormatV3(layer, path, ctx, opts)
    except AttributeError:
        res = QgsVectorFileWriter.writeAsVectorFormatV2(layer, path, ctx, opts)
    err, msg = res[0], res[1]
    L.debug("QgsVectorFileWriter result: %r" % (res,))
    if err != QgsVectorFileWriter.NoError:
        raise RuntimeError("Export failed (code %s): %s" % (err, msg))

    produced = sorted(os.listdir(workdir))
    L.info("Export produced files: " + ", ".join(
        "%s (%d B)" % (f, os.path.getsize(os.path.join(workdir, f))) for f in produced))

    if fmt == "shp":
        if not os.path.exists(os.path.join(workdir, name + ".prj")):
            L.warn("No .prj written; GeoServer will not know the CRS (layer CRS %s)." % layer.crs().authid())
        long_fields = [f.name() for f in layer.fields() if len(f.name()) > 10]
        if long_fields:
            L.warn("Shapefile truncates field names to 10 chars; affected: %s. "
                   "Use GeoPackage if the server has that extension." % long_fields)
        zpath = os.path.join(workdir, name + ".zip")
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
            for f in produced:
                if f.startswith(name + ".") and not f.endswith(".zip"):
                    z.write(os.path.join(workdir, f), f)
                    L.debug("  zipped " + f)
        with open(zpath, "rb") as fh:
            data = fh.read()
        L.info("Zip size: %d bytes" % len(data))
        return data, "shp"
    with open(path, "rb") as fh:
        data = fh.read()
    L.info("GeoPackage size: %d bytes" % len(data))
    return data, "gpkg"


# ------------------------------------------------------------ REST publish
def publish_rest(client, layer, ws, store, name, fmt, only_selected, with_style, style_name):
    """Returns True on success. All steps are logged; HTTP failures never raise."""
    L.info("=" * 70)
    L.info("REST PUBLISH: layer='%s' -> %s:%s (store=%s, format=%s)" % (layer.name(), ws, name, store, fmt))

    # Preflight: informational only, never blocks (non-admin users may legitimately get 403/404 here)
    r = client.probe_root()
    if r.status == 0:
        L.error("Server unreachable; aborting.")
        return False
    if r.blocked:
        L.warn("WFS answered with a sign-in page, not GeoServer. Checking REST anyway.")
    r = client.get_workspace(ws)
    if r.ok:
        L.info("Workspace '%s' is visible to this user." % ws)
    elif r.blocked:
        L.error("REST answered with a sign-in page, so nothing can be uploaded. Not exporting or "
                "uploading. Enter credentials or sign in with SSO (see hints above).")
        return False
    else:
        L.warn("Could not read workspace '%s' (HTTP %s). Continuing anyway - the upload is the real test."
               % (ws, r.status))

    workdir = tempfile.mkdtemp(prefix="gsp_")
    try:
        data, ext = export_layer(layer, fmt, name, only_selected, workdir)
        L.info("Uploading %d bytes to store '%s' ..." % (len(data), store))
        r = client.upload_vector_file(ws, store, data, ext)
        if not r.ok:
            if fmt == "gpkg" and r.status in (404, 405, 415, 500):
                L.error("GeoPackage upload needs the GeoPackage vector-store extension on the server. "
                        "Try the Shapefile format.")
            return False
        L.info("Upload accepted (HTTP %s)." % r.status)

        # Verify the layer really exists. This is what decides success: an upload that
        # "succeeded" against a proxy/login page leaves nothing on GeoServer.
        ft = client.get_featuretype(ws, store, name)
        if not ft.ok:
            lst = client.request("GET", "/rest/workspaces/%s/datastores/%s/featuretypes.json"
                                 % (quote(ws), quote(store)), accept="application/json", ok_statuses=(404, 403))
            L.error("VERIFICATION FAILED: feature type %s:%s is not on the server (HTTP %s%s). Store "
                    "contents: %s" % (ws, name, ft.status, ", " + ft.blocked if ft.blocked else "",
                                      lst.text[:500] if lst.ok else "<unavailable>"))
            return False
        try:
            j = ft.json()["featureType"]
        except Exception as e:
            L.error("VERIFICATION FAILED: the feature type answer is not GeoServer JSON (%s): %s"
                    % (e, ft.text[:300]))
            return False
        L.info("Verified feature type: name=%s nativeCRS=%s srs=%s enabled=%s"
               % (j.get("name"), str(j.get("nativeCRS"))[:60], j.get("srs"), j.get("enabled")))

        if with_style:
            apply_style(client, layer, ws, name, style_name or name)

        L.info("SUCCESS. Try: %s/%s/wms?service=WMS&version=1.1.0&request=GetMap&layers=%s:%s"
               "&styles=&bbox=-180,-90,180,90&width=512&height=256&srs=EPSG:4326&format=image/png"
               % (client.base_url, ws, ws, name))
        return True
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def apply_style(client, layer, ws, layer_name, style_name):
    L.info("Exporting QGIS style as SLD ...")
    p = os.path.join(tempfile.gettempdir(), "gsp_style_%s.sld" % style_name)
    try:
        res = layer.saveSldStyle(p)
        L.debug("saveSldStyle result: %r" % (res,))
        with open(p, "r", encoding="utf-8") as fh:
            sld = fh.read()
    except Exception:
        L.exception("SLD export failed (non-fatal, layer stays with default style)")
        return False
    finally:
        try:
            os.remove(p)
        except OSError:
            pass
    L.debug("SLD size: %d chars" % len(sld))
    r = client.create_style(ws, style_name, sld)
    if r.status == 409 or (not r.ok and "already exists" in r.text.lower()):
        L.info("Style exists, updating instead.")
        r = client.update_style(ws, style_name, sld)
    if not r.ok:
        L.warn("Style upload failed; layer keeps the default style.")
        return False
    r = client.set_default_style(ws, layer_name, ws, style_name)
    if not r.ok:
        L.warn("Style uploaded but could not be assigned as the default style.")
        return False
    L.info("Style '%s:%s' assigned as default." % (ws, style_name))
    return True


# ------------------------------------------------------------------ WFS-T
def _local(tag):
    return tag.split("}")[-1]


def describe_target(client, ws, layer_name):
    """Return (namespace, element_name, [(prop, type)], geom_prop, geom_type) or None."""
    r = client.wfs_describe(ws, layer_name)
    if not r.ok:
        return None
    if b"ExceptionReport" in r.body or b"ServiceException" in r.body:
        texts = re.findall(r"<(?:ows:)?ExceptionText>(.*?)</", r.text, re.S) or \
            re.findall(r"<ServiceException[^>]*>(.*?)</", r.text, re.S)
        L.error("GeoServer refused DescribeFeatureType for %s:%s: %s"
                % (ws, layer_name, "; ".join(t.strip() for t in texts) or r.text[:500]))
        L.error("HINT: check the layer name (case-sensitive) and that it exists in workspace '%s'." % ws)
        return None
    try:
        root = ET.fromstring(r.body)
    except ET.ParseError as e:
        L.error("DescribeFeatureType is not valid XML: %s" % e)
        return None
    ns = root.get("targetNamespace")
    props, geom_prop, geom_type = [], None, None
    for seq in root.iter():
        if _local(seq.tag) != "sequence":
            continue
        for el in seq:
            if _local(el.tag) != "element":
                continue
            t = el.get("type") or ""
            if t.startswith("gml:"):
                geom_prop, geom_type = el.get("name"), t
            else:
                props.append((el.get("name"), t))
    L.info("Target schema: ns=%s geometry=%s(%s) attributes=%s"
           % (ns, geom_prop, geom_type, [p[0] for p in props]))
    if not ns or not geom_prop:
        L.error("Could not determine namespace/geometry of the target layer from DescribeFeatureType.")
        return None
    return ns, layer_name, props, geom_prop, geom_type


def publish_wfst(client, layer, ws, target_layer, only_selected, batch=200):
    """Append features to an EXISTING layer through WFS-T (no REST access required)."""
    L.info("=" * 70)
    L.info("WFS-T APPEND: layer='%s' -> existing %s:%s" % (layer.name(), ws, target_layer))
    tgt = describe_target(client, ws, target_layer)
    if not tgt:
        L.error("Cannot append: target layer must already exist and be readable via WFS.")
        return False
    ns, ename, props, gprop, gtype = tgt
    field_map = {f.name().lower(): f.name() for f in layer.fields()}
    mapped = [(p, field_map[p.lower()]) for p, _ in props if p.lower() in field_map]
    missing = [p for p, _ in props if p.lower() not in field_map]
    L.info("Attribute mapping (target <- source): %s" % mapped)
    if missing:
        L.warn("Target attributes with no matching source field (will be left empty): %s" % missing)
    want_multi = "Multi" in gtype
    src_crs = layer.crs()
    L.info("Source CRS %s is sent as srsName=%s - the target layer must use the same CRS."
           % (src_crs.authid(), src_crs.authid()))

    feats = layer.getSelectedFeatures() if only_selected else layer.getFeatures()
    total, done, buf = 0, 0, []

    def flush(buf):
        xml = _build_insert(ns, ws, ename, gprop, mapped, buf, src_crs.authid(), want_multi)
        r = client.wfs_transaction(ws, xml)
        if not r.ok:
            return 0
        text = r.text
        if "ExceptionReport" in text or "ServiceException" in text:
            L.error("WFS-T returned an exception report (HTTP 200):\n" + text[:3000])
            return 0
        m = re.search(r"totalInserted>\s*(\d+)", text)
        n = int(m.group(1)) if m else 0
        L.info("Batch inserted %d of %d features." % (n, len(buf)))
        return n

    for f in feats:
        buf.append(f)
        total += 1
        if len(buf) >= batch:
            n = flush(buf)
            if n == 0:
                return False
            done += n
            buf = []
    if buf:
        n = flush(buf)
        if n == 0:
            return False
        done += n
    L.info("WFS-T finished: %d/%d features inserted." % (done, total))
    return done == total and total > 0


def _build_insert(ns, ws, ename, gprop, mapped, feats, srs, want_multi):
    doc = QDomDocument()
    root = doc.createElement("wfs:Transaction")
    root.setAttribute("service", "WFS")
    root.setAttribute("version", "1.1.0")
    root.setAttribute("xmlns:wfs", "http://www.opengis.net/wfs")
    root.setAttribute("xmlns:gml", "http://www.opengis.net/gml")
    root.setAttribute("xmlns:%s" % ws, ns)
    doc.appendChild(root)
    ins = doc.createElement("wfs:Insert")
    root.appendChild(ins)
    for f in feats:
        fe = doc.createElement("%s:%s" % (ws, ename))
        ins.appendChild(fe)
        g = f.geometry()
        if g and not g.isNull():
            if want_multi and not g.isMultipart():
                g.convertToMultiType()
            gel = doc.createElement("%s:%s" % (ws, gprop))
            # asGml3 lives on QgsAbstractGeometry, not QgsGeometry
            gml = g.constGet().asGml3(doc, 17, "gml")
            gml.setAttribute("srsName", srs)
            gel.appendChild(gml)
            fe.appendChild(gel)
        for tname, sname in mapped:
            v = f[sname]
            if v is None or v == NULL:
                continue
            el = doc.createElement("%s:%s" % (ws, tname))
            if hasattr(v, "toString") and not isinstance(v, str):
                try:
                    v = v.toString(Qt.ISODate)
                except TypeError:
                    v = v.toString()
            elif isinstance(v, bool):
                v = "true" if v else "false"
            el.appendChild(doc.createTextNode(str(v)))
            fe.appendChild(el)
    return doc.toString().encode("utf-8")
