#!/usr/bin/env python3
"""Jenkins core/plugin vulnerability scanner (stdlib only).
Compares installed versions against official Jenkins update-center security warnings."""
import urllib.error, argparse, base64, html, json, os, re, ssl, sys, urllib.request
from datetime import datetime

UC_URL = "https://updates.jenkins.io/update-center.actual.json"
UC_STABLE_URL = "https://updates.jenkins.io/stable/update-center.actual.json"

def ctx(insecure):
    if insecure:
        c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE; return c
    return None

def http_get(url, insecure=False, auth=None, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "jenkins-vuln-scan/1.0"})
    if auth:
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode())
    r = urllib.request.urlopen(req, timeout=timeout, context=ctx(insecure))
    return r.headers, r.read()

def load_uc(path_or_url, insecure):
    if os.path.exists(path_or_url):
        txt = open(path_or_url, encoding="utf-8").read()
    else:
        txt = http_get(path_or_url, insecure)[1].decode("utf-8")
    txt = txt.strip()
    if txt.startswith("updateCenter.post("):  # JSONP variant
        txt = txt[len("updateCenter.post("):].rstrip(");\n ")
    return json.loads(txt)

def severity(msg):
    m = msg.lower()
    if "rogue" in m or "remote code" in m or "rce" in m or "arbitrary code" in m or "sandbox bypass" in m: return "CRITICAL"
    if "credential" in m or "csrf" in m or "xss" in m or "permission check" in m or "xxe" in m or "path traversal" in m: return "HIGH"
    if "multiple security" in m or "vulnerab" in m: return "HIGH"
    return "MEDIUM"

def matches(warning, version):
    for v in warning.get("versions", []):
        try:
            if re.fullmatch(v["pattern"], version): return True
        except re.error:
            pass
    return False

def load_plugins_file(path):
    txt = open(path, encoding="utf-8").read().strip()
    if txt.startswith("{") or txt.startswith("["):
        d = json.loads(txt)
        return d.get("plugins", []) if isinstance(d, dict) else d
    out = []
    for line in txt.splitlines():
        line = line.split("#")[0].strip()
        if ":" in line:
            n, v = line.split(":", 1)
            out.append(dict(shortName=n.strip(), version=v.strip(), active=True, hasUpdate=None))
    return out

def is_lts(version):
    return bool(re.fullmatch(r"\d+\.\d+\.\d+", version))

def scan(core_version, plugins, uc, uc_stable=None):
    warnings = uc.get("warnings", [])
    findings, updates = [], []
    latest_core = uc.get("core", {}).get("version")
    latest_lts = (uc_stable or {}).get("core", {}).get("version")
    lts = is_lts(core_version) if core_version else False
    core_rec = (latest_lts if lts and latest_lts else latest_core) or "-"
    if core_version:
        for w in warnings:
            if w.get("type") == "core" and matches(w, core_version):
                findings.append(dict(component="jenkins-core", title="Jenkins core", current=core_version,
                    recommended=core_rec, id=w["id"], message=w["message"], url=w["url"], severity=severity(w["message"])))
    for p in plugins:
        name, ver = p.get("shortName"), str(p.get("version", ""))
        info = uc.get("plugins", {}).get(name, {})
        latest = info.get("version", "-")
        hu = p.get("hasUpdate")
        if hu is None: hu = latest not in ("-", ver)
        if hu:
            updates.append(dict(name=name, title=info.get("title", p.get("longName", name)), current=ver, latest=latest, active=p.get("active")))
        for w in warnings:
            if w.get("type") == "plugin" and w.get("name") == name and matches(w, ver):
                findings.append(dict(component=name, title=info.get("title", p.get("longName", name)), current=ver,
                    recommended=latest, id=w["id"], message=w["message"], url=w["url"],
                    severity=severity(w["message"]), active=p.get("active")))
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    findings.sort(key=lambda f: (order[f["severity"]], f["component"]))
    return dict(generated=datetime.now().isoformat(timespec="seconds"), core=dict(version=core_version,
        channel="LTS" if lts else "weekly", latest_weekly=latest_core, latest_lts=latest_lts, recommended=core_rec),
        plugin_count=len(plugins), vulnerabilities=findings, updates_available=updates)

def table(rows, cols):
    w = [max(len(c), *(len(str(r.get(c, ""))[:70]) for r in rows)) if rows else len(c) for c in cols]
    line = "  ".join(c.ljust(x) for c, x in zip(cols, w))
    out = [line, "-" * len(line)]
    out += ["  ".join(str(r.get(c, ""))[:70].ljust(x) for c, x in zip(cols, w)) for r in rows]
    return "\n".join(out)

def to_md(r, jenkins_url):
    c = r["core"]
    s = [f"# Jenkins Security Scan Report", f"- Jenkins: {jenkins_url}", f"- Scan time: {r['generated']}",
         f"- Core: **{c['version']}** ({c['channel']}) → recommended **{c['recommended']}**",
         (f"- ⚠️ {r['plugin_note']}\n" if r.get('plugin_note') else "") + f"- Plugins installed: {r['plugin_count']} | Vulnerable findings: **{len(r['vulnerabilities'])}** | Updates available: {len(r['updates_available'])}", ""]
    if r["vulnerabilities"]:
        s += ["## Vulnerable components (please update)", "", "| Severity | Component | Current | Recommended | Advisory |", "|---|---|---|---|---|"]
        s += [f"| {f['severity']} | {f['component']} | {f['current']} | {f['recommended']} | [{f['id']}]({f['url']}) {f['message']} |" for f in r["vulnerabilities"]]
    else:
        s += ["## No known vulnerabilities found ✅"]
    if r["updates_available"]:
        s += ["", "## Other plugins with updates", "", "| Plugin | Current | Latest |", "|---|---|---|"]
        s += [f"| {u['name']} | {u['current']} | {u['latest']} |" for u in r["updates_available"]]
    s += ["", "_Severity is estimated from advisory text; see the advisory link for the official CVSS._"]
    return "\n".join(s) + "\n"

def to_html(r, jenkins_url):
    e = html.escape; c = r["core"]
    col = {"CRITICAL": "#b00020", "HIGH": "#e65100", "MEDIUM": "#f9a825"}
    vrows = "".join(f"<tr><td style='background:{col[f['severity']]};color:#fff'>{f['severity']}</td><td>{e(f['component'])}<br><small>{e(str(f['title']))}</small></td><td>{e(f['current'])}</td><td><b>{e(str(f['recommended']))}</b></td><td><a href='{e(f['url'])}'>{e(f['id'])}</a><br>{e(f['message'])}</td></tr>" for f in r["vulnerabilities"]) or "<tr><td colspan=5>No known vulnerabilities ✅</td></tr>"
    urows = "".join(f"<tr><td>{e(u['name'])}</td><td>{e(u['current'])}</td><td>{e(str(u['latest']))}</td></tr>" for u in r["updates_available"]) or "<tr><td colspan=3>All up to date</td></tr>"
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>Jenkins Security Scan</title>
<style>body{{font-family:sans-serif;margin:24px}}table{{border-collapse:collapse;width:100%;margin-bottom:24px}}td,th{{border:1px solid #ccc;padding:6px;vertical-align:top}}th{{background:#333;color:#fff}}</style></head><body>
<h1>Jenkins Security Scan</h1><p>Jenkins: {e(jenkins_url)}<br>Scan time: {e(r['generated'])}<br>
Core: <b>{e(str(c['version']))}</b> ({c['channel']}) → recommended <b>{e(str(c['recommended']))}</b> (latest weekly {e(str(c['latest_weekly']))}, latest LTS {e(str(c['latest_lts']))})<br>
{('<b style=color:#b00020>⚠ '+e(r['plugin_note'])+'</b><br>') if r.get('plugin_note') else ''}Plugins: {r['plugin_count']} | Vulnerable findings: <b>{len(r['vulnerabilities'])}</b> | Updates available: {len(r['updates_available'])}</p>
<h2>Vulnerabilities</h2><table><tr><th>Severity</th><th>Component</th><th>Current</th><th>Recommended</th><th>Advisory</th></tr>{vrows}</table>
<h2>Plugins with updates</h2><table><tr><th>Plugin</th><th>Current</th><th>Latest</th></tr>{urows}</table>
<p><small>Severity is estimated from advisory text; open the advisory link for official CVSS.</small></p></body></html>"""

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", default=os.environ.get("JENKINS_URL"))
    ap.add_argument("--update-center", default=UC_URL, help="URL or local file of update-center.actual.json")
    ap.add_argument("--update-center-stable", default=UC_STABLE_URL, help="LTS update-center URL/file ('' to skip)")
    ap.add_argument("--plugins-file", help="plugins list exported by admin: plugins.txt (name:version) or pluginManager JSON")
    ap.add_argument("--out", default="scan-output")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (Jenkins + update center)")
    ap.add_argument("--fail-on-vuln", action="store_true", help="exit 2 if vulnerabilities are found")
    a = ap.parse_args()
    user, token = os.environ.get("JENKINS_USER"), os.environ.get("JENKINS_TOKEN")
    if not a.url or not user or not token:
        sys.exit("ERROR: set JENKINS_URL, JENKINS_USER, JENKINS_TOKEN")
    base = a.url.rstrip("/"); auth = (user, token)
    try:
        hdr, _ = http_get(base + "/api/json", a.insecure, auth)
        core = hdr.get("X-Jenkins")
        plugin_note = None
        if a.plugins_file:
            plugins = load_plugins_file(a.plugins_file)
            plugin_note = f"plugins loaded from file {a.plugins_file}"
        else:
            try:
                _, body = http_get(base + "/pluginManager/api/json?depth=1&tree=plugins[shortName,longName,version,active,hasUpdate]", a.insecure, auth)
                plugins = json.loads(body).get("plugins", [])
            except urllib.error.HTTPError as he:
                if he.code not in (401, 403): raise
                plugins = []
                plugin_note = (f"pluginManager API returned HTTP {he.code}: account lacks Overall/SystemRead or Administer. "
                               "Plugins NOT scanned (core only). Ask DevOps for SystemRead or an exported list (--plugins-file).")
                print("WARN: " + plugin_note, file=sys.stderr)
        uc = load_uc(a.update_center, a.insecure)
        ucs = None
        if a.update_center_stable:
            try: ucs = load_uc(a.update_center_stable, a.insecure)
            except Exception as ex: print(f"WARN: cannot load LTS update center: {ex}", file=sys.stderr)
    except Exception as ex:
        sys.exit(f"ERROR: {ex}")
    if not core:
        print("WARN: X-Jenkins header missing; core version unknown", file=sys.stderr)
    r = scan(core, plugins, uc, ucs)
    r["plugin_note"] = plugin_note
    os.makedirs(a.out, exist_ok=True)
    json.dump(r, open(os.path.join(a.out, "report.json"), "w"), indent=2, ensure_ascii=False)
    open(os.path.join(a.out, "report.html"), "w", encoding="utf-8").write(to_html(r, base))
    open(os.path.join(a.out, "summary.md"), "w", encoding="utf-8").write(to_md(r, base))
    c = r["core"]
    print(f"Jenkins core {c['version']} ({c['channel']}), recommended {c['recommended']}; {r['plugin_count']} plugins")
    print(f"\n== Vulnerabilities: {len(r['vulnerabilities'])} ==")
    print(table(r["vulnerabilities"], ["severity", "component", "current", "recommended", "id"]))
    print(f"\n== Updates available: {len(r['updates_available'])} ==")
    print(table(r["updates_available"], ["name", "current", "latest"]))
    print(f"\nReports written to {a.out}/ (report.json, report.html, summary.md)")
    if r["vulnerabilities"] and a.fail_on_vuln:
        sys.exit(2)

if __name__ == "__main__":
    main()
