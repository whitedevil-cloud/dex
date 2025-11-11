#!/usr/bin/env python3
"""
Async Misconfiguration Scanner (extended)
- Async (aiohttp) passive checks + optional safe replication probes (active, non-destructive)
- Usage: python3 async_misconfig_scanner.py targets.txt --mode passive

Important: Only run against targets you are authorized to test. For active "replicate" mode you MUST pass --confirm-scope.
"""

import argparse
import asyncio
import aiohttp
import async_timeout
import ssl
import json
import time
from urllib.parse import urljoin, urlparse

USER_AGENT = "AsyncMisconfigScanner/1.0 (+https://example.com)"
COMMON_SENSITIVE_PATHS = [
    "/.git/config",
    "/.env",
    "/config/.env",
    "/wp-config.php",
    "/config.php",
    "/.htpasswd",
    "/.DS_Store",
    "/server-status",
]

def load_paths_from_file(filename):
    """Return a list of normalized paths from filename (one per line)."""
    out = []
    seen = set()
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for raw in f:
                line = raw.split('#', 1)[0].strip()   # allow inline comments starting with #
                if not line:
                    continue
                if not line.startswith('/'):
                    line = '/' + line
                if line not in seen:
                    seen.add(line)
                    out.append(line)
    except FileNotFoundError:
        print(f"[!] paths file not found: {filename}")
    except Exception as e:
        print(f"[!] error reading {filename}: {e}")
    return out

# Heuristics for subdomain takeover providers (basic strings to match)
TAKEOVER_INDICATORS = {
    "aws-s3": ["NoSuchBucket", "The specified bucket does not exist"],
    "github-pages": ["There isn't a GitHub Pages site here."],
    "heroku": ["No such app"],
    "azure": ["The resource you are looking for has been removed"],
}

async def fetch(session, url, method="GET", headers=None, allow_redirects=True, timeout_s=15):
    headers = headers or {"User-Agent": USER_AGENT}
    try:
        async with async_timeout.timeout(timeout_s):
            if method == "HEAD":
                async with session.head(url, headers=headers, allow_redirects=allow_redirects) as r:
                    text = await safe_text(r)
                    return r.status, dict(r.headers), text
            else:
                async with session.get(url, headers=headers, allow_redirects=allow_redirects) as r:
                    text = await safe_text(r)
                    return r.status, dict(r.headers), text
    except asyncio.TimeoutError:
        return None, None, None
    except aiohttp.ClientError:
        return None, None, None

async def safe_text(response):
    try:
        return await response.text()
    except Exception:
        return ""

async def tls_check(hostname, port=443):
    # non-blocking wrapper for ssl.get_server_certificate using thread
    def get_cert():
        try:
            return ssl.get_server_certificate((hostname, port))
        except Exception:
            return None
    cert_pem = await asyncio.to_thread(get_cert)
    return bool(cert_pem)

async def check_security_headers(status, headers, body):
    findings = []
    if headers is None:
        return findings
    h = {k.lower(): v for k, v in headers.items()}
    if "strict-transport-security" not in h:
        findings.append({"id":"missing_hsts","level":"warning","message":"HSTS header missing"})
    if "content-security-policy" not in h:
        findings.append({"id":"missing_csp","level":"warning","message":"Content-Security-Policy header missing"})
    if "x-frame-options" not in h and "content-security-policy" not in h:
        findings.append({"id":"missing_frame_options","level":"info","message":"No X-Frame-Options or CSP frame-ancestors detected"})
    if "x-content-type-options" not in h:
        findings.append({"id":"missing_x_content_type_options","level":"info","message":"X-Content-Type-Options header missing"})
    if "set-cookie" in h:
        sc = headers.get("Set-Cookie", "")
        if "httponly" not in sc.lower():
            findings.append({"id":"cookie_missing_httponly","level":"info","message":"Cookie without HttpOnly flag detected"})
        if "secure" not in sc.lower():
            findings.append({"id":"cookie_missing_secure","level":"info","message":"Cookie without Secure flag detected"})
    return findings

async def check_cors_passive(status, headers, body):
    findings = []
    if headers is None:
        return findings
    h = {k.lower(): v for k, v in headers.items()}
    if "access-control-allow-origin" in h:
        acao = h["access-control-allow-origin"].strip()
        if acao == "*":
            findings.append({"id":"cors_wildcard","level":"warning","message":"Access-Control-Allow-Origin is '*'"})
    return findings

async def check_directory_listing(status, headers, body):
    findings = []
    if body:
        b = body.lower()
        if "index of /" in b or "directory listing for" in b:
            findings.append({"id":"directory_listing","level":"warning","message":"Directory listing detected"})
    return findings

async def check_sensitive_files(session, base_url):
    findings = []
    for path in COMMON_SENSITIVE_PATHS:
        url = urljoin(base_url, path)
        status, headers, body = await fetch(session, url, method="HEAD")
        if status == 200:
            findings.append({"id":"sensitive_file_exposed","level":"high","message":f"{path} returned 200 on HEAD (may be exposed)","evidence":{"path":path,"status":status}})
    return findings

async def check_security_txt_and_robots(session, base_url):
    findings = []
    r_status, r_headers, r_body = await fetch(session, urljoin(base_url, "/robots.txt"), method="GET")
    if r_status == 200 and r_body:
        findings.append({"id":"robots_found","level":"info","message":"robots.txt exists"})
    s_status, s_headers, s_body = await fetch(session, urljoin(base_url, "/.well-known/security.txt"), method="GET")
    if s_status == 200:
        findings.append({"id":"security_txt","level":"info","message":"security.txt present"})
    return findings

async def passive_analyze(session, url):
    result = {"target": url, "findings": [], "status": {}}
    status, headers, body = await fetch(session, url, method="GET")
    result["status"]["http_status"] = status
    result["findings"].extend(await check_security_headers(status, headers, body))
    result["findings"].extend(await check_cors_passive(status, headers, body))
    result["findings"].extend(await check_directory_listing(status, headers, body))
    result["findings"].extend(await check_security_txt_and_robots(session, url))

    # TLS check (quick availability check)
    parsed = urlparse(url)
    if parsed.scheme == "https":
        hostname = parsed.hostname
        cert_present = await tls_check(hostname)
        if not cert_present:
            result["findings"].append({"id":"tls_no_cert","level":"high","message":"TLS certificate could not be retrieved"})
        result["status"]["tls_cert_present"] = cert_present

    # Sensitive files heuristic
    result["findings"].extend(await check_sensitive_files(session, url))

    # Subdomain takeover heuristic: check body strings
    if body:
        for provider, indicators in TAKEOVER_INDICATORS.items():
            for ind in indicators:
                if ind.lower() in body.lower():
                    result["findings"].append({"id":"takeover_indicator","level":"warning","message":f"Indicator for potential takeover: {provider}","evidence":ind})
    return result

async def active_replicate(session, url):
    """Active, but non-destructive replication probes.
    Requires explicit confirmation (--confirm-scope) before running.
    Actions performed:
      - CORS active test: send Origin header and check for reflected ACAO
      - Check for open redirect behavior (heuristic: detect redirect to external host in Location)
      - Attempt HEAD on common sensitive paths (already done passively but with GET vs HEAD differences)
    """
    result = {"target": url, "replication": [], "timestamp": time.time()}

    # CORS active probe
    origin = "https://evil.example"
    status, headers, body = await fetch(session, url, headers={"User-Agent": USER_AGENT, "Origin": origin})
    if headers and "access-control-allow-origin" in {k.lower(): v for k, v in headers.items()}:
        acao = headers.get("Access-Control-Allow-Origin", "").strip()
        if acao == origin or acao == "*":
            result["replication"].append({"id":"cors_active_reflection","level":"high","message":"Server reflects Access-Control-Allow-Origin for injected Origin (active probe detected)"})

    # Open redirect heuristic: check for redirects with external Location
    status, headers, body = await fetch(session, url, method="GET", allow_redirects=False)
    if status in (301,302,303,307,308) and headers:
        loc = headers.get("Location", "")
        if loc and urlparse(loc).netloc and urlparse(loc).netloc != urlparse(url).netloc:
            result["replication"].append({"id":"open_redirect_possible","level":"warning","message":f"Redirect to external host seen: {loc}"})

    # HEAD on sensitive files (extra pass)
    for path in COMMON_SENSITIVE_PATHS:
        full = urljoin(url, path)
        status, headers, body = await fetch(session, full, method="HEAD")
        if status == 200:
            result["replication"].append({"id":"sensitive_head_ok","level":"high","message":f"HEAD returned 200 for {path}","evidence":{"path":path}})

    return result

async def worker(queue, session, results, mode, confirm_scope, delay):
    while True:
        try:
            url = await asyncio.wait_for(queue.get(), timeout=1.0)
        except asyncio.TimeoutError:
            return
        try:
            res = await passive_analyze(session, url)
            if mode == "replicate":
                if not confirm_scope:
                    res["findings"].append({"id":"replication_skipped","level":"info","message":"Replication skipped because --confirm-scope was not provided"})
                else:
                    rep = await active_replicate(session, url)
                    res["replication"] = rep.get("replication", [])
            results.append(res)
            await asyncio.sleep(delay)
        finally:
            queue.task_done()

async def run_targets(targets, concurrency=5, mode="passive", confirm_scope=False, delay=0.5):
    queue = asyncio.Queue()
    for t in targets:
        queue.put_nowait(t)
    results = []
    timeout = aiohttp.ClientTimeout(total=30)
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        workers = [asyncio.create_task(worker(queue, session, results, mode, confirm_scope, delay)) for _ in range(concurrency)]
        await queue.join()
        for w in workers:
            w.cancel()
    return results

def load_targets(path):
    with open(path) as f:
        lines = [line.strip() for line in f if line.strip()]
    # ensure schemes
    processed = []
    for l in lines:
        if not l.startswith("http://") and not l.startswith("https://"):
            l = "https://" + l
        processed.append(l)
    return processed

def pretty_print(results):
    for r in results:
        print(f"\n== Target: {r.get('target')} ==")
        st = r.get("status", {}).get("http_status")
        print(f"HTTP Status: {st}")
        for f in r.get("findings", []):
            print(f" - [{f['level'].upper()}] {f['id']}: {f['message']}")
        if r.get("replication"):
            print(" Replication results:")
            for rp in r.get("replication", []):
                print(f"   - [{rp['level'].upper()}] {rp['id']}: {rp['message']}")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("targets_file")
    p.add_argument("--concurrency", type=int, default=6)
    p.add_argument("--delay", type=float, default=0.5)
    p.add_argument("--mode", choices=["passive","replicate"], default="passive")
    p.add_argument("--confirm-scope", action="store_true", help="Confirm you have authorization to run active replication probes")
    p.add_argument("--output", default="results.json")
    args = p.parse_args()

    if args.mode == "replicate" and not args.confirm_scope:
        print("ERROR: replicate mode requires --confirm-scope to be explicitly set (you must have authorization). Exiting.")
        return

    targets = load_targets(args.targets_file)
    results = asyncio.run(run_targets(targets, concurrency=args.concurrency, mode=args.mode, confirm_scope=args.confirm_scope, delay=args.delay))

    with open(args.output, "w") as fo:
        json.dump(results, fo, indent=2)

    pretty_print(results)
    print(f"\nSaved results to {args.output}")

if __name__ == '__main__':
    main()


# --- 403 diagnostics (defensive, non-destructive) ---
WAF_HEADER_INDICATORS = [
    "x-waf-request-id", "x-amzn-requestid", "x-amz-cf-id",
    "x-akamai-request-id", "x-edge-request-id", "x-sucuri-id",
    "x-cdn", "x-firewall", "server-timing"
]

async def analyze_403(session, url, status, headers, body):
    """
    Defensive diagnostics for 403 responses.
    - Collects headers and method behavior (HEAD/OPTIONS)
    - Looks for auth challenges (WWW-Authenticate), WAF/CDN markers, rate-limit headers.
    - Returns findings with non-actionable remediation guidance for defenders.
    """
    findings = []
    evidence = {
        "url": url,
        "initial_status": status,
        "initial_headers": headers or {},
        "initial_snippet": (body or "")[:200]
    }

    # 1) Check for WWW-Authenticate -> indicates protected resource needing credentials
    if headers:
        ww = None
        for k, v in (headers.items() if isinstance(headers, dict) else headers):
            if k.lower() == "www-authenticate":
                ww = v
                break
        if ww:
            findings.append({
                "id": "403_requires_auth",
                "level": "info",
                "message": "Resource returns 403 with WWW-Authenticate challenge (resource likely requires authentication).",
                "evidence": {"www_authenticate": ww}
            })
            evidence["www_authenticate"] = ww

    # 2) Options and Head method checks (safe, non-destructive)
    try:
        opt_status, opt_headers, opt_body = await fetch(session, url, method="OPTIONS")
        head_status, head_headers, head_body = await fetch(session, url, method="HEAD")
        evidence["options_status"] = opt_status
        evidence["head_status"] = head_status
        evidence["options_headers"] = opt_headers or {}
        evidence["head_headers"] = head_headers or {}
        # If OPTIONS returns 200 but GET returns 403 — could indicate method-specific ACLs or misconfiguration
        if opt_status and status and opt_status < 400 and status == 403:
            findings.append({
                "id": "403_method_discrepancy",
                "level": "info",
                "message": "OPTIONS returned a different status than GET; check method-based ACLs or server config.",
                "evidence": {"options_status": opt_status, "get_status": status}
            })
    except Exception:
        # keep diagnostics robust — don't fail analysis on probe errors
        pass

    # 3) WAF / CDN / Rate-limit indicators
    wafs = []
    if headers:
        for hk, hv in (headers.items() if isinstance(headers, dict) else headers):
            lk = hk.lower()
            if any(ind in lk for ind in WAF_HEADER_INDICATORS):
                wafs.append({hk: hv})
    if wafs:
        findings.append({
            "id": "403_waf_indicator",
            "level": "info",
            "message": "Response contains headers suggesting a WAF/CDN or access filtering may be enforcing the 403.",
            "evidence": wafs
        })
        evidence["waf_headers"] = wafs

    # 4) Rate-limit / Retry-After recommendations
    if headers:
        if "retry-after" in (k.lower() for k in (headers.keys() if isinstance(headers, dict) else headers)):
            ra = headers.get("Retry-After", headers.get("retry-after") if isinstance(headers, dict) else None)
            findings.append({
                "id": "403_retry_after",
                "level": "info",
                "message": f"Server returned Retry-After header: {ra}. This may be an access control or rate-limiting behavior.",
                "evidence": {"Retry-After": ra}
            })
            evidence["retry_after"] = ra

    # 5) Add non-actionable remediation guidance (for the asset owner)
    remediation = [
        "Verify intended access control: ensure the resource's ACL/permissions match the expected roles and identities.",
        "If authentication is required, confirm that WWW-Authenticate and response codes are consistent (401 vs 403 as appropriate).",
        "Check WAF/CDN rules or IP-based allowlists that may block legitimate traffic; inspect WAF logs for blocked signatures.",
        "If OPTIONS/HEAD differ from GET, check server config for method-based restrictions or override rules.",
        "Ensure file system / object storage permissions are correct (principle of least privilege) and not overly restrictive for intended consumers.",
        "Check for misconfigured reverse proxies or routing rules that may incorrectly return 403."
    ]

    findings.append({
        "id": "403_remediation_suggestions",
        "level": "info",
        "message": "Possible remediations (for the asset owner / admin).",
        "remediation": remediation
    })

    return {"diagnostics": findings, "evidence": evidence}

# Integration note: passive_analyze() in the main scanner should call analyze_403() when it observes status == 403
# and merge the returned diagnostics into the result JSON. Example (insert in passive_analyze after fetching):
# if status == 403:
#     diag = await analyze_403(session, url, status, headers, body)
#     result['findings'].extend(diag['diagnostics'])
#     result['evidence'] = diag['evidence']
