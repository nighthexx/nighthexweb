import os, re, io, zipfile, socket, ipaddress, time, secrets, json, html
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse
import requests
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, jsonify, session, send_file, Response
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024
UA = 'NIGHT-HEX-Responsible-Audit/4.0'
TIMEOUT = 8
MAX_BODY = 350_000
RATE_LIMIT_SECONDS = 12
# Larger, still bounded crawl to avoid runaway requests and Render timeouts.
MAX_PAGES = 40
SCAN_BUDGET_SECONDS = 32
_recent = defaultdict(float)


def public_ip(ip):
    try: return ipaddress.ip_address(ip).is_global
    except ValueError: return False


def validate_url(raw):
    raw = (raw or '').strip()
    if len(raw) > 2048: raise ValueError('URL is too long.')
    if not re.match(r'^https?://', raw, re.I): raw = 'https://' + raw
    p = urlparse(raw)
    if p.scheme.lower() not in ('http', 'https') or not p.hostname: raise ValueError('Enter a valid public HTTP/HTTPS URL.')
    if p.username or p.password: raise ValueError('URLs with usernames/passwords are not allowed.')
    host = p.hostname.rstrip('.').lower()
    if host == 'localhost' or host.endswith(('.localhost','.local','.internal','.test')): raise ValueError('Local/internal hosts are blocked.')
    port = p.port or (443 if p.scheme.lower() == 'https' else 80)
    if (p.scheme.lower(), port) not in (('http',80),('https',443)): raise ValueError('Only standard HTTP/HTTPS ports are allowed.')
    try:
        if public_ip(host): ips = [host]
        else: ips = list({x[4][0] for x in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
        if not ips or any(not public_ip(x) for x in ips): raise ValueError('Private or reserved network targets are blocked.')
    except socket.gaierror: raise ValueError('Could not resolve the domain.')
    clean = urlunparse((p.scheme.lower(), p.netloc, p.path or '/', '', p.query, ''))
    return {'url':clean,'host':host,'scheme':p.scheme.lower()}


def fetch(url):
    t = validate_url(url)
    with requests.Session() as s:
        s.trust_env = False
        with s.get(t['url'], headers={'User-Agent':UA,'Accept':'text/html,*/*;q=0.5'}, timeout=(4,TIMEOUT), allow_redirects=False, stream=True, verify=True) as r:
            chunks=[]; total=0; ct=r.headers.get('Content-Type','')
            if 'text/html' in ct.lower() or not ct:
                for c in r.iter_content(8192):
                    if not c: continue
                    take=c[:MAX_BODY-total]; chunks.append(take); total+=len(take)
                    if total>=MAX_BODY: break
            return {'url':t['url'],'host':t['host'],'scheme':t['scheme'],'status':r.status_code,'headers':{k.lower():v for k,v in r.headers.items()},'body':b''.join(chunks).decode(r.encoding or 'utf-8','replace'),'content_type':ct or 'Not provided','seconds':round(r.elapsed.total_seconds(),2),'location':r.headers.get('Location','')}


def scan_site(raw):
    """Bounded, non-destructive same-origin crawl and configuration review."""
    scan_started = time.monotonic()
    root = fetch(raw)
    root_url = root['url']
    root_parts = urlparse(root_url)
    root_host = root_parts.hostname
    checks = []
    pages = [root]
    seen = {root_url}
    queue = deque()
    soup0 = BeautifulSoup(root['body'], 'html.parser')
    for a in soup0.find_all('a', href=True):
        href = (a.get('href') or '').strip()
        if not href or href.startswith(('#', 'mailto:', 'tel:', 'javascript:')):
            continue
        from urllib.parse import urljoin
        candidate = urljoin(root_url, href)
        parts = urlparse(candidate)
        if parts.scheme not in ('http', 'https') or parts.hostname != root_host:
            continue
        if parts.username or parts.password or parts.port not in (None, 80, 443):
            continue
        # Crawl public page paths only; avoid query-driven actions and fragments.
        if parts.query:
            continue
        candidate = urlunparse((parts.scheme, parts.netloc, parts.path or '/', '', '', ''))
        if candidate not in seen:
            seen.add(candidate)
            queue.append(candidate)
    while queue and len(pages) < MAX_PAGES and (time.monotonic() - scan_started) < SCAN_BUDGET_SECONDS:
        candidate = queue.popleft()
        try:
            page = fetch(candidate)
        except (ValueError, requests.RequestException):
            continue
        pages.append(page)
        if 'text/html' not in (page.get('content_type') or '').lower() and page.get('body'):
            continue
        psoup = BeautifulSoup(page.get('body', ''), 'html.parser')
        for a in psoup.find_all('a', href=True):
            href = (a.get('href') or '').strip()
            if not href or href.startswith(('#', 'mailto:', 'tel:', 'javascript:')):
                continue
            from urllib.parse import urljoin
            parts = urlparse(urljoin(page['url'], href))
            if parts.scheme not in ('http', 'https') or parts.hostname != root_host or parts.query or parts.username or parts.password:
                continue
            if parts.port not in (None, 80, 443):
                continue
            candidate2 = urlunparse((parts.scheme, parts.netloc, parts.path or '/', '', '', ''))
            if candidate2 not in seen:
                seen.add(candidate2)
                queue.append(candidate2)

    def add(name, severity, status, detail, fix='', page_url=None, confidence='Observed'):
        item = {'name': name, 'severity': severity, 'status': status, 'detail': detail, 'fix': fix,
                'page_url': page_url or root_url, 'confidence': confidence}
        if status == 'REVIEW':
            item['risk_priority'] = {'high': 80, 'medium': 55, 'low': 25}.get(severity, 15)
        else:
            item['risk_priority'] = 0
        checks.append(item)

    h = root['headers']; https = root['scheme'] == 'https'
    add('HTTPS transport', 'high', 'PASS' if https else 'REVIEW',
        'The target was requested over HTTPS and certificate verification succeeded.' if https else 'The submitted URL uses HTTP; browser-to-server traffic is not encrypted.',
        '' if https else 'Enable a valid TLS certificate and redirect HTTP to HTTPS. Verify the canonical HTTPS URL and proxy/application scheme handling.', root_url)
    if root['status'] in (301, 302, 303, 307, 308):
        add('Redirect destination review', 'medium', 'REVIEW',
            'The root response redirects to: ' + (root.get('location') or '(Location header missing)') + '. Redirects were not followed automatically.',
            'Confirm the destination is the intended canonical host and uses HTTPS. Avoid redirecting to user-controlled destinations.', root_url, 'Manual review')
    for key, label, sev, fix in [
      ('strict-transport-security','HSTS','medium','After HTTPS is verified on every covered hostname, set Strict-Transport-Security: max-age=31536000. Add includeSubDomains only when every subdomain supports HTTPS.'),
      ('content-security-policy','Content-Security-Policy','medium',"Start with a tested Content-Security-Policy such as default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'. Test with Report-Only first and allow only required origins."),
      ('x-content-type-options','X-Content-Type-Options','low','Set X-Content-Type-Options: nosniff.'),
      ('referrer-policy','Referrer-Policy','low','Set Referrer-Policy: strict-origin-when-cross-origin.'),
      ('permissions-policy','Permissions-Policy','low','Disable browser features the site does not need, for example camera=(), microphone=(), geolocation=(). Tune this to the application features.')]:
        ok = bool(h.get(key))
        add(label, sev, 'PASS' if ok else 'REVIEW', 'Header observed in the root response.' if ok else 'Header was not observed in the root response; this is a hardening observation, not proof of exploitability.', '' if ok else fix, root_url)
    csp = h.get('content-security-policy', '')
    frame = bool(h.get('x-frame-options')) or 'frame-ancestors' in csp.lower()
    add('Clickjacking protection', 'medium', 'PASS' if frame else 'REVIEW',
        'A frame-protection policy was observed.' if frame else 'Neither X-Frame-Options nor CSP frame-ancestors was observed in the root response.',
        '' if frame else "If the site must not be embedded, set Content-Security-Policy: frame-ancestors 'none'; otherwise specify the legitimate framing origins.", root_url)
    cookies = h.get('set-cookie', ''); flags = []
    if cookies:
        low = cookies.lower()
        if https and 'secure' not in low: flags.append('Secure')
        if 'httponly' not in low: flags.append('HttpOnly')
        if 'samesite=' not in low: flags.append('SameSite')
    add('Cookie security flags', 'medium', 'NOT OBSERVED' if not cookies else ('REVIEW' if flags else 'PASS'),
        'No Set-Cookie header was observed in this response; session cookies may be set after login.' if not cookies else ('Potential missing flags: ' + ', '.join(flags) if flags else 'Common cookie flags were observed in the response.'),
        'For session cookies, use Secure and HttpOnly on HTTPS and choose an appropriate SameSite value. Recheck authenticated responses because cookies may only appear after login.', root_url, 'Limited to cookies returned by this response')
    server = h.get('server', ''); powered = h.get('x-powered-by', '')
    add('Server technology disclosure', 'low', 'REVIEW' if server or powered else 'PASS',
        f'Server: {server or "not set"}; X-Powered-By: {powered or "not set"}.',
        'Remove unnecessary version/product disclosure where practical; this information alone is not a vulnerability.' if server or powered else '', root_url)

    # Check response headers on every additional page too; a header present on the
    # homepage is not assumed to be present on other routes.
    header_specs = [
        ('strict-transport-security', 'HSTS', 'medium', 'Enable HSTS only after HTTPS is verified across the intended hostnames.'),
        ('content-security-policy', 'Content-Security-Policy', 'medium', "Test a restrictive Content-Security-Policy, preferably in Report-Only mode first."),
        ('x-content-type-options', 'X-Content-Type-Options', 'low', 'Set X-Content-Type-Options: nosniff.'),
        ('referrer-policy', 'Referrer-Policy', 'low', 'Set Referrer-Policy: strict-origin-when-cross-origin.'),
        ('permissions-policy', 'Permissions-Policy', 'low', 'Disable browser capabilities the application does not need.'),
    ]
    for page in pages[1:]:
        ph = page.get('headers', {})
        for key, label, sev, fix in header_specs:
            if not ph.get(key):
                add(label + ' (page-specific)', sev, 'REVIEW',
                    'Header was not observed on this page response. This is a hardening observation, not proof of exploitability.',
                    fix, page['url'])
        pcsp = ph.get('content-security-policy', '')
        if not ph.get('x-frame-options') and 'frame-ancestors' not in pcsp.lower():
            add('Clickjacking protection (page-specific)', 'medium', 'REVIEW',
                'No X-Frame-Options or CSP frame-ancestors policy was observed on this page response.',
                "If embedding is not required, set Content-Security-Policy: frame-ancestors 'none'; otherwise allow only trusted origins.", page['url'])
        pserver, ppowered = ph.get('server', ''), ph.get('x-powered-by', '')
        if pserver or ppowered:
            add('Server technology disclosure (page-specific)', 'low', 'REVIEW',
                f'Server: {pserver or "not set"}; X-Powered-By: {ppowered or "not set"}. This alone is not a vulnerability.',
                'Remove unnecessary version/product disclosure where practical.', page['url'])

    forms = []; priority = []
    for page in pages:
        soup = BeautifulSoup(page.get('body', ''), 'html.parser')
        page_url = page['url']
        path = urlparse(page_url).path.lower()
        if any(k in path for k in ('login','signin','auth','account','admin')):
            priority.append({'area': 'Login / account / admin route', 'page_url': page_url, 'reason': 'The URL path suggests an authentication or administrative area; review MFA, rate limits, authorization, and session handling manually.', 'priority': 'High manual review'})
        for f in soup.find_all('form')[:100]:
            method = (f.get('method') or 'GET').upper()
            action = (f.get('action') or '')[:300]
            fields = [{'name': (e.get('name') or '')[:80], 'type': (e.get('type') or e.name or 'text')[:30]} for e in f.find_all(['input','textarea','select','button'])[:50]]
            forms.append({'page_url': page_url, 'method': method, 'action': action, 'fields': fields})
            input_types = [x['type'].lower() for x in fields]
            input_names = ' '.join(x['name'].lower() for x in fields)
            has_password = 'password' in input_types
            if has_password:
                if not https or method == 'GET':
                    why = 'Password form is served over HTTP.' if not https else 'Password form appears to use GET; query values can leak into URLs, history, or logs.'
                    add('Password form transport', 'high', 'REVIEW', why,
                        'Serve the form over HTTPS and submit credentials with POST. Never put passwords in URL query parameters.', page_url, 'Form markup observed; server behavior not tested')
                missing_auto = sum(1 for e in f.find_all('input', attrs={'type': re.compile(r'^password$', re.I)}) if not e.get('autocomplete'))
                if missing_auto:
                    add('Password autocomplete guidance', 'low', 'REVIEW', f'{missing_auto} password input(s) lack autocomplete.',
                        'Use autocomplete="current-password" for login and autocomplete="new-password" for account creation/reset. This is guidance, not proof of a vulnerability.', page_url)
                priority.append({'area': 'Login / password form', 'page_url': page_url, 'reason': 'A password field is present. Manually verify MFA, rate limiting, password reset, session rotation, and account-enumeration protections.', 'priority': 'High manual review'})
            if method == 'POST' and not any(re.search(r'csrf|token', x['name'], re.I) for x in fields):
                add('CSRF token hint', 'low', 'REVIEW', 'POST form has no obvious CSRF/token input in returned HTML. Token handling may be elsewhere; this is not proof of CSRF.',
                    'Confirm that every state-changing request has server-side CSRF protection. Do not rely only on a client-side token field.', page_url, 'HTML-only heuristic')
            if any(k in input_names for k in ('search','query','filter','id','file','upload','redirect','url','path')):
                priority.append({'area': 'Input-handling form', 'page_url': page_url, 'reason': 'A form field name suggests user-controlled input. Review server-side validation, output encoding, authorization, upload type/size limits, and safe redirect allowlists as applicable.', 'priority': 'Review'})
        for e in soup.find_all(['input','textarea','select']):
            typ = (e.get('type') or e.name or '').lower()
            name = (e.get('name') or e.get('id') or '').lower()
            if typ == 'file' or any(k in name for k in ('upload','file')):
                priority.append({'area': 'File upload input', 'page_url': page_url, 'reason': 'An upload control is visible. Manually verify server-side file allowlists, size limits, random storage names, non-executable storage, and authorization.', 'priority': 'High manual review'})
    if not forms:
        add('Page and form inventory', 'info', 'INFO', f'Inspected {len(pages)} same-origin page(s); no HTML forms were found in returned markup. JavaScript-rendered forms may not be visible.', '', root_url)
    else:
        add('Page and form inventory', 'info', 'INFO', f'Inspected {len(pages)} same-origin page(s); found {len(forms)} HTML form(s). No forms were submitted.', '', root_url)
    # Deduplicate identical page/area recommendations.
    unique_priority = []
    seen_priority = set()
    for item in priority:
        key = (item['area'], item['page_url'])
        if key not in seen_priority:
            seen_priority.add(key); unique_priority.append(item)
    counts = {sev: sum(1 for c in checks if c['severity'] == sev and c['status'] == 'REVIEW') for sev in ('high','medium','low')}
    weights = {'high': 30, 'medium': 15, 'low': 5}
    score = min(100, sum(weights.get(c['severity'], 0) for c in checks if c['status'] == 'REVIEW'))
    if score >= 60: level = 'Elevated indicators — prioritize review'
    elif score >= 30: level = 'Several indicators — review recommended'
    elif score > 0: level = 'Some indicators — hardening recommended'
    else: level = 'Few indicators observed in this limited scan'
    return {'target': root_url, 'host': root['host'], 'checked_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
            'http_status': root['status'], 'content_type': root['content_type'], 'response_time': root['seconds'],
            'pages_scanned': len(pages), 'pages': [{'url': x['url'], 'http_status': x['status'], 'response_time': x['seconds']} for x in pages],
            'checks': checks, 'forms': forms, 'priority_areas': unique_priority, 'summary': counts,
            'exposure_score': score, 'exposure_level': level,
            'exposure_score_note': '0–100 heuristic priority indicator based on observed configuration findings. It is NOT the probability or percentage chance of being hacked. The scan is limited and does not test exploitability.',
            'limitations': f'Bounded passive same-origin crawl (up to {MAX_PAGES} pages or {SCAN_BUDGET_SECONDS} seconds, whichever comes first). Actual pages checked: {len(pages)}. It does not submit forms, authenticate, exploit vulnerabilities, test access-control bypass, or inspect server-side code. Findings and priority areas require authorized manual validation.'}


def collect_domain_intelligence(domain):
    """Fetch passive public DNS and certificate-transparency metadata from fixed providers."""
    out = {'dns_records': [], 'certificate_names': [], 'intel_sources_status': {}}
    tasks = []
    # Fixed DoH endpoints only; never accept a user-supplied URL here.
    for provider, endpoint in [('Google DNS', 'https://dns.google/resolve'), ('Cloudflare DNS', 'https://cloudflare-dns.com/dns-query')]:
        for rrtype in ('A', 'AAAA', 'MX', 'NS', 'TXT', 'CAA'):
            tasks.append((provider, rrtype, endpoint))
    def lookup_dns(task):
        provider, rrtype, endpoint = task
        headers = {'User-Agent': UA}
        if provider == 'Cloudflare DNS': headers['Accept'] = 'application/dns-json'
        response = requests.get(endpoint, params={'name': domain, 'type': rrtype}, headers=headers, timeout=3)
        response.raise_for_status()
        payload = response.json()
        return provider, rrtype, [str(a.get('data', '')).strip()[:500] for a in (payload.get('Answer') or [])[:30] if a.get('data')]
    found = {'Google DNS': 0, 'Cloudflare DNS': 0}
    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = [pool.submit(lookup_dns, task) for task in tasks]
        for future in as_completed(futures):
            try:
                provider, rrtype, values = future.result()
                for value in values:
                    item = {'type': rrtype, 'value': value}
                    if item not in out['dns_records']: out['dns_records'].append(item)
                    found[provider] += 1
            except Exception:
                continue
    for provider, count in found.items():
        out['intel_sources_status'][provider] = 'records found' if count else 'no records / provider unavailable'
    try:
        # crt.sh returns public certificate names; cap the response size and number of names.
        response = requests.get('https://crt.sh/', params={'q': '%25.' + domain, 'output': 'json'},
                                headers={'User-Agent': UA, 'Accept': 'application/json'}, timeout=4, stream=True)
        if response.ok:
            chunks = []; total = 0
            for chunk in response.iter_content(8192):
                total += len(chunk); chunks.append(chunk)
                if total > 1_500_000: break
            if total <= 1_500_000:
                rows = json.loads(b''.join(chunks).decode('utf-8', 'replace'))
                names = set()
                for row in rows if isinstance(rows, list) else []:
                    for name in str(row.get('name_value', '')).splitlines():
                        name = name.strip().lower().lstrip('*.')
                        if name and (name == domain or name.endswith('.' + domain)):
                            names.add(name)
                        if len(names) >= 250: break
                    if len(names) >= 250: break
                out['certificate_names'] = sorted(names)
        out['intel_sources_status']['Certificate Transparency'] = f'{len(out["certificate_names"])} public name(s) found'
    except (requests.RequestException, ValueError, TypeError):
        out['intel_sources_status']['Certificate Transparency'] = 'provider unavailable'
    return out


def domain_lookup(raw):
    domain=(raw or '').strip().lower().rstrip('.')
    if domain.startswith(('http://','https://')):
        domain=urlparse(domain).hostname or ''
    domain=domain.strip().rstrip('.')
    if not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',domain):
        raise ValueError('Enter a valid domain name, e.g. example.com. Do not include a path.')
    try:
        r=requests.get('https://rdap.org/domain/'+domain,
                       headers={'Accept':'application/rdap+json, application/json','User-Agent':UA},
                       timeout=14,allow_redirects=True)
        if r.status_code==404:
            return {'domain':domain,'status':'No public registration record found','handle':None,
                    'events':[],'nameservers':[],'entities':[],'domain_status':[],
                    'secure_dns':None,'registrar':None,'public_ids':[], 'links':[], 'notices':[],
                    'rdap_conformance':[], 'raw_public_fields':{},
                    **collect_domain_intelligence(domain),
                    'note':'প্রকাশ্য রেজিস্ট্রেশন রেকর্ড পাওয়া যায়নি। DNS ও certificate-transparency তথ্য পাওয়া গেলে তা আলাদাভাবে দেখানো হয়েছে। এর অর্থ এই নয় যে ডোমেইনের মালিক নেই।'}
        r.raise_for_status()
        data=r.json()
        if not isinstance(data,dict): raise ValueError('Invalid RDAP response')
    except (requests.RequestException,ValueError):
        raise ValueError('Public domain registration lookup failed or returned an invalid response. Try again later.')

    events=[]
    for ev in data.get('events',[]) or []:
        if isinstance(ev,dict): events.append({'action':ev.get('eventAction',''), 'date':ev.get('eventDate',''), 'actor':ev.get('eventActor','')})
    nameservers=[]
    for x in data.get('nameservers',[]) or []:
        if isinstance(x,dict):
            entry={'name':x.get('ldhName') or x.get('unicodeName') or '', 'unicode_name':x.get('unicodeName') or '', 'status':x.get('status') or [], 'ip_addresses':x.get('ipAddresses') or {}}
            if entry['name'] or entry['ip_addresses']: nameservers.append(entry)
    statuses=data.get('status',[]) or []
    secure_dns=data.get('secureDNS')
    entities=[]; registrar=None
    def vcard_props(ent):
        v=ent.get('vcardArray',[])
        return v[1] if isinstance(v,list) and len(v)>1 and isinstance(v[1],list) else []
    def flatten_entity(ent, parent_roles=None):
        nonlocal registrar
        if not isinstance(ent,dict): return
        roles=ent.get('roles',[]) or parent_roles or []
        props=vcard_props(ent); card={}
        for prop in props:
            if len(prop)<4 or not isinstance(prop[0],str): continue
            key=prop[0]; val=prop[3]
            if key=='adr':
                if isinstance(val,dict):
                    country=val.get('country') or val.get('country-name')
                    if country: card['country']=str(country)[:120]
                    val=', '.join(str(x) for x in val.values() if x)
                elif isinstance(val,list):
                    if val and val[-1]: card['country']=str(val[-1])[:120]
                    val=', '.join(str(x) for x in val if x)
            elif isinstance(val,list): val=', '.join(str(x) for x in val if x)
            elif isinstance(val,dict): val=json.dumps(val,ensure_ascii=False)
            if isinstance(val,(str,int,float)) and str(val).strip():
                card[key]=str(val)[:500]
        item={'roles':roles,'public_contact':card,'handle':ent.get('handle'),'public_ids':ent.get('publicIds') or [],
              'status':ent.get('status') or [], 'remarks':ent.get('remarks') or [],
              'redacted':not bool(card)}
        if card or roles or item['handle'] or item['public_ids'] or item['status']:
            entities.append(item)
        if 'registrar' in roles and card:
            registrar=card.get('org') or card.get('fn') or registrar
        for child in ent.get('entities',[]) or []: flatten_entity(child, roles)
    for ent in data.get('entities',[]) or []: flatten_entity(ent)
    public_ids=[]
    for item in data.get('publicIds',[]) or []:
        if isinstance(item,dict): public_ids.append({'type':item.get('type',''), 'identifier':item.get('identifier','')})
    links=[]
    for item in data.get('links',[]) or []:
        if isinstance(item,dict):
            # Do not expose executable HTML; retain public RDAP link metadata for reference.
            links.append({'rel':item.get('rel',''), 'type':item.get('type',''), 'href':item.get('href',''), 'value':item.get('value','')})
    notices=[]
    for item in data.get('notices',[]) or data.get('remarks',[]) or []:
        if isinstance(item,dict):
            notices.append({'title':item.get('title',''), 'type':item.get('type',''),
                            'description':item.get('description',[]) or [], 'links':item.get('links',[]) or []})
    # Retain all additional top-level public fields, excluding fields already normalized above.
    known={'objectClassName','handle','ldhName','unicodeName','nameservers','events','status','secureDNS','entities','publicIds','links','notices','remarks','rdapConformance','port43','lang','arin_originas0_originautnums'}
    raw_fields={k:v for k,v in data.items() if k not in known}
    intelligence = collect_domain_intelligence(domain)
    return {'domain':data.get('ldhName',domain),'unicode_name':data.get('unicodeName'),
            'object_class_name':data.get('objectClassName'),'status':'Public registration record found',
            'handle':data.get('handle'),'registrar':registrar,'events':events,'nameservers':nameservers,
            'entities':entities,'domain_status':statuses,'secure_dns':secure_dns,
            'public_ids':public_ids,'links':[],'notices':[],
            'rdap_conformance':[],'port43':None,
            'lang':data.get('lang'),'raw_public_fields':{},
            'dns_records':intelligence.get('dns_records',[]),'certificate_names':intelligence.get('certificate_names',[]),
            'intel_sources_status':intelligence.get('intel_sources_status',{}),
            'note':'শুধু প্রকাশ্য রেজিস্ট্রেশন রেকর্ডে থাকা তথ্য দেখানো হয়েছে। রেজিস্ট্রি অনুযায়ী তথ্য ভিন্ন হতে পারে; কিছু যোগাযোগের তথ্য গোপন বা অপ্রকাশিত থাকতে পারে। কোনো ব্যক্তিগত তথ্য অনুমান বা বাইপাস করা হয়নি।'}

# Conservative static source audit: flags suspicious patterns for human review; does not execute uploaded files.
PATTERNS=[
 ('Possible SQL injection','high',re.compile(r'(execute|query)\s*\(\s*[\'"].*(SELECT|INSERT|UPDATE|DELETE).*(\$\w+|\+\s*\w+|\.\s*\$)',re.I),'Use parameterized queries/prepared statements; verify data flow manually.'),
 ('Dynamic code execution','high',re.compile(r'\b(eval|exec|system|shell_exec|passthru|popen)\s*\(',re.I),'Avoid dynamic execution of untrusted input; use safe APIs and allowlists.'),
 ('Potential hardcoded secret','high',re.compile(r'(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*[\'"`][^\'"`\s]{8,}[\'"`]'),'Move secrets to environment variables and rotate any exposed credentials.'),
 ('Debug mode enabled','medium',re.compile(r'(?i)(debug\s*=\s*true|app\.run\([^\n]*debug\s*=\s*True|display_errors\s*=\s*On)'),'Disable debug output in production.'),
 ('TLS verification disabled','high',re.compile(r'(?i)(verify\s*=\s*False|CURLOPT_SSL_VERIFYPEER\s*,\s*false|rejectUnauthorized\s*:\s*false)'),'Enable certificate and hostname verification.'),
 ('Unsafe HTML insertion','medium',re.compile(r'(?i)innerHTML\s*=|document\.write\s*\('),'If user-controlled data reaches this sink, escape/sanitize it or use textContent.'),
 ('Possible SQL query concatenation','high',re.compile(r'(?i)(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)[^\n;]{0,220}(\+\s*[a-z_$]|\.\s*\$|f[\"\']|format\s*\()'),'Prefer parameterized queries/prepared statements. Review the complete query and input data flow manually.'),
 ('Weak password hashing indicator','high',re.compile(r'(?i)(md5|sha1)\s*\(\s*[^)]*(password|passwd|secret)|create_hash\s*\(\s*[\"\'](md5|sha1)[\"\']'),'Use a password-hashing function designed for passwords, such as Argon2id, scrypt, or bcrypt.'),
 ('Possible weak password policy','medium',re.compile(r'(?i)(min_length|minlength|minimum_length)\s*[:=]\s*[1-7]\b'),'Review password length policy; prefer long passphrases and block known-compromised passwords.'),
 ('Possible path traversal sink','high',re.compile(r'(?i)(open|readFile|readFileSync|send_file|File\.open)\s*\([^\n)]*(request\.|req\.|params?\[|query\[|input\[)'),'Resolve user-supplied paths against a fixed base directory and enforce an allowlist; never trust raw paths.'),
 ('Possible disabled authentication / permissive access','high',re.compile(r'(?i)(auth(?:entication)?_required\s*=\s*False|login_required\s*=\s*False|verify\s*=\s*False|allow_unauthenticated\s*=\s*True)'),'Confirm the setting is intentional and enforce authentication/authorization server-side.'),
 ('Session cookie security setting','medium',re.compile(r'(?i)(SESSION_COOKIE_SECURE|cookie_secure)\s*[:=]\s*False'),'Enable secure session cookies in production over HTTPS, and review HttpOnly and SameSite settings.'),
 ('Potential password guessing exposure','medium',re.compile(r'(?i)(rate.?limit|throttle|lockout|login_attempts|failed_login).{0,80}(disable|false|0|none)|(?:disable|false|0|none).{0,80}(rate.?limit|throttle|lockout|login_attempts|failed_login)'),'Review server-side rate limiting, progressive delays, breached-password controls, and alerting. This pattern alone does not prove missing protections.'),
 ('Potential weak session/token generation','high',re.compile(r'(?i)(session|token|reset_token|csrf_token).{0,80}(random\.random|Math\.random|rand\s*\()'),'Use a cryptographically secure random generator for session IDs and security tokens.'),
 ('Potential authentication check omission','medium',re.compile(r'(?i)(@app\.(route|get|post|put|delete)|router\.(get|post|put|delete)|app\.(get|post|put|delete))[^\n]{0,180}(admin|private|account|profile|dashboard|settings)'),'Manually verify that every sensitive route performs server-side authentication and authorization; route names alone are not proof of a flaw.'),
]
ALLOWED_EXT={'.py','.php','.js','.ts','.jsx','.tsx','.html','.htm','.sql','.rb','.go','.java','.cs','.json','.yml','.yaml','.env.example','.config','.xml'}

def audit_zip(file):
    if not file or not file.filename or not file.filename.lower().endswith('.zip'): raise ValueError('Upload a ZIP containing source code.')
    raw=file.read()
    if len(raw)>8*1024*1024: raise ValueError('ZIP is too large (maximum 8 MB).')
    results=[]; scanned=0
    try: z=zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile: raise ValueError('The uploaded file is not a valid ZIP.')
    with z:
        infos=z.infolist()
        if len(infos)>500: raise ValueError('ZIP contains too many files (maximum 500).')
        total=0
        for info in infos:
            if info.is_dir(): continue
            name=info.filename.replace('\\','/')
            if name.startswith('/') or '..' in name.split('/') or info.file_size>1_000_000: continue
            total+=info.file_size
            if total>20_000_000: break
            ext=os.path.splitext(name.lower())[1]
            if ext not in ALLOWED_EXT or any(x in name.lower() for x in ('node_modules/','.git/','vendor/','dist/','build/')): continue
            try: content=z.read(info).decode('utf-8','replace')
            except Exception: continue
            scanned+=1
            for no,line in enumerate(content.splitlines(),1):
                if len(results)>=250: break
                for title,sev,pattern,fix in PATTERNS:
                    if pattern.search(line):
                        results.append({'file':name,'line':no,'title':title,'severity':sev,'risk_priority':{'high':80,'medium':55,'low':25}.get(sev,15),'evidence':line.strip()[:260],'fix':fix,'confidence':'Needs manual review; pattern matches can be false positives'})
                        break
    return {'files_scanned':scanned,'findings':results,'note':'Heuristic static analysis only. Pattern matches can be false positives and do not prove exploitability. Uploaded files were not executed.'}

@app.get('/')
def index():
    session.setdefault('csrf',secrets.token_urlsafe(24))
    return render_template('index.html',csrf=session['csrf'],telegram_url='https://t.me/NightHex_X',channel_url='https://t.me/+qFllt01YeXk2YzQ1')

@app.post('/api/scan')
def api_scan():
    if not secrets.compare_digest(session.get('csrf',''),str((request.get_json(silent=True) or {}).get('csrf',''))): return jsonify(error='Session expired. Refresh the page and try again.'),403
    client=(request.headers.get('X-Forwarded-For') or request.remote_addr or 'unknown').split(',')[0].strip()
    now=time.time()
    if now-_recent[client]<RATE_LIMIT_SECONDS: return jsonify(error='Please wait 12 seconds between scans.'),429
    _recent[client]=now
    try: return jsonify(result=scan_site((request.get_json(silent=True) or {}).get('url','')))
    except ValueError as e: return jsonify(error=str(e)),400
    except requests.RequestException: return jsonify(error='The target did not respond or TLS/network validation failed.'),400
    except Exception: app.logger.exception('Unexpected scan error'); return jsonify(error='Unexpected scan error. Check service logs.'),500

@app.post('/api/domain')
def api_domain():
    payload=request.get_json(silent=True) or {}
    if not secrets.compare_digest(session.get('csrf',''),str(payload.get('csrf',''))): return jsonify(error='Session expired. Refresh the page and try again.'),403
    try: return jsonify(result=domain_lookup(payload.get('domain','')))
    except ValueError as e: return jsonify(error=str(e)),400
    except Exception: app.logger.exception('RDAP lookup failed'); return jsonify(error='Public domain lookup failed. Try again later.'),502

@app.post('/api/audit')
def api_audit():
    if not secrets.compare_digest(session.get('csrf',''),str(request.form.get('csrf',''))): return jsonify(error='Session expired. Refresh the page and try again.'),403
    if not request.files.get('source_zip'): return jsonify(error='Choose a ZIP file first.'),400
    try: return jsonify(result=audit_zip(request.files['source_zip']))
    except ValueError as e: return jsonify(error=str(e)),400

@app.post('/api/export/<fmt>')
def api_export(fmt):
    if fmt not in ('json', 'txt', 'pdf'):
        return jsonify(error='Choose JSON, TXT, or PDF.'), 400
    payload=request.get_json(silent=True) or {}
    if not secrets.compare_digest(session.get('csrf',''),str(payload.get('csrf',''))):
        return jsonify(error='Session expired. Refresh the page and try again.'),403
    report=payload.get('report')
    if not isinstance(report,dict): return jsonify(error='No report data was provided.'),400
    # Bound the export payload and avoid rendering arbitrary huge content.
    try: raw=json.dumps(report, ensure_ascii=False, separators=(',',':')).encode('utf-8')
    except (TypeError,ValueError): return jsonify(error='Report data is invalid.'),400
    if len(raw)>1_500_000: return jsonify(error='Report is too large to export.'),413
    stamp=datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
    # Make every export target-specific without including paths or unsafe characters.
    target = str(report.get('target') or report.get('domain') or report.get('host') or 'source-audit')
    try:
        host = urlparse(target if '://' in target else 'https://' + target).hostname or target
    except Exception:
        host = target
    slug = re.sub(r'[^a-zA-Z0-9.-]+', '-', host.lower()).strip('.-')[:100] or 'site-report'
    base_name = f'night-hex-{slug}-{stamp}'
    if fmt=='json':
        return Response(json.dumps(report,ensure_ascii=False,indent=2),mimetype='application/json',headers={'Content-Disposition':f'attachment; filename="{base_name}.json"'})
    if fmt=='txt':
        lines=['NIGHT HEX SECURITY AUDIT REPORT','='*34]
        def walk(value, prefix=''):
            if isinstance(value,dict):
                for k,v in value.items():
                    if isinstance(v,(dict,list)): lines.append(f'\n{prefix}{k}:'); walk(v,prefix+'  ')
                    else: lines.append(f'{prefix}{k}: {v}')
            elif isinstance(value,list):
                for i,item in enumerate(value,1): lines.append(f'{prefix}[{i}]'); walk(item,prefix+'  ')
            else: lines.append(f'{prefix}{value}')
        walk(report)
        return Response('\n'.join(lines),mimetype='text/plain; charset=utf-8',headers={'Content-Disposition':f'attachment; filename="{base_name}.txt"'})
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Preformatted
        buff=io.BytesIO(); doc=SimpleDocTemplate(buff,pagesize=A4,rightMargin=16*mm,leftMargin=16*mm,topMargin=16*mm,bottomMargin=16*mm)
        styles=getSampleStyleSheet(); styles.add(ParagraphStyle(name='SmallMono',parent=styles['Code'],fontSize=7,leading=9,wordWrap='CJK'))
        story=[Paragraph('NIGHT HEX Security Audit Report',styles['Title']),Spacer(1,5*mm),Paragraph('Generated '+datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),styles['Normal']),Spacer(1,4*mm)]
        # Render a compact readable report; content is escaped before Paragraph parsing.
        def pdf_walk(value, depth=0):
            if isinstance(value,dict):
                for k,v in value.items():
                    label=html.escape(str(k))
                    if isinstance(v,(dict,list)):
                        story.append(Paragraph(('<b>'+label+'</b>') if depth==0 else label,styles['Heading3'] if depth==0 else styles['Heading4']))
                        pdf_walk(v,depth+1)
                    else:
                        txt=html.escape(str(v))[:3000]
                        story.append(Paragraph('<b>'+label+':</b> '+txt,styles['BodyText']))
                        story.append(Spacer(1,1.5*mm))
            elif isinstance(value,list):
                for i,item in enumerate(value,1):
                    story.append(Paragraph('Item '+str(i),styles['Heading4']))
                    pdf_walk(item,depth+1)
            else: story.append(Paragraph(html.escape(str(value))[:3000],styles['BodyText']))
        pdf_walk(report)
        doc.build(story); buff.seek(0)
        return send_file(buff,mimetype='application/pdf',as_attachment=True,download_name=f'night-hex-report-{stamp}.pdf')
    except ImportError:
        return jsonify(error='PDF export dependency is missing. Redeploy after installing requirements.txt.'),500

@app.get('/healthz')
def health(): return jsonify(status='ok',service='night-hex-advanced-v15')

if __name__=='__main__': app.run(host='0.0.0.0',port=int(os.environ.get('PORT','5000')),debug=False)
