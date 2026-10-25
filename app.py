import os, re, io, zipfile, socket, ipaddress, time, secrets, json, html
from collections import defaultdict
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
    root=fetch(raw); checks=[]; h=root['headers']; https=root['scheme']=='https'
    def add(name,severity,status,detail,fix=''):
        checks.append({'name':name,'severity':severity,'status':status,'detail':detail,'fix':fix})
    add('HTTPS','high','PASS' if https else 'REVIEW','HTTPS used with certificate verification.' if https else 'Submitted URL uses HTTP; traffic is not encrypted.','Enable HTTPS and redirect HTTP to HTTPS.' if not https else '')
    for key,label,sev,fix in [
      ('strict-transport-security','HSTS','medium','Enable HSTS only after HTTPS works across the site and required subdomains.'),
      ('content-security-policy','Content-Security-Policy','medium','Create a CSP based on the site’s required scripts, styles, images, and other resources.'),
      ('x-content-type-options','X-Content-Type-Options','low','Set X-Content-Type-Options: nosniff.'),
      ('referrer-policy','Referrer-Policy','low','Set a suitable Referrer-Policy.'),
      ('permissions-policy','Permissions-Policy','low','Restrict browser capabilities the site does not need.')]:
        ok=bool(h.get(key)); add(label,sev,'PASS' if ok else 'REVIEW','Header observed.' if ok else 'Header not observed in the root response; this is a hardening observation, not proof of exploitability.', '' if ok else fix)
    csp=h.get('content-security-policy',''); frame=bool(h.get('x-frame-options')) or 'frame-ancestors' in csp.lower()
    add('Clickjacking protection','medium','PASS' if frame else 'REVIEW','Frame protection header observed.' if frame else 'Neither X-Frame-Options nor CSP frame-ancestors was observed.','Set X-Frame-Options or a suitable CSP frame-ancestors directive.' if not frame else '')
    cookies=h.get('set-cookie',''); flags=[]
    if cookies:
        low=cookies.lower()
        if https and 'secure' not in low: flags.append('Secure')
        if 'httponly' not in low: flags.append('HttpOnly')
        if 'samesite=' not in low: flags.append('SameSite')
    add('Cookie security flags','medium','NOT OBSERVED' if not cookies else ('REVIEW' if flags else 'PASS'),'No Set-Cookie header observed.' if not cookies else ('Potential missing flags: '+', '.join(flags) if flags else 'Common flags observed.'),'Review each cookie individually; use Secure on HTTPS, HttpOnly where appropriate, and suitable SameSite.' if flags else '')
    server=h.get('server',''); powered=h.get('x-powered-by','')
    add('Server disclosure','low','REVIEW' if server or powered else 'PASS',f'Server: {server or "not set"}; X-Powered-By: {powered or "not set"}.','Minimize unnecessary product/version disclosure.' if server or powered else '')
    soup=BeautifulSoup(root['body'],'html.parser')
    forms=[]
    for f in soup.find_all('form')[:100]:
        forms.append({'method':(f.get('method') or 'GET').upper(),'action':(f.get('action') or '')[:300],'fields':[{'name':(e.get('name') or '')[:80],'type':(e.get('type') or e.name or 'text')[:30]} for e in f.find_all(['input','textarea','select','button'])[:50]]})
    add('Page and form inventory','info','INFO',f'Inspected 1 page; found {len(forms)} form(s). No forms submitted and redirects were not followed.')
    password_inputs=[e for f in soup.find_all('form') for e in f.find_all('input',attrs={'type':re.compile(r'^password$',re.I)})]
    if password_inputs:
        get_password_forms=[f for f in soup.find_all('form') if (f.get('method') or 'GET').upper()=='GET' and f.find('input',attrs={'type':re.compile(r'^password$',re.I)})]
        add('Password form transport','high','REVIEW' if not https or get_password_forms else 'PASS',
            'Password input is present. Review HTTPS and form method.' if not get_password_forms and https else ('A password form appears to use GET; credentials may enter URLs, logs, or browser history.' if get_password_forms else 'Password form is served over HTTP, not HTTPS.'),
            'Use HTTPS and POST for credential submission; never place passwords in URL query strings.' if not https or get_password_forms else '')
        missing_auto=sum(1 for e in password_inputs if not e.get('autocomplete'))
        add('Password autocomplete guidance','low','REVIEW' if missing_auto else 'PASS',
            f'{missing_auto} password input(s) lack an autocomplete attribute.' if missing_auto else 'Password input autocomplete attributes observed.',
            'Set an intentional autocomplete value such as current-password or new-password.' if missing_auto else '')
    # This is only a page-level hint; JavaScript-rendered and server-side protections cannot be confirmed here.
    csrf_hints=sum(1 for f in soup.find_all('form') if (f.get('method') or 'GET').upper()=='POST' and not f.find('input',attrs={'name':re.compile(r'csrf|token',re.I)}))
    if csrf_hints:
        add('CSRF token hint','low','REVIEW',f'{csrf_hints} POST form(s) have no obvious CSRF/token input in the returned HTML. Tokens may be provided by another mechanism; this is not proof of CSRF.',
            'Verify server-side CSRF protection for state-changing requests; use framework-supported CSRF middleware.')
    counts={s:sum(1 for c in checks if c['severity']==s and c['status']=='REVIEW') for s in ('high','medium','low')}
    return {'target':root['url'],'host':root['host'],'checked_at':datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),'http_status':root['status'],'content_type':root['content_type'],'response_time':root['seconds'],'checks':checks,'forms':forms,'summary':counts,'limitations':'Bounded passive scan only. No exploitation, credential testing, form submission, or access-control bypass. Findings are observations, not proof of a vulnerability.'}


def domain_lookup(raw):
    domain=(raw or '').strip().lower().rstrip('.')
    if domain.startswith('http://') or domain.startswith('https://'): domain=urlparse(domain).hostname or ''
    if not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',domain): raise ValueError('Enter a valid domain name, e.g. example.com.')
    try:
        r=requests.get('https://rdap.org/domain/'+domain,headers={'Accept':'application/rdap+json','User-Agent':UA},timeout=10,allow_redirects=True)
        if r.status_code==404: return {'domain':domain,'status':'No public RDAP record found','events':[],'nameservers':[],'entities':[],'note':'No public record returned. This does not establish who owns the domain.'}
        r.raise_for_status(); data=r.json()
    except (requests.RequestException,ValueError) as e:
        raise ValueError('Public RDAP lookup failed or returned an invalid response. Try again later.')
    events=[]
    for ev in data.get('events',[]):
        action=ev.get('eventAction',''); date=ev.get('eventDate','')
        if action and date: events.append({'action':action,'date':date})
    nameservers=[x.get('ldhName') for x in data.get('nameservers',[]) if x.get('ldhName')]
    entities=[]
    for ent in data.get('entities',[]):
        roles=ent.get('roles',[]); v=ent.get('vcardArray',[])
        props=v[1] if isinstance(v,list) and len(v)>1 and isinstance(v[1],list) else []
        card={}
        for prop in props:
            if len(prop)>=4 and prop[0] in ('fn','org','email','tel','adr'):
                val=prop[3]
                if prop[0]=='adr':
                    # Publicly returned postal addresses only; never attempt to infer or bypass redaction.
                    if isinstance(val,dict): val=', '.join(str(x) for x in val.values() if x)
                    elif isinstance(val,list): val=', '.join(str(x) for x in val if x)
                if isinstance(val,(str,int,float)) and str(val).strip(): card[prop[0]]=str(val)[:250]
        if card or roles: entities.append({'roles':roles,'public_contact':card,'redacted':not bool(card)})
    return {'domain':data.get('ldhName',domain),'status':'Public RDAP record found','handle':data.get('handle'),'port43':data.get('port43'),'events':events,'nameservers':nameservers,'entities':entities,'note':'Only information returned by the public RDAP service is shown. Registrant data may be privacy-redacted or unavailable; no privacy bypass is attempted.'}

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
                        results.append({'file':name,'line':no,'title':title,'severity':sev,'evidence':line.strip()[:260],'fix':fix,'confidence':'Needs manual review'})
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
    if fmt=='json':
        return Response(json.dumps(report,ensure_ascii=False,indent=2),mimetype='application/json',headers={'Content-Disposition':f'attachment; filename="night-hex-report-{stamp}.json"'})
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
        return Response('\n'.join(lines),mimetype='text/plain; charset=utf-8',headers={'Content-Disposition':f'attachment; filename="night-hex-report-{stamp}.txt"'})
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
def health(): return jsonify(status='ok',service='night-hex-advanced-v6')

if __name__=='__main__': app.run(host='0.0.0.0',port=int(os.environ.get('PORT','5000')),debug=False)
