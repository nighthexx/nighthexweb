# NIGHT HEX Advanced — Responsible Web Security Audit

A GitHub + Render deployable passive web security assessment dashboard.

## Included

- HTTPS/TLS request validation
- Security-header review (HSTS, CSP, clickjacking, content-type, referrer, permissions policy)
- Cookie-flag observation
- Bounded same-host crawl (maximum 10 pages)
- HTML form/input inventory (forms are never submitted)
- Redirect observation (redirects are not followed)
- JSON export, copyable summary, print / save as PDF
- Public/private IP validation, standard-port restriction, access-key gate, cooldown
- Embedded SVG logo and NIGHT HEX / Telegram links

## Deploy to Render

1. Upload the contents of this folder to a GitHub repository named `nighthex`.
2. In Render, choose **New + → Blueprint** and select that repository. Render reads `render.yaml`.
3. In the Render service's **Environment** settings, set `SCANNER_ACCESS_KEY` to a long random secret. Do not commit this value to GitHub.
4. Deploy. Open the generated `https://nighthex.onrender.com` address.
5. Enter the same access key in the scanner UI. Keep it private.

If you create a Web Service manually, use:
- Runtime: Python
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app --workers 1 --threads 4 --timeout 45`
- Environment variables: `FLASK_SECRET_KEY` (random secret), `SCANNER_ACCESS_KEY` (private access key)

## Scope and safety

This tool performs bounded, non-destructive HTTP checks. It does **not** exploit vulnerabilities, submit forms, brute-force passwords, try to bypass authentication, access private resources, or take control of websites. A missing header is a hardening observation, not proof of an exploitable vulnerability. Use only on websites you own or are explicitly authorized to assess.

For a responsible disclosure report, include the exact affected URL, date/time, observed response evidence, impact that you can validate safely, and a suggested fix. Do not include passwords, session cookies, personal data, or exploit payloads in reports.

## Security notes

- Keep `SCANNER_ACCESS_KEY` private; never put it in frontend JavaScript or commit it to GitHub.
- Render free services may sleep when idle. In-memory cooldowns reset on restart; they are not a substitute for platform-level protection.
- If you intend to offer public accounts or many users, add persistent authentication, quotas, audit logs, and a stronger network egress policy before opening it publicly.
