"""Email body templates used by the auth router's welcome flow.

Lives in services/ because the copy is product/business logic, not an HTTP
adapter concern. Returns (subject, body_text, body_html). All untrusted
strings (name, domain) are HTML-escaped before interpolation into the HTML
body. The plain-text body interpolates the raw values (no escaping required).
"""
from __future__ import annotations

import html as _html


def render_welcome_email(*, name: str, domain: str) -> tuple[str, str, str]:
    safe_name_html = _html.escape(name)
    safe_domain_html = _html.escape(domain)

    subject = "Welcome to Sender Safety — let's get you set up"
    body_text = f"""Hi {name},

Welcome to Sender Safety! You're one step away from protecting every email that leaves {domain}.

Here's what to do next:

1. Verify your domain
   Log in to your dashboard and follow the domain verification steps. You'll add a simple DNS record — takes about 2 minutes.

2. Configure your SMTP gateway
   In Google Workspace Admin, go to Apps → Gmail → Routing → Outbound Gateway and point it to:
   smtp.sendersafety.com (port 587)

3. Add your first keyword rule
   Head to the Rules section and add any words or phrases you want to flag or block in outgoing emails.

4. Test the connection
   Use the "Test connection" button in your dashboard to confirm emails are flowing through the gateway.

That's it. Once those four steps are done, Sender Safety is live for your entire organization.

If you run into anything, just reply to this email.

— The Sender Safety team
https://app.sendersafety.com
"""

    body_html = f"""<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto;color:#222;">
<h2 style="color:#1a1a1a;">Welcome to Sender Safety 👋</h2>
<p>Hi {safe_name_html},</p>
<p>You're one step away from protecting every email that leaves <strong>{safe_domain_html}</strong>.</p>
<h3>Here's what to do next:</h3>
<ol>
  <li style="margin-bottom:12px;">
    <strong>Verify your domain</strong><br>
    Log in to your dashboard and follow the domain verification steps. You'll add a simple DNS record — takes about 2 minutes.
  </li>
  <li style="margin-bottom:12px;">
    <strong>Configure your SMTP gateway</strong><br>
    In Google Workspace Admin, go to <em>Apps → Gmail → Routing → Outbound Gateway</em> and point it to:<br>
    <code style="background:#f4f4f4;padding:2px 6px;border-radius:3px;">smtp.sendersafety.com (port 587)</code>
  </li>
  <li style="margin-bottom:12px;">
    <strong>Add your first keyword rule</strong><br>
    Head to the Rules section and add any words or phrases you want to flag in outgoing emails.
  </li>
  <li style="margin-bottom:12px;">
    <strong>Test the connection</strong><br>
    Use the "Test connection" button in your dashboard to confirm emails are flowing through the gateway.
  </li>
</ol>
<p>Once those four steps are done, Sender Safety is live for your entire organization.</p>
<p>If you run into anything, just reply to this email.</p>
<p style="margin-top:32px;color:#888;font-size:13px;">— The Sender Safety team<br>
<a href="https://app.sendersafety.com">app.sendersafety.com</a></p>
</body></html>"""
    return subject, body_text, body_html
