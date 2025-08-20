import json
import os
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta

SOURCE = "angular"
REPORT = "/app/reports/angular-full.json"
FILTERED_REPORT = "/app/reports/angular-filtered.json"

def load_scan_result():
    if not os.path.exists(REPORT):
        print(f"Fichier introuvable dans {REPORT}")
        return None
    with open(REPORT, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            print("Erreur lors du parsing JSON")
            return None

def save_json(data, path):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def filter_vulnerabilities(data):
    vulns = data.get("vulnerabilities", [])
    filtered = [v for v in vulns if v.get("severity") in ["medium", "high", "critical"]]
    for v in filtered:
        v["source"] = SOURCE
    return filtered

def generate_html(filtered):
    date = (datetime.now() + timedelta(hours=2)).strftime("%Y-%m-%d %H:%M")
    html = f"""<html>
<head><meta charset="utf-8"><title>Rapport Snyk Angular</title></head>
<body>
<h2>Rapport de vulnérabilités Snyk – {SOURCE} – {date}</h2>
<table border="1" cellpadding="5" cellspacing="0">
<tr>
<th>Paquet</th><th>Version</th><th>Sévérité</th><th>Titre</th><th>Identifiants</th><th>Recommandation</th>
</tr>"""

    for v in filtered:
        ids = ", ".join(v.get("identifiers", {}).get("CVE", []) or [v.get("id", "")])
        fixes = v.get("fixedIn") or []
        recommendation = f"Mettre à jour vers {fixes[0]}" if fixes else "Aucune correction disponible"

        html += f"""<tr>
<td>{v.get('packageName')}</td>
<td>{v.get('version')}</td>
<td>{v.get('severity')}</td>
<td>{v.get('title')}</td>
<td>{ids}</td>
<td>{recommendation}</td>
</tr>"""

    html += "</table></body></html>"
    return html

def send_email(subject, html_content):
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT", 465))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    sender_email = os.getenv("EMAIL_FROM", smtp_user)
    receiver_email = os.getenv("EMAIL_TO")

    if not all([smtp_server, smtp_user, smtp_password, receiver_email]):
        print("Variables d’environnement liées à la messagerie manquantes")
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg.attach(MIMEText(html_content, "html"))

    try:
        context = ssl._create_unverified_context()
        with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context) as server:
            server.login(smtp_user, smtp_password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
        print(f"Email envoyé à {receiver_email}")
    except Exception as e:
        print(f"Erreur lors de l’envoi de l’email : {e}")

def main():
    data = load_scan_result()
    if not data:
        return

    filtered = filter_vulnerabilities(data)
    save_json(filtered, FILTERED_REPORT)

    print(f"Vulnérabilités Angular filtrées : {len(filtered)}")
    if filtered:
        html_report = generate_html(filtered)
        send_email("Rapport du scan Snyk - Angular", html_report)
    else:
        print("Aucune vulnérabilité medium ou plus trouvée, pas d’email envoyé.")

if __name__ == "__main__":
    main()
