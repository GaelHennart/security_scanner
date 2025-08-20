import json
import os
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from datetime import datetime, timedelta

REPORT_PATH = "/zap/wrk/report.json"
HTML_REPORT_PATH = "/zap/wrk/filtered_report.html"
MIN_RISK_CODE = 2

def get_risk_label(riskcode):
    return {0: "Informational", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}.get(riskcode, "Unknown")

def load_report(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def filter_alerts(alerts):
    return [
        {
            "name": alert["name"],
            "risk": get_risk_label(int(alert["riskcode"])),
            "desc": alert.get("desc", "").strip(),
            "instances": [
                {
                    "uri": inst["uri"],
                    "param": inst.get("param", "N/A")
                }
                for inst in alert.get("instances", [])
            ],
            "solution": alert.get("solution", "").strip()
        }
        for alert in alerts
        if int(alert["riskcode"]) >= MIN_RISK_CODE
    ]

def generate_html(alerts):
    html = f"""<html>
    <head><meta charset="utf-8"><title>Rapport du Scan ZAP</title></head>
    <body>
    <h2>Rapport de Vulnérabilités ZAP – {(datetime.now() + timedelta(hours=2)).strftime('%Y-%m-%d %H:%M')}</h2>
    <p><strong>Rapport filtré pour ne garder que les vulnérabilités de niveau Medium ou supérieur</strong></p>
    <table border="1" cellpadding="5" cellspacing="0">
    <tr><th>Nom</th><th>Risque</th><th>Description</th><th>Paramètres</th><th>URLs</th><th>Solution</th></tr>
    """
    for alert in alerts:
        urls = "<br>".join([f"<code>{i['uri']}</code>" for i in alert["instances"]])
        params = "<br>".join(set(i["param"] for i in alert["instances"]))
        desc = alert["desc"]
        solution = alert["solution"]
        html += f"<tr><td>{alert['name']}</td><td>{alert['risk']}</td><td>{desc}</td><td>{params}</td><td>{urls}</td><td>{solution}</td></tr>\n"
    html += "</table></body></html>"
    return html

def send_email(subject, html_content, recipient):
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT", 465))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    sender_email = smtp_user
    receiver_email = recipient or os.getenv("EMAIL_TO")

    if not all([smtp_server, smtp_user, smtp_password, receiver_email]):
        print("Variables d’environnement liées à la messagerie manquantes")
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver_email

    part_html = MIMEText(html_content, "html")
    msg.attach(part_html)

    context = ssl._create_unverified_context()
    with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context) as server:
        server.login(smtp_user, smtp_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())

    print(f"Email envoyé à {receiver_email}")

def main():
    if not Path(REPORT_PATH).exists():
        print(f"Le rapport n'existe pas dans {REPORT_PATH}")
        return

    report = load_report(REPORT_PATH)
    if not report.get("site"):
        print("Aucune donnée 'site' trouvée dans le rapport.")
        return

    alerts = filter_alerts(report["site"][0].get("alerts", []))
    if not alerts:
        print("Aucune vulnérabilité de niveau Medium ou supérieur détectée. Aucun email envoyé.")
        return

    html_content = generate_html(alerts)
    Path(HTML_REPORT_PATH).write_text(html_content, encoding="utf-8")
    print(f"Rapport HTML généré : {HTML_REPORT_PATH}")

    send_email("Rapport du scan ZAP", html_content, os.getenv("EMAIL_TO"))

if __name__ == "__main__":
    main()
