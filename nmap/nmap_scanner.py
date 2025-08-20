import os
import smtplib
import ssl
import xml.etree.ElementTree as ET
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from datetime import datetime, timedelta

XML_PATH = "/nmap/reports/report.xml"

def parse_nmap_xml(xml_path):
    if not Path(xml_path).exists():
        print(f"Fichier XML introuvable dans {xml_path}")
        return [], []

    tree = ET.parse(xml_path)
    root = tree.getroot()

    ports_info = []
    vulns_info = []

    for host in root.findall("host"):
        address_elem = host.find("address")
        address = address_elem.attrib.get("addr", "N/A") if address_elem is not None else "N/A"

        for port in host.findall(".//port"):
            port_id = port.attrib.get("portid", "N/A")
            protocol = port.attrib.get("protocol", "N/A")
            state = port.find("state").attrib.get("state", "unknown")

            service_elem = port.find("service")
            service_name = service_elem.attrib.get("name", "N/A") if service_elem is not None else "N/A"
            product = service_elem.attrib.get("product", "") if service_elem is not None else ""
            version = service_elem.attrib.get("version", "") if service_elem is not None else ""

            ports_info.append({
                "host": address,
                "port": port_id,
                "protocol": protocol,
                "state": state,
                "service": service_name,
                "product": product,
                "version": version
            })

            for script in port.findall("script"):
                script_id = script.attrib.get("id", "N/A")
                output = script.attrib.get("output", "").strip()

                if output:
                    vulns_info.append({
                        "host": address,
                        "port": port_id,
                        "script_id": script_id,
                        "output": output
                    })

    return ports_info, vulns_info

def generate_html_report(ports, vulns):
    html = f"""<html>
<head><meta charset="utf-8"><title>Rapport Nmap</title></head>
<body>
<h2>Rapport de Scan Nmap – {(datetime.now() + timedelta(hours=2)).strftime('%Y-%m-%d %H:%M')}</h2>

<h3>Ports et Services détectés</h3>
<table border="1" cellpadding="5" cellspacing="0">
<tr>
<th>Hôte</th><th>Port</th><th>Protocole</th><th>État</th><th>Service</th><th>Produit</th><th>Version</th>
</tr>"""
    if not ports:
        html += "<tr><td colspan='7'>Aucun port ouvert détecté.</td></tr>"
    else:
        for p in ports:
            html += f"<tr><td>{p['host']}</td><td>{p['port']}</td><td>{p['protocol']}</td><td>{p['state']}</td><td>{p['service']}</td><td>{p['product']}</td><td>{p['version']}</td></tr>"

    html += "</table>"

    html += """<h3>Vulnérabilités détectées par les scripts nmap</h3>
<table border="1" cellpadding="5" cellspacing="0">
<tr><th>Hôte</th><th>Port</th><th>Script</th><th>Résultat</th></tr>"""
    if not vulns:
        html += "<tr><td colspan='4'>Aucune vulnérabilité ou sortie de script détectée.</td></tr>"
    else:
        for v in vulns:
            output_formatted = v['output'].replace("\n", "<br>")
            html += f"<tr><td>{v['host']}</td><td>{v['port']}</td><td>{v['script_id']}</td><td>{output_formatted}</td></tr>"

    html += "</table></body></html>"
    return html

def send_email(subject, html_content, recipient):
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT", 465))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    sender_email = os.getenv("EMAIL_FROM", smtp_user)
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

    try:
        context = ssl._create_unverified_context()
        with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context) as server:
            server.login(smtp_user, smtp_password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
        print(f"Email envoyé à {receiver_email}")
    except Exception as e:
        print(f"Erreur lors de l’envoi de l’email : {e}")

def main():
    ports_info, vulns_info = parse_nmap_xml(XML_PATH)
    html_report = generate_html_report(ports_info, vulns_info)
    send_email("Rapport du scan Nmap", html_report, os.getenv("EMAIL_TO"))

if __name__ == "__main__":
    main()
