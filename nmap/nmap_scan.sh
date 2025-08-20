#!/bin/bash
set -e

TARGET="$TARGET"
OUTPUT_XML="/nmap/reports/report.xml"

echo "Démarrage du scan Nmap sur $TARGET"

nmap -sV -sC -A \
     --script "vulners,vuln,ssl*,http-enum,http-title,http-headers" \
     -p 80,443,8080,8443 \
     -oX "$OUTPUT_XML" "$TARGET"

echo "Scan terminé. Rapport disponible dans $OUTPUT_XML"
echo "Filtrage du rapport Nmap et envoi de l'email"

python3 /nmap/nmap_scanner.py
