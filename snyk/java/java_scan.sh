#!/bin/bash
set -e

echo "Authentification Snyk java"
snyk auth "$SNYK_TOKEN"

echo "Scan des dépendances java (pom.xml)"
snyk test --file=pom.xml --json > /app/reports/java_report.json || true

echo "Filtrage des vulnérabilités sur les dépendances java"
python3 java_scanner.py
