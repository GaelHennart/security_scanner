#!/bin/bash
set -e

echo "Authentification Snyk angular"
snyk auth "$SNYK_TOKEN"

echo "Scan des dépendances angular (package.json)"
mkdir -p /app/reports
snyk test --file=package.json --json > /app/reports/angular-full.json || true

echo "Filtrage des vulnérabilités sur les dépendances angular"
python3 /app/angular_scanner.py
