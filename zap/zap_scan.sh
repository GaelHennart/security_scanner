#!/bin/bash
set -e

if [ -z "$TOKEN" ]; then
  echo "Variable TOKEN non définie."
  exit 1
fi

TARGET_URL="$TARGET_URL"
JSON_REPORT="/zap/wrk/report.json"

echo "Démarrage du scan ZAP sur $TARGET_URL"

zap-api-scan.py \
  -t /zap/swagger/swagger.json \
  -f openapi \
  -J "$JSON_REPORT" \
  -z "-config replacer.full_list(0).description=AuthHeader \
      -config replacer.full_list(0).enabled=true \
      -config replacer.full_list(0).matchtype=REQ_HEADER \
      -config replacer.full_list(0).matchstr=Authorization \
      -config replacer.full_list(0).replacement=Bearer $TOKEN" \
  -I

echo "Scan terminé. Rapport json généré dans $JSON_REPORT"

echo "Filtrage du rapport ZAP et envoi de l'email"
python3 /zap/zap_scanner.py
