FROM ghcr.io/zaproxy/zaproxy:stable

USER root

WORKDIR /zap

COPY zap_scan.sh /zap/zap_scan.sh
COPY zap_scanner.py /zap/zap_scanner.py
COPY swagger.json /zap/swagger/swagger.json

# Dépendances Python
RUN apt-get update && \
    apt-get install -y python3 python3-pip python3-venv && \
    python3 -m venv /zap/venv && \
    /zap/venv/bin/pip install six python-owasp-zap-v2.4

ENV PATH="/zap/venv/bin:$PATH"

USER zap

CMD ["/zap/zap_scan.sh"]
