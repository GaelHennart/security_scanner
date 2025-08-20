FROM alpine:latest

RUN apk add --no-cache nmap nmap-scripts nmap-nselibs bash curl git python3 py3-pip

WORKDIR /nmap

COPY nmap_scan.sh /nmap/nmap_scan.sh
COPY nmap_scanner.py /nmap/nmap_scanner.py

CMD ["/nmap/nmap_scan.sh"]
