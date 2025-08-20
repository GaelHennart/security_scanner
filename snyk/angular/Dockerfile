FROM node:18-slim

RUN apt-get update && apt-get install -y python3 python3-pip git curl jq && rm -rf /var/lib/apt/lists/*
RUN npm install -g snyk

WORKDIR /app
COPY . /app

RUN npm config set legacy-peer-deps true
RUN npm install

ENTRYPOINT ["/app/angular_scan.sh"]
