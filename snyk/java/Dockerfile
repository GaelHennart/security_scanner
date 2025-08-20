FROM maven:3.8.7-eclipse-temurin-17

RUN apt-get update && \
    apt-get install -y curl gnupg python3 python3-pip git jq && \
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

RUN npm install -g snyk

WORKDIR /app
COPY . /app

ENTRYPOINT ["/app/java_scan.sh"]
