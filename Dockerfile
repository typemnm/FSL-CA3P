FROM mcr.microsoft.com/playwright:v1.58.2-noble

# The Playwright image supplies Chromium and its OS libraries. The repository
# supplies the matching Playwright package, while casper-db needs Python.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv curl \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/ca3p-venv

ENV PATH="/opt/ca3p-venv/bin:${PATH}" \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

WORKDIR /app

COPY xss-parser/package.json xss-parser/package-lock.json ./xss-parser/
RUN npm ci --prefix ./xss-parser --omit=dev

COPY casper-db/ ./casper-db/
RUN python -m pip install --no-cache-dir ./casper-db

COPY . .
RUN mkdir -p /app/casper-db/data /app/reports/pentest-db-runs

EXPOSE 4173
CMD ["node", "start.mjs"]
