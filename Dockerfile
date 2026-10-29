FROM node:24.19.0-bookworm

# Keep API/worker on the same Node 24 runtime used by CI, including node:sqlite.
# Browser dependencies are installed from the repository's pinned Playwright.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv curl \
        tesseract-ocr tesseract-ocr-kor \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/ca3p-venv

ENV PATH="/opt/ca3p-venv/bin:${PATH}" \
    PLAYWRIGHT_BROWSERS_PATH=/opt/ca3p-browsers \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

WORKDIR /app

COPY xss-parser/package.json xss-parser/package-lock.json ./xss-parser/
COPY packages/report/capture/package.json packages/report/capture/package-lock.json ./packages/report/capture/
# web-parser's postinstall downloads the Wappalyzer dataset, so its scripts/ must be present in this layer.
COPY web-parser/package.json web-parser/package-lock.json ./web-parser/
COPY web-parser/scripts/ ./web-parser/scripts/
RUN npm ci --prefix ./xss-parser --omit=dev
RUN npm ci --prefix ./packages/report/capture --omit=dev
RUN npm ci --prefix ./web-parser --omit=dev
# Chromium is shared: xss-parser and web-parser pin the same Playwright version.
RUN cd xss-parser && npx playwright install --with-deps chromium

COPY casper-db/ ./casper-db/
COPY packages/report/requirements-ci.lock ./packages/report/requirements-ci.lock
COPY packages/report/py/ ./packages/report/py/
RUN python -m pip install --no-cache-dir -r ./casper-db/requirements-runtime.lock \
    && python -m pip install --no-cache-dir -r ./packages/report/requirements-ci.lock \
    && python -m pip install --no-cache-dir --no-deps ./casper-db ./packages/report/py

COPY . .
RUN mkdir -p /app/.runtime /app/casper-db/data /app/reports/pentest-db-runs

ARG VCS_REF=local
LABEL org.opencontainers.image.source="https://github.com/typemnm/FSL-CA3P" \
      org.opencontainers.image.revision="${VCS_REF}"
ENV CA3P_STORE_PATH=/app/.runtime/runs.sqlite \
    CA3P_COMMIT_SHA=${VCS_REF}

EXPOSE 4173
CMD ["node", "start.mjs"]
