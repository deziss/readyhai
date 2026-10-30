# Build: docker build -t readyhai/playwright-runner:local runners/playwright
# Base pinned by digest (tag kept for readability).
FROM mcr.microsoft.com/playwright:v1.56.0-noble@sha256:35246d87a7c88ea9b771c65d33171b2611b02a8253b4b12ce6f94376c55f99f2
WORKDIR /runner
COPY package.json package-lock.json* ./
# playwright version must match the base image tag (browsers live in /ms-playwright).
RUN if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev --no-audit --no-fund; fi \
 && npm cache clean --force
COPY *.mjs ./
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright HOME=/tmp
USER pwuser
ENTRYPOINT []
