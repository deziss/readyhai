# Build: docker build -t readyhai/playwright-runner:local runners/playwright
# Base pinned by digest (tag kept for readability).
FROM mcr.microsoft.com/playwright:v1.65.1-noble@sha256:1507cbfc550a63a6b7396791ca4f00df17beb56342d2447b3f106c306f525579
WORKDIR /runner
COPY package.json package-lock.json* ./
# playwright version must match the base image tag (browsers live in /ms-playwright).
RUN if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev --no-audit --no-fund; fi \
 && npm cache clean --force
COPY *.mjs ./
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright HOME=/tmp
USER 1000:1000
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["node", "-e", "process.exit(0)"]
ENTRYPOINT []
