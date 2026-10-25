# Build: docker build -t readyhai/playwright-runner:local runners/playwright
# TODO: pin the base image by digest once resolved (docker buildx imagetools inspect <tag>).
FROM mcr.microsoft.com/playwright:v1.56.0-noble
WORKDIR /runner
COPY package.json package-lock.json* ./
# playwright version must match the base image tag (browsers live in /ms-playwright).
RUN if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev --no-audit --no-fund; fi \
 && npm cache clean --force
COPY *.mjs ./
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright HOME=/tmp
USER pwuser
ENTRYPOINT []
