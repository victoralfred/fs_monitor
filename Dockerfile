# Build the frontend with pnpm, then bake into a Python runtime image.
# Run with --pid=host so /proc reflects the host's processes.

FROM node:20-alpine AS web
RUN corepack enable
WORKDIR /web
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
# vite.config.js writes the build to ../monitor/static; mirror that layout here.
RUN mkdir -p /monitor && pnpm build

FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY monitor/ ./monitor/
COPY --from=web /monitor/static/ ./monitor/static/
RUN pip install --no-cache-dir .
EXPOSE 8765
# Default host bind 0.0.0.0 only makes sense inside a container; still requires
# --allow-remote so the choice is explicit.
ENTRYPOINT ["python", "-m", "monitor"]
CMD ["--host", "0.0.0.0", "--allow-remote"]
