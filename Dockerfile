# Backend dashboard image (Node + Express + SQLite, serves the frontend too).
# NOTE: only the dashboard runs in Docker. The host agents must run natively
# on the OpenVPN box and the Proxmox host (they manipulate easy-rsa & iptables).
FROM node:20-slim

WORKDIR /app/backend

# Install deps first for better layer caching
COPY backend/package*.json ./
RUN npm ci --omit=dev

# App code + static frontend (server.js serves ../../frontend)
COPY backend/ ./
COPY frontend/ /app/frontend/

# SQLite DB lives here; mounted as a volume so it survives container rebuilds
RUN mkdir -p /app/backend/data
VOLUME ["/app/backend/data"]

EXPOSE 8080
CMD ["node", "src/server.js"]
