import express from 'express';
import cookieParser from 'cookie-parser';
import path from 'path';
import { fileURLToPath } from 'url';

import cfg from './config.js';
import { requireAuth, requireRole, writeGuard } from './auth.js';
import { requireApiKey } from './apikeys.js';
import { startScheduler } from './scheduler.js';

import authRoutes from './routes/auth.js';
import userRoutes from './routes/users.js';
import aclRoutes from './routes/acl.js';
import groupRoutes from './routes/groups.js';
import forwardRoutes from './routes/forwards.js';
import adminRoutes from './routes/admins.js';
import apiKeyRoutes from './routes/apikeys.js';
import apiV1Routes from './routes/apiv1.js';
import agentRoutes from './routes/agents.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
app.set('trust proxy', true); // behind nginx: honor X-Forwarded-Proto/For
app.use(express.json());
app.use(cookieParser());

// --- API ---
// Reads allowed for any signed-in role; writes require admin/operator (writeGuard).
app.use('/api/auth', authRoutes);
app.use('/api/users', requireAuth, writeGuard, userRoutes);
app.use('/api/users', requireAuth, writeGuard, aclRoutes); // /:id/acl and /:id/groups
app.use('/api/groups', requireAuth, writeGuard, groupRoutes);
app.use('/api/forwards', requireAuth, writeGuard, forwardRoutes);
app.use('/api/admins', requireAuth, requireRole('admin'), adminRoutes); // IAM: admin only
app.use('/api/apikeys', requireAuth, requireRole('admin'), apiKeyRoutes); // manage keys: admin only
app.use('/api/v1', requireApiKey, apiV1Routes); // server-to-server API (API key)
app.use('/api/agents', requireAuth, agentRoutes);
app.use('/api', requireAuth, agentRoutes); // /api/audit

// --- Static frontend ---
app.use(express.static(path.join(__dirname, '..', '..', 'frontend')));

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', '..', 'frontend', 'index.html'));
});

app.listen(cfg.port, () => {
  console.log(`OpenVPN Manager dashboard on http://0.0.0.0:${cfg.port}`);
  startScheduler();
});
