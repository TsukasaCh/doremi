import express from 'express';
import cookieParser from 'cookie-parser';
import path from 'path';
import { fileURLToPath } from 'url';

import cfg from './config.js';
import { requireAuth } from './auth.js';
import { startScheduler } from './scheduler.js';

import authRoutes from './routes/auth.js';
import userRoutes from './routes/users.js';
import aclRoutes from './routes/acl.js';
import agentRoutes from './routes/agents.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
app.use(express.json());
app.use(cookieParser());

// --- API ---
app.use('/api/auth', authRoutes);
app.use('/api/users', requireAuth, userRoutes);
app.use('/api/users', requireAuth, aclRoutes); // /:id/acl endpoints
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
