import { Router } from 'express';
import { audit } from '../db.js';
import * as keys from '../apikeys.js';

const router = Router();

// GET /api/apikeys — list keys (prefix only, never the secret)
router.get('/', (req, res) => res.json(keys.listKeys()));

// POST /api/apikeys — create a key; returns the raw value ONCE
router.post('/', (req, res) => {
  const name = (req.body?.name || '').trim();
  if (!name || name.length > 60) return res.status(400).json({ error: 'Nama key wajib (maks 60 char)' });
  const k = keys.generateKey(name);
  audit(req.user, 'apikey_create', name);
  res.status(201).json({ id: k.id, name, key: k.raw, prefix: k.prefix });
});

// PATCH /api/apikeys/:id — enable/disable
router.patch('/:id', (req, res) => {
  keys.setDisabled(req.params.id, !!req.body?.disabled);
  audit(req.user, 'apikey_update', req.params.id, `disabled=${!!req.body?.disabled}`);
  res.json({ ok: true });
});

// DELETE /api/apikeys/:id
router.delete('/:id', (req, res) => {
  keys.deleteKey(req.params.id);
  audit(req.user, 'apikey_delete', req.params.id);
  res.json({ ok: true });
});

export default router;
