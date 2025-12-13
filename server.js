// server.js
const express = require('express');
const dotenv = require('dotenv');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');

dotenv.config();

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);

const app = express();

app.use(helmet());
app.use(bodyParser.json({ limit: '6mb' }));

app.use(cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.length === 0) return callback(null, true);
    if (ALLOWED_ORIGINS.indexOf(origin) !== -1) return callback(null, true);
    return callback(new Error('CORS policy: origin not allowed'), false);
  },
  credentials: true
}));

const analyzeLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20,
  message: { error: 'Too many requests, slow down.' }
});

let storedAdsHtml = '<h3 style="font-size:20px;margin-bottom:15px">🎯 Tangazo Lako Hapa!</h3><p style="line-height:1.6">Wasiliana nasi kwa matangazo.</p>';

// Middleware to check admin token
function requireAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  const token = auth.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload && payload.role === 'admin') return next();
    return res.status(403).json({ error: 'Forbidden' });
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Admin login
app.post('/admin/login', (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required' });
  if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Invalid password' });

  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token });
});

// Update ads (admin only)
app.post('/admin/ads', requireAdmin, (req, res) => {
  const { adsHtml } = req.body;
  if (typeof adsHtml !== 'string') return res.status(400).json({ error: 'adsHtml required' });

  storedAdsHtml = adsHtml; // update the ads
  res.json({ message: 'Ads updated successfully' });
});

// View current ads (public)
app.get('/ads', (req, res) => {
  res.send(storedAdsHtml);
});

// Example test endpoint
app.get('/', (req, res) => {
  res.json({ message: 'Server is running ✅' });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
