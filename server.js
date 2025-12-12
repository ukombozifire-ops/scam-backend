const express = require('express');
const dotenv = require('dotenv');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const bodyParser = require('body-parser');
const sanitizeHtml = require('sanitize-html');
const jwt = require('jsonwebtoken');

dotenv.config();

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
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
  windowMs: 60 * 1000,
  max: 20,
  message: { error: 'Too many requests, slow down.' }
});

let storedAdsHtml = '<h3 style="font-size:20px;margin-bottom:15px">🎯 Tangazo Lako Hapa!</h3><p style="line-height:1.6">Wasiliana nasi kwa matangazo.</p>';

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

app.post('/admin/login', (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required' });
  if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Invalid password' });

  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token });
});

app.post('/admin/ads', requireAdmin, (req, res) => {
  const { adsHtml } = req.body;
  if (typeof adsHtml !== 'string') return res.status(400).json({ error: 'adsHtml required' });

  storedAdsHtml = sanitizeHtml(adsHtml, {
    allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img','h3']),
    allowedAttributes: {
      a: ['href','name','target','rel'],
      img: ['src','alt','width','height'],
      '*': ['style']
    },
    allowedSchemesByTag: { img: ['data','http','https'] }
  });

  res.json({ ok: true });
});

app.get('/ads', (req, res) => {
  res.json({ adsHtml: storedAdsHtml });
});

app.post('/analyze', analyzeLimiter, async (req, res) => {
  const { message, language, model, image } = req.body;
  if (!message && !image) return res.status(400).json({ error: 'message or image required' });

  const lang = language === 'en' ? 'en' : 'sw';
  const modelName = model || 'gpt-4o';

  if (OPENAI_API_KEY) {
    try {
      const prompt = `
You are a Scam Message Detector. Classify the following content as one of: "scam", "suspicious", or "safe".
Return JSON only in this format: {"type":"scam"|"suspicious"|"safe","analysis":"...explanation..."}
Language: ${lang}
Content:
${message || '[image provided]'}
      `;
      const openaiResp = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${OPENAI_API_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: modelName,
          messages: [{ role: 'system', content: 'You are a helpful assistant.' }, { role: 'user', content: prompt }],
          max_tokens: 450,
          temperature: 0.0
        })
      });

      if (!openaiResp.ok) {
        const txt = await openaiResp.text();
        console.error('OpenAI error:', txt);
        return res.status(502).json({ error: 'External API error' });
      }
      const j = await openaiResp.json();
      const reply = j.choices && j.choices[0] && j.choices[0].message && j.choices[0].message.content;
      let parsed;
      try {
        parsed = JSON.parse(reply);
      } catch (e) {
        const m = reply && reply.match && reply.match(/\{[\s\S]*\}/);
        parsed = m ? JSON.parse(m[0]) : { type: 'suspicious', analysis: reply || 'Could not parse model response' };
      }
      return res.json(parsed);
    } catch (err) {
      console.error('Analyze error', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
  } else {
    const text = (message || '').toLowerCase();
    let type = 'safe';
    let analysis = 'Hakuna dalili kubwa za scam (fallback detector).';

    const scamPatterns = [
      /congrat/i,
      /click.*bit\.ly|tinyurl|bit\.ly/i,
      /send (?:money|cash|rwf|shilling|tsh)/i,
      /account.*suspend|verify.*account|provide.*password/i,
      /urgent|haraka|within.*hour/i,
      /transfer.*money/i,
      /prize|lottery|winner/i
    ];

    if (scamPatterns.some(re => re.test(text))) {
      type = 'scam';
      analysis = 'Ujumbe unaonyesha alama za kawaida za scam (kiungo kifupi, ahadi nzito, shinikizo la haraka).';
    } else if (text.length < 30 && /http|bit\.ly/.test(text)) {
      type = 'suspicious';
      analysis = 'Kiungo kifupi kinapatikana kwenye ujumbe mfupi - inashukiwa.';
    }

    return res.json({ type, analysis });
  }
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
