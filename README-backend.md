# Scam Detector Backend (Express)

Endpoints
- POST /admin/login   -> body: { password }  => returns { token }
- POST /admin/ads     -> Authorization: Bearer <token>, body: { adsHtml }
- GET  /ads           -> returns { adsHtml }
- POST /analyze       -> body: { message, language, model, image } => returns { type, analysis }

Local run (commands)
1. cd backend
2. cp .env.example .env    # edit .env and set ADMIN_PASSWORD, JWT_SECRET, OPENAI_API_KEY (optional)
3. npm install
4. npm start
5. Server runs on http://localhost:3000 by default
6. Test: curl http://localhost:3000/ads
Security notes
- Do NOT commit .env to GitHub.
- Set ALLOWED_ORIGINS to your frontend domain(s).
- Use Render/Railway and set env vars there for production.
