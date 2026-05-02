# LexIndia — AI Legal Research Platform for Indian Advocates

> An AI-powered legal workspace built for Indian lawyers. Search 27 crore judgments, draft court documents, analyze files, and get instant legal guidance.

**Live:** [lexsindia.com](https://lexsindia.com)

## Modules

| Module | Description |
|--------|-------------|
| LexSearch | Search 27 crore judgments via Indian Kanoon API with AI analysis |
| LexChat | AI legal advisor — BNS, BNSS, IPC, CrPC, Indian Evidence Act |
| LexPlain | Indian laws explained in simple Hinglish |
| LexConstitute | Constitutional law — Articles, writs, landmark cases |
| LexDebate | Counter-arguments generator for any legal position |
| LexGlobe | International law with India-specific context |
| LexDraft | Drafts 56+ legal document types with correct citations |
| LexScan | AI analysis of uploaded PDF/DOCX legal documents |
| LexVault | Google Drive-style file manager with AI analysis |

## Tech Stack

- **Frontend:** Next.js 16 + TypeScript — Vercel
- **Backend:** FastAPI + Python — Railway
- **Database:** PostgreSQL — Railway
- **Storage:** Cloudflare R2
- **AI:** Claude Haiku (Anthropic)
- **Case Law:** Indian Kanoon API
- **Auth:** JWT + Google OAuth 2.0

## Running Locally

### Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
### Frontend
cd frontend
npm install
npm run dev
## Built By

**Deepak Saxena** — Full-stack developer

- GitHub: [github.com/dpksaxena21](https://github.com/dpksaxena21)
- Live: [lexsindia.com](https://lexsindia.com)

*Portfolio project. Not a substitute for professional legal advice.*
