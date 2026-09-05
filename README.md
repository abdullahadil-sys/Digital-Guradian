# 🛡️ Digital Guardian — Scam & Fraud Alert Assistant

A production-style, full-stack, RAG-powered AI assistant that analyzes suspicious emails, SMS
messages, social media messages, and links for scam and fraud risk — and returns a grounded,
explainable, actionable risk assessment.

---

## 1. Project Overview

Digital Guardian is a **defensive cybersecurity application**. A user pastes a suspicious message
into the interface; the backend retrieves relevant entries from a curated, trusted scam-pattern
knowledge base, augments an AI model (or a deterministic fallback engine) with that context, and
generates a structured risk report: a 0–100 risk score, a risk level (LOW/MEDIUM/HIGH), red flags,
safe next steps, and the sources that informed the verdict.

The assistant **never** asks for passwords, OTPs, PINs, or full financial credentials, never
encourages clicking suspicious links, and always encourages independent verification through
official channels.

## 2. Architecture

```
┌─────────────┐      HTTPS/JSON       ┌───────────────────┐
│   Frontend   │ ────────────────────▶ │      Backend       │
│ React + Vite │ ◀──────────────────── │  FastAPI + RAG      │
│ R3F 3D scene │                       │                     │
└─────────────┘                       └─────────┬───────────┘
                                                 │
                       ┌─────────────────────────┼─────────────────────────┐
                       ▼                         ▼                         ▼
              ┌─────────────────┐      ┌──────────────────┐      ┌──────────────────┐
              │ Retrieval stage  │      │ Augmentation      │      │ Generation stage  │
              │ TF-IDF vector    │─────▶│ stage             │─────▶│ LLM provider OR   │
              │ search over the  │      │ formats retrieved │      │ heuristic fallback │
              │ knowledge base   │      │ entries as context │      │ analyzer (never    │
              │ (knowledge_base  │      │ for the model      │      │ blindly trusted —  │
              │ .json)           │      │                    │      │ output is validated │
              └─────────────────┘      └──────────────────┘      │ and clamped)        │
                                                                   └──────────────────┘
```

The pipeline strictly separates **Retrieval → Augmentation → Generation** (see
`backend/app/rag.py`). The generation stage's JSON output is always parsed and validated before
being trusted — invalid or missing fields are corrected or clamped, never passed straight through.

## 3. Folder Structure

```
digital-guardian/
├── frontend/
│   ├── package.json
│   ├── vite.config.js
│   ├── index.html
│   ├── .env.example
│   └── src/
│       ├── main.jsx
│       ├── App.jsx
│       ├── styles.css
│       ├── components/
│       │   ├── GuardianScene.jsx     # 3D animated guardian (R3F + Drei)
│       │   ├── ChatBox.jsx           # message input + example prompts
│       │   ├── RiskCard.jsx          # analysis result display
│       │   ├── FeatureCard.jsx       # feature grid
│       │   └── RAGPipeline.jsx       # animated pipeline visualization
│       └── services/
│           └── api.js                # single point of contact with backend
│
├── backend/
│   ├── requirements.txt
│   ├── .env.example
│   ├── app/
│   │   ├── main.py                   # FastAPI app, routes, error handling
│   │   ├── config.py                 # environment-based settings
│   │   ├── rag.py                    # RAG orchestration
│   │   ├── schemas.py                # Pydantic request/response models
│   │   └── services/
│   │       ├── retrieval_service.py  # knowledge base search
│   │       ├── embedding_service.py  # TF-IDF vectorization
│   │       └── llm_service.py        # provider abstraction + fallback
│   └── data/
│       └── knowledge_base.json       # trusted scam pattern references
│
├── README.md
└── .gitignore
```

## 4. Installation

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm

### Clone / unzip the project, then set up each side independently (below).

## 5. Backend Setup

```bash
cd backend
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` if you want to enable a live LLM provider (see [Environment Variables](#7-environment-variables)).
If you leave `LLM_PROVIDER=none` (the default), the app runs entirely offline using the built-in
heuristic analyzer — no API key required, and nothing ever crashes because a key is missing.

## 6. Frontend Setup

```bash
cd frontend
npm install
cp .env.example .env
```

Edit `.env` if your backend runs somewhere other than `http://localhost:8000`.

## 7. Environment Variables

**Backend (`backend/.env`)**

| Variable | Description | Default |
|---|---|---|
| `LLM_PROVIDER` | `anthropic`, `openai`, or `none` | `none` |
| `ANTHROPIC_API_KEY` | API key if using Anthropic | *(empty)* |
| `ANTHROPIC_MODEL` | Anthropic model name | `claude-sonnet-4-6` |
| `OPENAI_API_KEY` | API key if using OpenAI | *(empty)* |
| `OPENAI_MODEL` | OpenAI model name | `gpt-4o-mini` |
| `CORS_ORIGINS` | Comma-separated allowed origins | `http://localhost:5173,http://127.0.0.1:5173` |
| `MAX_MESSAGE_LENGTH` | Max characters accepted per analysis | `4000` |
| `RETRIEVAL_TOP_K` | Number of knowledge-base entries retrieved per query | `4` |

**Frontend (`frontend/.env`)**

| Variable | Description | Default |
|---|---|---|
| `VITE_API_BASE_URL` | Base URL of the backend API | `http://localhost:8000` |

Never commit a real `.env` file — both are already excluded via `.gitignore`.

## 8. Running Locally

**Terminal 1 — backend:**
```bash
cd backend
source .venv/bin/activate
uvicorn app.main:app --reload --port 8000
```

**Terminal 2 — frontend:**
```bash
cd frontend
npm run dev
```

Visit `http://localhost:5173`. The FastAPI interactive docs are available at
`http://localhost:8000/docs`.

## 9. API Documentation

### `GET /api/health`
Returns service status, whether an LLM provider is active, and how many knowledge-base entries are
loaded.

```json
{
  "status": "ok",
  "app_name": "Digital Guardian API",
  "version": "1.0.0",
  "llm_enabled": false,
  "llm_provider": "none",
  "knowledge_base_entries": 12
}
```

### `POST /api/analyze`
**Request**
```json
{ "message": "URGENT: verify your account or it will be suspended. Enter your OTP here: bit.ly/xyz" }
```

**Response**
```json
{
  "risk_score": 82,
  "risk_level": "HIGH",
  "verdict": "This message shows strong indicators of a scam...",
  "explanation": "Heuristic keyword and pattern analysis identified...",
  "red_flags": ["Otp", "Urgent", "Suspended", "Shortened/obscured URL"],
  "safe_actions": ["Do not click any links in the message", "..."],
  "sources": [
    { "id": "kb-002", "category": "otp_scam", "title": "OTP / one-time-passcode sharing requests", "summary": "...", "relevance": 0.71 }
  ],
  "analysis_mode": "heuristic",
  "uncertainty_note": null
}
```

Errors return `4xx`/`5xx` with `{"error": "...", "detail": "..."}` (or FastAPI's standard
`{"detail": "..."}` shape for validation errors) — the frontend always renders these as a friendly
banner instead of crashing.

## 10. RAG Explanation

1. **Retrieve** — `retrieval_service.py` loads `knowledge_base.json` once at startup and uses
   `embedding_service.py` (a TF-IDF vector space model) to find the entries most similar to the
   user's message, entirely offline.
2. **Augment** — `rag.py` formats the retrieved entries into a compact context block.
3. **Generate** — `llm_service.py` sends the message + context to the configured LLM provider (or,
   if none is configured or the call fails, runs the deterministic heuristic analyzer). The
   returned JSON is validated and clamped (score bounds, enum checks, required fields) before ever
   reaching the API response — **the system does not blindly trust the LLM.**

Swapping LLM providers only requires editing `llm_service.py` — no other file needs to change.

## 11. Deployment Instructions

**Backend** — deploy as any standard ASGI app (Render, Railway, Fly.io, a VM, or a container):
```bash
uvicorn app.main:app --host 0.0.0.0 --port $PORT
```
Set the real environment variables (API keys, `CORS_ORIGINS` pointing at your deployed frontend
origin) on the host platform — never bake them into the image.

**Frontend** — build a static bundle and deploy to any static host (Vercel, Netlify, S3+CloudFront):
```bash
npm run build
```
Set `VITE_API_BASE_URL` to your deployed backend's public URL before building.

## 12. Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| Frontend shows "Backend Offline" | FastAPI server not running or wrong port | Confirm `uvicorn` is running on the port in `VITE_API_BASE_URL` |
| CORS error in browser console | Frontend origin not in `CORS_ORIGINS` | Add your dev/prod origin to the backend `.env` |
| `analysis_mode: "heuristic"` even though a key is set | Key missing/invalid or `LLM_PROVIDER` mismatched to the key you set | Confirm `LLM_PROVIDER` matches the key you populated, and the key is valid |
| `500` on `/api/analyze` | Unexpected pipeline error | Check backend logs; the app is designed to degrade to heuristic mode rather than crash — a 500 indicates something outside that path |
| 3D scene doesn't render | WebGL unavailable in the browser/environment | Try a different browser; the rest of the app still functions without WebGL |
| `pip install` fails on `scikit-learn`/`numpy` | Missing build tools on some minimal Linux images | Use a standard Python image (`python:3.11-slim` works) or `pip install --only-binary=:all:` |

---

**Digital Guardian** is an educational and defensive tool. It does not replace official fraud
reporting channels, your bank's fraud department, or law enforcement.
