from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional
import anthropic
import requests
import os
import json
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────

SECRET_KEY    = os.getenv("SECRET_KEY", "change-this-in-production-use-a-long-random-string")
ALGORITHM     = "HS256"
TOKEN_EXPIRY  = 30  # days

DATABASE_URL         = os.getenv("DATABASE_URL")
CLAUDE_API_KEY       = os.getenv("CLAUDE_API_KEY")
INDIAN_KANOON_TOKEN  = os.getenv("INDIAN_KANOON_TOKEN")

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="LexIndia API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://lexindia-one.vercel.app", "https://*.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

claude  = anthropic.Anthropic(api_key=CLAUDE_API_KEY)
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer  = HTTPBearer(auto_error=False)

# ── DB helpers ────────────────────────────────────────────────────────────────

def get_conn():
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)

# ── JWT helpers ───────────────────────────────────────────────────────────────

def create_token(user_id: str) -> str:
    expire = datetime.utcnow() + timedelta(days=TOKEN_EXPIRY)
    return jwt.encode({"sub": user_id, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

def current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> str:
    if not creds:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return decode_token(creds.credentials)

def optional_user(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> Optional[str]:
    if not creds:
        return None
    try:
        return decode_token(creds.credentials)
    except HTTPException:
        return None

# ── Pydantic models ───────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: str
    name: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

class SearchRequest(BaseModel):
    query: str

class ChatRequest(BaseModel):
    message: str
    history: list = []
    session_id: Optional[str] = None   # if provided, load+save to DB

class DraftRequest(BaseModel):
    doc_type: str
    court: str
    petitioner: str
    respondent: str
    facts: str
    grounds: str
    save: bool = False                  # if True + auth, save to documents table

class SaveDraftRequest(BaseModel):
    doc_type: str
    title: str
    content: str

# ── Auth endpoints ────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "LexIndia API running"}

@app.post("/api/auth/register")
def register(req: RegisterRequest):
    hashed = pwd_ctx.hash(req.password)
    try:
        conn = get_conn()
        cur  = conn.cursor()
        cur.execute(
            "INSERT INTO users (email, name, password) VALUES (%s, %s, %s) RETURNING id, email, name, plan",
            (req.email.lower().strip(), req.name.strip(), hashed)
        )
        user = dict(cur.fetchone())
        conn.commit()
        cur.close()
        conn.close()
    except psycopg2.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Email already registered")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    token = create_token(str(user["id"]))
    return {"token": token, "user": user}

@app.post("/api/auth/login")
def login(req: LoginRequest):
    try:
        conn = get_conn()
        cur  = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (req.email.lower().strip(),))
        row = cur.fetchone()
        cur.close()
        conn.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    if not row or not pwd_ctx.verify(req.password, row["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    user  = {"id": str(row["id"]), "email": row["email"], "name": row["name"], "plan": row["plan"]}
    token = create_token(str(row["id"]))
    return {"token": token, "user": user}

@app.get("/api/auth/me")
def me(user_id: str = Depends(current_user)):
    try:
        conn = get_conn()
        cur  = conn.cursor()
        cur.execute("SELECT id, email, name, plan, created_at FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
        cur.close()
        conn.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return dict(row)

# ── Search endpoint ───────────────────────────────────────────────────────────

@app.post("/api/search")
def search(req: SearchRequest, user_id: Optional[str] = Depends(optional_user)):
    try:
        response = requests.post(
            "https://api.indiankanoon.org/search/",
            data={"formInput": req.query, "pagenum": 0},
            headers={"Authorization": f"Token {INDIAN_KANOON_TOKEN}"},
            timeout=15
        )
        results = response.json().get("docs", [])[:10]
    except Exception:
        results = []

    context = "\n\n".join([
        f"Case: {r.get('title', '')}\nCourt: {r.get('docsource', '')}\nDate: {r.get('publishdate', '')}\nSummary: {r.get('headline', '')}"
        for r in results
    ])

    try:
        message = claude.messages.create(
            model="claude-haiku-4-5",
            max_tokens=6000,
            messages=[{
                "role": "user",
                "content": f"""You are LexIndia, a senior Indian advocate and legal scholar with 30 years of experience. A lawyer searched for: "{req.query}"

Relevant cases from Indian Kanoon:
{context}

Provide comprehensive legal analysis with ALL sections below in this exact order:

# Legal Analysis: {req.query}

## Overview
3-4 sentences on this legal topic and its significance in Indian law.

## Interpretive Framework
How Indian courts have interpreted this provision or legal concept:
- Which rule of interpretation applied (literal, golden, mischief, purposive, harmonious construction)
- How meaning evolved from original enactment to present day
- Key judges and benches who shaped the interpretation
- Constitutional philosophy underlying the interpretation
- Current prevailing interpretation and its limits

## Jurisprudential Evolution
Complete legal journey chronologically:
- Original scope when the law was enacted or concept first arose
- First major Supreme Court pronouncement and what it established
- Decade by decade development with key cases and year
- Turning point judgments that expanded or restricted the concept
- Current settled legal position
- Areas still contested or unsettled in courts today

## Key Legal Principles
Core principles from these cases. For each: state it clearly, cite the case, explain ratio decidendi, give practical significance for advocates.

## Landmark Cases Analysis
For each major case: full name and year, court, key facts, key holding and ratio decidendi, practical application today.

## Constitutional and Statutory Framework
Relevant provisions and statutes including IPC/BNS/BNSS/CrPC/Evidence Act. Include section numbers and practical application. Note BNS/BNSS replacements post July 2024.

## Practical Takeaways for Advocates
- Arguments for petitioner or appellant
- Arguments to anticipate from other side
- Key evidence and documentation needed
- Common pitfalls to avoid
- How to use interpretive framework in arguments
- Recent developments affecting this area

## Suggested Next Steps
What the advocate should do next in terms of research, filings, and applications.

Be comprehensive, precise, and practical for practising advocates in Indian courts."""
            }]
        )
        summary = message.content[0].text
    except Exception as e:
        summary = f"AI summary unavailable: {str(e)}"

    # Save to search history if logged in
    if user_id:
        try:
            conn = get_conn()
            cur  = conn.cursor()
            cur.execute(
                "INSERT INTO searches (user_id, query, module, result) VALUES (%s, %s, %s, %s)",
                (user_id, req.query, "LexSearch", json.dumps({"cases_count": len(results)}))
            )
            conn.commit()
            cur.close()
            conn.close()
        except Exception:
            pass  # search history failure should never block the response

    return {"query": req.query, "cases": results, "ai_summary": summary}

# ── Chat endpoint (with persistent sessions) ──────────────────────────────────

@app.post("/api/chat")
def chat(req: ChatRequest, user_id: Optional[str] = Depends(optional_user)):
    session_id   = req.session_id
    history      = req.history

    # If logged in and session_id provided, load history from DB
    if user_id and session_id:
        try:
            conn = get_conn()
            cur  = conn.cursor()
            cur.execute(
                "SELECT messages FROM chat_sessions WHERE id = %s AND user_id = %s",
                (session_id, user_id)
            )
            row = cur.fetchone()
            cur.close()
            conn.close()
            if row:
                history = row["messages"]
        except Exception:
            pass

    messages = history + [{"role": "user", "content": req.message}]

    try:
        response = claude.messages.create(
            model="claude-haiku-4-5",
            max_tokens=2000,
            system="You are LexChat, a senior Indian advocate and legal scholar with 50 years of experience across the Supreme Court, High Courts, and Sessions Courts. Deep expertise in BNS, BNSS, IPC, CrPC, Indian Evidence Act, Constitution of India, and jurisprudence. When answering: cite relevant sections and cases, explain the interpretive framework courts use, trace jurisprudential evolution of key concepts when relevant, give practical actionable advice. Speak like a senior advocate advising a junior colleague.",
            messages=messages
        )
        reply = response.content[0].text
    except Exception as e:
        reply = f"Error: {str(e)}"

    updated_history = messages + [{"role": "assistant", "content": reply}]

    # Save/update session if logged in
    new_session_id = session_id
    if user_id:
        try:
            conn = get_conn()
            cur  = conn.cursor()
            if session_id:
                cur.execute(
                    "UPDATE chat_sessions SET messages = %s, updated_at = NOW() WHERE id = %s AND user_id = %s",
                    (json.dumps(updated_history), session_id, user_id)
                )
            else:
                # Create new session — title = first 60 chars of first message
                title = req.message[:60] + ("..." if len(req.message) > 60 else "")
                cur.execute(
                    "INSERT INTO chat_sessions (user_id, title, messages) VALUES (%s, %s, %s) RETURNING id",
                    (user_id, title, json.dumps(updated_history))
                )
                row = cur.fetchone()
                new_session_id = str(row["id"])
            conn.commit()
            cur.close()
            conn.close()
        except Exception:
            pass

    return {"reply": reply, "session_id": new_session_id}

# ── Chat session management ───────────────────────────────────────────────────

@app.get("/api/chat/sessions")
def list_sessions(user_id: str = Depends(current_user)):
    try:
        conn = get_conn()
        cur  = conn.cursor()
        cur.execute(
            "SELECT id, title, updated_at FROM chat_sessions WHERE user_id = %s ORDER BY updated_at DESC LIMIT 50",
            (user_id,)
        )
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        conn.close()
        return {"sessions": rows}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/chat/sessions/{session_id}")
def delete_session(session_id: str, user_id: str = Depends(current_user)):
    try:
        conn = get_conn()
        cur  = conn.cursor()
        cur.execute("DELETE FROM chat_sessions WHERE id = %s AND user_id = %s", (session_id, user_id))
        conn.commit()
        cur.close()
        conn.close()
        return {"ok": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── Draft endpoint ────────────────────────────────────────────────────────────

@app.post("/api/draft")
def draft(req: DraftRequest, user_id: Optional[str] = Depends(optional_user)):
    try:
        message = claude.messages.create(
            model="claude-haiku-4-5",
            max_tokens=3000,
            messages=[{
                "role": "user",
                "content": f"You are LexDraft, an expert Indian legal document drafter with 30 years of experience. Draft a {req.doc_type} for Court: {req.court}, Petitioner: {req.petitioner}, Respondent: {req.respondent}, Facts: {req.facts}, Grounds: {req.grounds}. Use correct BNS/BNSS sections for post-July 2024 matters, IPC/CrPC for pre-July 2024. Format as a proper court document with all standard sections including cause title, facts, grounds, prayer. Include proper legal language, citation format, and applicable precedents."
            }]
        )
        document = message.content[0].text
    except Exception as e:
        document = f"Error: {str(e)}"

    # Auto-save if requested and logged in
    saved_id = None
    if req.save and user_id and document and not document.startswith("Error"):
        try:
            title = f"{req.doc_type} — {req.petitioner}"
            conn  = get_conn()
            cur   = conn.cursor()
            cur.execute(
                "INSERT INTO documents (user_id, doc_type, title, content) VALUES (%s, %s, %s, %s) RETURNING id",
                (user_id, req.doc_type, title, document)
            )
            saved_id = str(cur.fetchone()["id"])
            conn.commit()
            cur.close()
            conn.close()
        except Exception:
            pass

    return {"document": document, "saved_id": saved_id}

@app.get("/api/documents")
def list_documents(user_id: str = Depends(current_user)):
    try:
        conn = get_conn()
        cur  = conn.cursor()
        cur.execute(
            "SELECT id, doc_type, title, created_at FROM documents WHERE user_id = %s ORDER BY created_at DESC",
            (user_id,)
        )
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        conn.close()
        return {"documents": rows}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/searches")
def search_history(user_id: str = Depends(current_user)):
    try:
        conn = get_conn()
        cur  = conn.cursor()
        cur.execute(
            "SELECT id, query, module, created_at FROM searches WHERE user_id = %s ORDER BY created_at DESC LIMIT 50",
            (user_id,)
        )
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        conn.close()
        return {"searches": rows}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
