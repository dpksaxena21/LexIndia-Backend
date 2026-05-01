from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional
import anthropic
import requests
import os
import json
import psycopg2
import psycopg2.extras
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import boto3
from botocore.config import Config

SECRET_KEY   = os.getenv("SECRET_KEY", "change-this-in-production-use-a-long-random-string")
ALGORITHM    = "HS256"
TOKEN_EXPIRY = 30

DATABASE_URL         = os.getenv("DATABASE_URL") or os.getenv("DATABASE_PRIVATE_URL") or os.getenv("DATABASE_PUBLIC_URL")
CLAUDE_API_KEY       = os.getenv("CLAUDE_API_KEY")
INDIAN_KANOON_TOKEN  = os.getenv("INDIAN_KANOON_TOKEN")
R2_ACCOUNT_ID        = os.getenv("R2_ACCOUNT_ID")
R2_ACCESS_KEY_ID     = os.getenv("R2_ACCESS_KEY_ID")
R2_SECRET_ACCESS_KEY = os.getenv("R2_SECRET_ACCESS_KEY")
R2_BUCKET_NAME       = os.getenv("R2_BUCKET_NAME", "lexindia-vault")

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

def get_conn():
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)

def get_r2():
    return boto3.client(
        "s3",
        endpoint_url=f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com",
        aws_access_key_id=R2_ACCESS_KEY_ID,
        aws_secret_access_key=R2_SECRET_ACCESS_KEY,
        config=Config(signature_version="s3v4"),
        region_name="auto",
    )

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
    session_id: Optional[str] = None

class DraftRequest(BaseModel):
    doc_type: str
    court: str
    petitioner: str
    respondent: str
    facts: str
    grounds: str
    save: bool = False

class GoogleAuthRequest(BaseModel):
    access_token: str

class VaultSaveRequest(BaseModel):
    title: str
    content: str
    source: str = "LexSearch"

@app.get("/debug-env")
def debug_env():
    return {
        "db_set": DATABASE_URL is not None,
        "r2_account": R2_ACCOUNT_ID[:8] if R2_ACCOUNT_ID else "NONE",
        "r2_key": R2_ACCESS_KEY_ID[:8] if R2_ACCESS_KEY_ID else "NONE",
        "r2_secret": "SET" if R2_SECRET_ACCESS_KEY else "NONE",
        "r2_bucket": R2_BUCKET_NAME,
    }

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

@app.post("/api/auth/google")
def google_auth(req: GoogleAuthRequest):
    try:
        resp = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {req.access_token}"},
            timeout=10
        )
        if not resp.ok:
            raise HTTPException(status_code=401, detail="Invalid Google token")
        info  = resp.json()
        email = info.get("email", "").lower().strip()
        name  = info.get("name", email.split("@")[0])
        if not email:
            raise HTTPException(status_code=400, detail="Could not get email from Google")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    try:
        conn = get_conn()
        cur  = conn.cursor()
        cur.execute("SELECT id, email, name, plan FROM users WHERE email = %s", (email,))
        row = cur.fetchone()
        if row:
            user = dict(row)
        else:
            cur.execute(
                "INSERT INTO users (email, name, password) VALUES (%s, %s, %s) RETURNING id, email, name, plan",
                (email, name, "google-oauth-no-password")
            )
            user = dict(cur.fetchone())
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    token = create_token(str(user["id"]))
    return {"token": token, "user": user}

@app.post("/api/search")
async def search(req: SearchRequest, user_id: Optional[str] = Depends(optional_user)):
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
            pass

    async def stream():
        yield f"data: {json.dumps({'type': 'cases', 'cases': results})}\n\n"
        try:
            with claude.messages.stream(
                model="claude-haiku-4-5",
                max_tokens=4000,
                messages=[{
                    "role": "user",
                    "content": f"""You are LexIndia, a senior Indian advocate. A lawyer searched for: "{req.query}"

Relevant cases:
{context}

Provide legal analysis with these sections:

# Legal Analysis: {req.query}

## Overview
3-4 sentences on this legal topic.

## Key Legal Principles
Core principles with case citations and ratio decidendi.

## Landmark Cases Analysis
For each major case: name, court, key holding, practical application today.

## Constitutional and Statutory Framework
Relevant BNS/BNSS/IPC/CrPC sections with practical application.

## Practical Takeaways for Advocates
- Arguments for petitioner
- Key evidence needed
- Common pitfalls
- Recent developments

Be precise and practical for Indian court advocates."""
                }]
            ) as stream:
                for text in stream.text_stream:
                    yield f"data: {json.dumps({'type': 'text', 'content': text})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"
        yield f"data: {json.dumps({'type': 'done'})}\n\n"

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )

@app.post("/api/chat")
def chat(req: ChatRequest, user_id: Optional[str] = Depends(optional_user)):
    session_id = req.session_id
    history    = req.history

    if user_id and session_id:
        try:
            conn = get_conn()
            cur  = conn.cursor()
            cur.execute("SELECT messages FROM chat_sessions WHERE id = %s AND user_id = %s", (session_id, user_id))
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
            system="You are LexChat, a senior Indian advocate with 50 years of experience. Deep expertise in BNS, BNSS, IPC, CrPC, Indian Evidence Act, Constitution of India. Cite relevant sections and cases, give practical actionable advice.",
            messages=messages
        )
        reply = response.content[0].text
    except Exception as e:
        reply = f"Error: {str(e)}"

    updated_history = messages + [{"role": "assistant", "content": reply}]
    new_session_id  = session_id

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

@app.get("/api/chat/sessions")
def list_sessions(user_id: str = Depends(current_user)):
    try:
        conn = get_conn()
        cur  = conn.cursor()
        cur.execute("SELECT id, title, updated_at FROM chat_sessions WHERE user_id = %s ORDER BY updated_at DESC LIMIT 50", (user_id,))
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

@app.post("/api/draft")
def draft(req: DraftRequest, user_id: Optional[str] = Depends(optional_user)):
    try:
        message = claude.messages.create(
            model="claude-haiku-4-5",
            max_tokens=3000,
            messages=[{
                "role": "user",
                "content": f"You are LexDraft, an expert Indian legal document drafter. Draft a {req.doc_type} for Court: {req.court}, Petitioner: {req.petitioner}, Respondent: {req.respondent}, Facts: {req.facts}, Grounds: {req.grounds}. Use correct BNS/BNSS sections for post-July 2024, IPC/CrPC for pre-July 2024. Format as proper court document with cause title, facts, grounds, prayer."
            }]
        )
        document = message.content[0].text
    except Exception as e:
        document = f"Error: {str(e)}"

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
        cur.execute("SELECT id, doc_type, title, created_at FROM documents WHERE user_id = %s ORDER BY created_at DESC", (user_id,))
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
        cur.execute("SELECT id, query, module, created_at FROM searches WHERE user_id = %s ORDER BY created_at DESC LIMIT 50", (user_id,))
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        conn.close()
        return {"searches": rows}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/vault/save")
def vault_save(req: VaultSaveRequest, user_id: str = Depends(current_user)):
    try:
        conn = get_conn()
        cur  = conn.cursor()
        cur.execute(
            "INSERT INTO vault (user_id, title, content, source) VALUES (%s, %s, %s, %s) RETURNING id",
            (user_id, req.title, req.content, req.source)
        )
        saved_id = str(cur.fetchone()["id"])
        conn.commit()
        cur.close()
        conn.close()
        return {"ok": True, "id": saved_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/vault")
def list_vault(user_id: str = Depends(current_user)):
    try:
        conn = get_conn()
        cur  = conn.cursor()
        cur.execute(
            "SELECT id, title, source, created_at FROM vault WHERE user_id = %s ORDER BY created_at DESC",
            (user_id,)
        )
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        conn.close()
        return {"items": rows}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/vault/{item_id}")
def delete_vault(item_id: str, user_id: str = Depends(current_user)):
    try:
        conn = get_conn()
        cur  = conn.cursor()
        cur.execute("DELETE FROM vault WHERE id = %s AND user_id = %s", (item_id, user_id))
        conn.commit()
        cur.close()
        conn.close()
        return {"ok": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── R2 File Upload ──────────────────────────────────────────────────────────

@app.post("/api/vault/upload")
async def vault_upload(
    file: UploadFile = File(...),
    title: str = Form(""),
    user_id: str = Depends(current_user)
):
    import uuid
    ext = file.filename.split(".")[-1] if "." in file.filename else "bin"
    key = f"{user_id}/{uuid.uuid4()}.{ext}"
    contents = await file.read()
    try:
        r2 = get_r2()
        r2.put_object(
            Bucket=R2_BUCKET_NAME,
            Key=key,
            Body=contents,
            ContentType=file.content_type or "application/octet-stream",
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"R2 upload failed: {str(e)}")
    file_title = title or file.filename
    try:
        conn = get_conn()
        cur  = conn.cursor()
        cur.execute(
            "INSERT INTO vault (user_id, title, content, source) VALUES (%s, %s, %s, %s) RETURNING id",
            (user_id, file_title, key, "file")
        )
        saved_id = str(cur.fetchone()["id"])
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"ok": True, "id": saved_id, "key": key, "filename": file.filename}

@app.get("/api/vault/file/{item_id}")
def vault_file_url(item_id: str, user_id: str = Depends(current_user)):
    try:
        conn = get_conn()
        cur  = conn.cursor()
        cur.execute(
            "SELECT content, title FROM vault WHERE id = %s AND user_id = %s AND source = 'file'",
            (item_id, user_id)
        )
        row = cur.fetchone()
        cur.close()
        conn.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    if not row:
        raise HTTPException(status_code=404, detail="File not found")
    key = row["content"]
    try:
        r2  = get_r2()
        url = r2.generate_presigned_url(
            "get_object",
            Params={"Bucket": R2_BUCKET_NAME, "Key": key},
            ExpiresIn=3600
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not generate URL: {str(e)}")
    return {"url": url, "title": row["title"]}