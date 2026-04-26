from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import anthropic
import requests
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="LexIndia API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://lexindia-one.vercel.app", "https://*.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

claude = anthropic.Anthropic(api_key=os.getenv("CLAUDE_API_KEY"))
INDIAN_KANOON_TOKEN = os.getenv("INDIAN_KANOON_TOKEN")

class SearchRequest(BaseModel):
    query: str

class ChatRequest(BaseModel):
    message: str
    history: list = []

class DraftRequest(BaseModel):
    doc_type: str
    court: str
    petitioner: str
    respondent: str
    facts: str
    grounds: str

@app.get("/")
def root():
    return {"status": "LexIndia API running"}

@app.post("/api/search")
def search(req: SearchRequest):
    try:
        response = requests.post(
            "https://api.indiankanoon.org/search/",
            data={"formInput": req.query, "pagenum": 0},
            headers={"Authorization": f"Token {INDIAN_KANOON_TOKEN}"},
            timeout=15
        )
        results = response.json().get("docs", [])[:10]
    except Exception as e:
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

    return {"query": req.query, "cases": results, "ai_summary": summary}

@app.post("/api/chat")
def chat(req: ChatRequest):
    messages = req.history + [{"role": "user", "content": req.message}]
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
    return {"reply": reply}

@app.post("/api/draft")
def draft(req: DraftRequest):
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
    return {"document": document}