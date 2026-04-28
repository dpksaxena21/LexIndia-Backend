
class GoogleAuthRequest(BaseModel):
    access_token: str

@app.post("/api/auth/google")
def google_auth(req: GoogleAuthRequest):
    # Verify token with Google and get user info
    try:
        resp = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {req.access_token}"},
            timeout=10
        )
        if not resp.ok:
            raise HTTPException(status_code=401, detail="Invalid Google token")
        info = resp.json()
        email = info.get("email", "").lower().strip()
        name  = info.get("name", email.split("@")[0])
        if not email:
            raise HTTPException(status_code=400, detail="Could not get email from Google")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Upsert user — create if not exists, login if exists
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

