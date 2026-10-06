"""
main.py - TokenProxy Multi-Tenant (BYOK: Bring Your Own Key)
FastAPI + SQLite Multi-Cliente + Autenticación + Proxy LLM
"""

import os
import re
import hashlib
import secrets
import sqlite3
import datetime
import json
import httpx
from fastapi import FastAPI, Request, Header, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

app = FastAPI(
    title="TokenProxy Multi-Tenant Engine",
    description="Gateway LLM multi-cliente con compresión y BYOK",
    version="2.0.0"
)

# Permitir conexiones desde hercules.app y local
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_FILE = "tokenproxy.db"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_ROUTED_MODEL = "meta-llama/llama-3.1-8b-instruct:free"

# -------------------------------------------------------------
# Base de Datos SQLite Multi-Tenant
# -------------------------------------------------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # 1. Tabla de Usuarios / Cuentas de Clientes
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tenants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            proxy_key TEXT UNIQUE NOT NULL,
            upstream_api_key TEXT,
            created_at TEXT NOT NULL
        )
    """)

    # 2. Métricas agregadas por Cliente
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tenant_metrics (
            tenant_id INTEGER PRIMARY KEY,
            total_requests INTEGER DEFAULT 0,
            raw_characters INTEGER DEFAULT 0,
            compressed_characters INTEGER DEFAULT 0,
            tokens_saved INTEGER DEFAULT 0,
            cache_hits INTEGER DEFAULT 0,
            dollars_saved REAL DEFAULT 0.0,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id)
        )
    """)

    # 3. Log de peticiones por Cliente
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS request_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            client_ip TEXT,
            model_used TEXT,
            orig_chars INTEGER,
            comp_chars INTEGER,
            tokens_saved INTEGER,
            cache_hit INTEGER,
            estimated_usd_saved REAL,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id)
        )
    """)

    # 4. Caché de respuestas aislada por Cliente
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS response_cache (
            tenant_id INTEGER NOT NULL,
            cache_key TEXT NOT NULL,
            response_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, cache_key),
            FOREIGN KEY (tenant_id) REFERENCES tenants(id)
        )
    """)

    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def compress_text(text: str) -> str:
    patterns = [
        r"(?i)\b(por favor|amablemente|podrías|serías tan amable de)\b",
        r"(?i)\b(please|kindly|could you please|be sure to)\b",
        r"(?i)\b(como un modelo de lenguaje de ia|como un modelo de lenguaje|as an ai language model)\b",
    ]
    for pattern in patterns:
        text = re.sub(pattern, "", text)
    text = re.sub(r"[ \t]+", " ", text)
    return re.sub(r"\n\s*\n+", "\n\n", text).strip()

# -------------------------------------------------------------
# Endpoints de Autenticación y Cuentas de Clientes
# -------------------------------------------------------------

@app.get("/")
async def root():
    return {"status": "online", "mode": "multi-tenant", "version": "2.0.0"}

@app.post("/api/register")
async def register(payload: dict):
    """Crea una nueva cuenta de cliente con su propia proxy_key."""
    email = payload.get("email", "").strip().lower()
    password = payload.get("password", "")
    upstream_key = payload.get("upstream_api_key", "").strip()

    if not email or not password:
        raise HTTPException(status_code=400, detail="Email y contraseña requeridos.")

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM tenants WHERE email = ?", (email,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Este correo ya está registrado.")

    new_proxy_key = f"tk_live_{secrets.token_hex(16)}"
    now_str = datetime.datetime.utcnow().isoformat()

    cursor.execute("""
        INSERT INTO tenants (email, password_hash, proxy_key, upstream_api_key, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (email, hash_pw(password), new_proxy_key, upstream_key, now_str))
    
    tenant_id = cursor.lastrowid
    cursor.execute("INSERT INTO tenant_metrics (tenant_id) VALUES (?)", (tenant_id,))

    conn.commit()
    conn.close()

    return {
        "status": "success",
        "email": email,
        "proxy_key": new_proxy_key,
        "upstream_configured": bool(upstream_key)
    }

@app.post("/api/login")
async def login(payload: dict):
    """Inicio de sesión para acceder al dashboard privado del cliente."""
    email = payload.get("email", "").strip().lower()
    password = payload.get("password", "")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, email, proxy_key, upstream_api_key 
        FROM tenants 
        WHERE email = ? AND password_hash = ?
    """, (email, hash_pw(password)))
    user = cursor.fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=401, detail="Credenciales incorrectas.")

    return {
        "status": "success",
        "email": user["email"],
        "proxy_key": user["proxy_key"],
        "has_upstream_key": bool(user["upstream_api_key"])
    }

@app.post("/api/settings/upstream-key")
async def set_upstream_key(payload: dict, authorization: str = Header(None)):
    """Permite al cliente guardar o actualizar su API key propia de OpenRouter."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Token no provisto.")
    
    proxy_key = authorization.replace("Bearer ", "").strip()
    new_upstream_key = payload.get("upstream_api_key", "").strip()

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE tenants SET upstream_api_key = ? WHERE proxy_key = ?", (new_upstream_key, proxy_key))
    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Cuenta no encontrada.")

    conn.commit()
    conn.close()
    return {"status": "success", "message": "API key de OpenRouter actualizada con éxito."}

@app.get("/api/metrics")
async def get_metrics(authorization: str = Header(None)):
    """Devuelve las métricas exclusivas del cliente autenticado con su proxy_key."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Cabecera Authorization requerida.")
    
    proxy_key = authorization.replace("Bearer ", "").strip()
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT id, email, proxy_key, upstream_api_key FROM tenants WHERE proxy_key = ?", (proxy_key,))
    tenant = cursor.fetchone()
    if not tenant:
        conn.close()
        raise HTTPException(status_code=401, detail="API key de proxy inválida.")

    tenant_id = tenant["id"]
    cursor.execute("SELECT * FROM tenant_metrics WHERE tenant_id = ?", (tenant_id,))
    metrics = dict(cursor.fetchone() or {})

    cursor.execute("""
        SELECT timestamp, model_used, tokens_saved, cache_hit, estimated_usd_saved 
        FROM request_logs 
        WHERE tenant_id = ? 
        ORDER BY id DESC LIMIT 10
    """, (tenant_id,))
    metrics["recent_logs"] = [dict(row) for row in cursor.fetchall()]
    metrics["email"] = tenant["email"]
    metrics["proxy_key"] = tenant["proxy_key"]
    metrics["has_upstream_key"] = bool(tenant["upstream_api_key"])

    conn.close()
    return JSONResponse(content=metrics)

# -------------------------------------------------------------
# Endpoints de Compatibilidad (GET /models)
# -------------------------------------------------------------
@app.get("/v1/models")
@app.get("/models")
async def list_models():
    return {
        "object": "list",
        "data": [
            {"id": "smart-route", "object": "model", "owned_by": "tokenproxy"},
            {"id": "meta-llama/llama-3.1-8b-instruct:free", "object": "model", "owned_by": "meta"}
        ]
    }

# -------------------------------------------------------------
# Gateway Proxy de Inferencia Multi-Tenant
# -------------------------------------------------------------
@app.post("/v1/chat/completions")
@app.post("/chat/completions")
@app.post("/v1/v1/chat/completions")
async def chat_proxy(request: Request, authorization: str = Header(None)):
    """
    El cliente envía su proxy_key en el header 'Authorization: Bearer tk_live_...'
    El proxy busca su cuenta, usa la API Key de OpenRouter de ESE cliente y persiste su ahorro.
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header. Use Bearer tk_live_...")

    client_proxy_key = authorization.replace("Bearer ", "").strip()

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, upstream_api_key FROM tenants WHERE proxy_key = ?", (client_proxy_key,))
    tenant = cursor.fetchone()

    if not tenant:
        conn.close()
        raise HTTPException(status_code=401, detail="Proxy API key inválida. Verifica tu credencial en el dashboard.")

    tenant_id = tenant["id"]
    upstream_key = tenant["upstream_api_key"]

    if not upstream_key:
        conn.close()
        raise HTTPException(
            status_code=400,
            detail="No has configurado tu propia API Key de OpenRouter en tu cuenta. Inicia sesión en el portal para añadirla."
        )

    payload = await request.json()
    messages = payload.get("messages", [])
    if not messages:
        conn.close()
        raise HTTPException(status_code=400, detail="No messages provided.")

    client_ip = request.client.host if request.client else "unknown"
    now_str = datetime.datetime.utcnow().isoformat()

    # 1. Medir y comprimir
    orig_chars = sum(len(m.get("content", "")) for m in messages if isinstance(m.get("content"), str))
    for m in messages:
        if isinstance(m.get("content"), str):
            m["content"] = compress_text(m["content"])
    comp_chars = sum(len(m.get("content", "")) for m in messages if isinstance(m.get("content"), str))
    saved_chars = max(0, orig_chars - comp_chars)
    saved_tokens = saved_chars // 4
    usd_saved = round(saved_tokens * 0.000002, 6)

    # 2. Caché persistente del cliente
    cache_key = hashlib.sha256(str(messages).encode()).hexdigest()
    cursor.execute("SELECT response_json FROM response_cache WHERE tenant_id = ? AND cache_key = ?", (tenant_id, cache_key))
    cached_row = cursor.fetchone()

    if cached_row:
        cached_data = json.loads(cached_row["response_json"])
        cache_usd_saved = 0.0025
        cursor.execute("""
            UPDATE tenant_metrics SET 
                total_requests = total_requests + 1,
                cache_hits = cache_hits + 1,
                dollars_saved = dollars_saved + ?
            WHERE tenant_id = ?
        """, (cache_usd_saved, tenant_id))

        cursor.execute("""
            INSERT INTO request_logs 
            (tenant_id, timestamp, client_ip, model_used, orig_chars, comp_chars, tokens_saved, cache_hit, estimated_usd_saved)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
        """, (tenant_id, now_str, client_ip, payload.get("model", "cached"), orig_chars, comp_chars, saved_tokens, cache_usd_saved))

        conn.commit()
        conn.close()
        cached_data["cached_by_proxy"] = True
        return JSONResponse(content=cached_data)

    # 3. Preparar petición a OpenRouter con la clave privada DEL CLIENTE
    headers = {
        "Authorization": f"Bearer {upstream_key}",
        "Content-Type": "application/json"
    }

    target_model = payload.get("model")
    if target_model in ["auto", "smart-route", None]:
        target_model = DEFAULT_ROUTED_MODEL
    payload["model"] = target_model

    async with httpx.AsyncClient(timeout=60.0) as client:
        upstream = await client.post(OPENROUTER_URL, json=payload, headers=headers)

    if upstream.status_code != 200:
        conn.close()
        return JSONResponse(status_code=upstream.status_code, content=upstream.json())

    data = upstream.json()

    # 4. Guardar en la caché y métricas aisladas de este cliente
    cursor.execute("""
        INSERT OR REPLACE INTO response_cache (tenant_id, cache_key, response_json, created_at)
        VALUES (?, ?, ?, ?)
    """, (tenant_id, cache_key, json.dumps(data), now_str))

    cursor.execute("""
        UPDATE tenant_metrics SET 
            total_requests = total_requests + 1,
            raw_characters = raw_characters + ?,
            compressed_characters = compressed_characters + ?,
            tokens_saved = tokens_saved + ?,
            dollars_saved = dollars_saved + ?
        WHERE tenant_id = ?
    """, (orig_chars, comp_chars, saved_tokens, usd_saved, tenant_id))

    cursor.execute("""
        INSERT INTO request_logs 
        (tenant_id, timestamp, client_ip, model_used, orig_chars, comp_chars, tokens_saved, cache_hit, estimated_usd_saved)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
    """, (tenant_id, now_str, client_ip, target_model, orig_chars, comp_chars, saved_tokens, usd_saved))

    conn.commit()
    conn.close()

    data["proxy_savings"] = {
        "tokens_saved": saved_tokens,
        "estimated_usd_saved": usd_saved
    }
    return JSONResponse(content=data)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
