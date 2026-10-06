import os
import re
import hashlib
import sqlite3
import datetime
import json
import httpx
from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

app = FastAPI(title="TokenProxy Engine con SQLite")

# Permitir que el frontend de hercules.app consulte el backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_FILE = "tokenproxy.db"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_API_KEY = os.getenv("OPENROUTER_API_KEY", "")

# -------------------------------------------------------------
# Base de datos SQLite
# -------------------------------------------------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # 1. Métricas globales acumuladas
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS summary_metrics (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            total_requests INTEGER DEFAULT 0,
            raw_characters INTEGER DEFAULT 0,
            compressed_characters INTEGER DEFAULT 0,
            tokens_saved INTEGER DEFAULT 0,
            cache_hits INTEGER DEFAULT 0,
            dollars_saved REAL DEFAULT 0.0
        )
    """)
    cursor.execute("INSERT OR IGNORE INTO summary_metrics (id) VALUES (1)")
    
    # 2. Historial de cada petición
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS request_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            client_ip TEXT,
            model_used TEXT,
            orig_chars INTEGER,
            comp_chars INTEGER,
            tokens_saved INTEGER,
            cache_hit INTEGER,
            estimated_usd_saved REAL
        )
    """)
    
    # 3. Caché de respuestas idénticas
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS response_cache (
            cache_key TEXT PRIMARY KEY,
            response_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# -------------------------------------------------------------
# Algoritmo de compresión sintáctica
# -------------------------------------------------------------
def compress_text(text: str) -> str:
    patterns = [
        r"(?i)\b(por favor|amablemente|podrías|serías tan amable de)\b",
        r"(?i)\b(please|kindly|could you please|be sure to)\b",
        r"(?i)\b(como un modelo de lenguaje|as an ai language model)\b",
    ]
    for p in patterns:
        text = re.sub(p, "", text)
    text = re.sub(r"[ \t]+", " ", text)
    return re.sub(r"\n\s*\n+", "\n\n", text).strip()

# -------------------------------------------------------------
# Endpoints
# -------------------------------------------------------------
@app.get("/api/metrics")
async def get_metrics():
    """Consulta la base de datos para alimentar el dashboard en Hercules."""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM summary_metrics WHERE id = 1")
    summary = dict(cursor.fetchone())
    
    cursor.execute("""
        SELECT timestamp, model_used, tokens_saved, cache_hit, estimated_usd_saved 
        FROM request_logs 
        ORDER BY id DESC LIMIT 10
    """)
    summary["recent_logs"] = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return JSONResponse(content=summary)

@app.post("/v1/chat/completions")
async def chat_proxy(request: Request, authorization: str = Header(None)):
    payload = await request.json()
    messages = payload.get("messages", [])
    if not messages:
        raise HTTPException(status_code=400, detail="Sin mensajes")

    client_ip = request.client.host if request.client else "unknown"
    now_str = datetime.datetime.utcnow().isoformat()

    orig_chars = sum(len(m.get("content", "")) for m in messages if isinstance(m.get("content"), str))

    # Compresión
    for m in messages:
        if isinstance(m.get("content"), str):
            m["content"] = compress_text(m["content"])

    comp_chars = sum(len(m.get("content", "")) for m in messages if isinstance(m.get("content"), str))
    saved_chars = max(0, orig_chars - comp_chars)
    saved_tokens = saved_chars // 4
    usd_saved = round(saved_tokens * 0.000002, 6)

    # Comprobar si existe en la caché de SQLite
    cache_key = hashlib.sha256(str(messages).encode()).hexdigest()
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT response_json FROM response_cache WHERE cache_key = ?", (cache_key,))
    cached_row = cursor.fetchone()
    
    if cached_row:
        cached_data = json.loads(cached_row["response_json"])
        cache_usd_saved = 0.0025
        
        cursor.execute("""
            UPDATE summary_metrics SET 
                total_requests = total_requests + 1,
                cache_hits = cache_hits + 1,
                dollars_saved = dollars_saved + ?
            WHERE id = 1
        """, (cache_usd_saved,))
        
        cursor.execute("""
            INSERT INTO request_logs 
            (timestamp, client_ip, model_used, orig_chars, comp_chars, tokens_saved, cache_hit, estimated_usd_saved)
            VALUES (?, ?, ?, ?, ?, ?, 1, ?)
        """, (now_str, client_ip, payload.get("model", "cached"), orig_chars, comp_chars, saved_tokens, cache_usd_saved))
        
        conn.commit()
        conn.close()
        
        cached_data["cached_by_proxy"] = True
        return JSONResponse(content=cached_data)

    # Si no está en caché, llamar al modelo upstream
    key = authorization.replace("Bearer ", "") if authorization else DEFAULT_API_KEY
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}

    target_model = payload.get("model")
    if target_model in ["auto", "smart-route", None]:
        target_model = "google/gemini-1.5-flash"
        payload["model"] = target_model

    async with httpx.AsyncClient(timeout=60.0) as client:
        upstream = await client.post(OPENROUTER_URL, json=payload, headers=headers)

    if upstream.status_code != 200:
        conn.close()
        return JSONResponse(status_code=upstream.status_code, content=upstream.json())

    data = upstream.json()

    # Guardar en SQLite y actualizar estadísticas
    cursor.execute("""
        INSERT OR REPLACE INTO response_cache (cache_key, response_json, created_at)
        VALUES (?, ?, ?)
    """, (cache_key, json.dumps(data), now_str))

    cursor.execute("""
        UPDATE summary_metrics SET 
            total_requests = total_requests + 1,
            raw_characters = raw_characters + ?,
            compressed_characters = compressed_characters + ?,
            tokens_saved = tokens_saved + ?,
            dollars_saved = dollars_saved + ?
        WHERE id = 1
    """, (orig_chars, comp_chars, saved_tokens, usd_saved))

    cursor.execute("""
        INSERT INTO request_logs 
        (timestamp, client_ip, model_used, orig_chars, comp_chars, tokens_saved, cache_hit, estimated_usd_saved)
        VALUES (?, ?, ?, ?, ?, ?, 0, ?)
    """, (now_str, client_ip, target_model, orig_chars, comp_chars, saved_tokens, usd_saved))

    conn.commit()
    conn.close()

    data["proxy_savings"] = {
        "tokens_saved": saved_tokens,
        "estimated_usd_saved": usd_saved
    }
    return JSONResponse(content=data)
