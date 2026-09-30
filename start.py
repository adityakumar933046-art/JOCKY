"""
JOCKY Central Production Server Runner.
Dynamically binds to the cloud provider's assigned PORT ($PORT on Render/Fly/Heroku, default 8000).
Gracefully initializes database schema, seeds default accounts, and boots Uvicorn ASGI server.
"""

import os
import sys

if __name__ == "__main__":
    raw_port = os.environ.get("PORT", "8000")
    try:
        port = int(raw_port)
    except ValueError:
        port = 8000

    host = os.environ.get("HOST", "0.0.0.0")
    env = os.environ.get("ENVIRONMENT", os.environ.get("JOCKY_ENV", "production"))

    print("=" * 70, flush=True)
    print("  JOCKY Central Forensic Platform - Production Server Bootloader", flush=True)
    print(f"  Mode        : {env}", flush=True)
    print(f"  Binding to  : {host}:{port}", flush=True)
    print("=" * 70, flush=True)

    # Pre-flight database check and schema initialization
    try:
        print("[JOCKY-BOOT] Initializing database tables and default seed accounts...", flush=True)
        from server.database import init_db
        init_db()
        print("[JOCKY-BOOT] Database initialization verified.", flush=True)
    except Exception as exc:
        print(f"[JOCKY-BOOT] WARNING: Database auto-init encountered an error: {exc}", flush=True)
        print("[JOCKY-BOOT] Proceeding with server boot...", flush=True)

    # Launch ASGI server
    import uvicorn
    print(f"[JOCKY-BOOT] Starting Uvicorn ASGI listener on {host}:{port}...", flush=True)
    uvicorn.run(
        "server.main:app",
        host=host,
        port=port,
        workers=1,
        log_level="info",
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
