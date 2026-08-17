from __future__ import annotations

import os
import socket
from typing import Any

from fastapi import FastAPI

VERSION = "0.5.10"
app = FastAPI(title="Hermes Node Agent", version=VERSION)


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "hermes-node-agent",
        "version": VERSION,
        "node": os.getenv("HERMES_AGENT_NAME", socket.gethostname()),
        "mode": "foundation",
        "execution_enabled": False,
        "capabilities": [],
    }
