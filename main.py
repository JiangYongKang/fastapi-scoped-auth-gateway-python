"""Local development entry point: ``python main.py``."""

from __future__ import annotations

import uvicorn

from auth_gateway.app import create_app
from auth_gateway.config import Settings

app = create_app(Settings.from_env())

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
