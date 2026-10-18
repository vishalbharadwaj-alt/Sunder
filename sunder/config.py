"""Runtime configuration for SUNDER, loaded from environment / .env."""
from __future__ import annotations

import os
from dataclasses import dataclass

try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # dotenv is optional
    pass


@dataclass(frozen=True)
class Config:
    mode: str = os.getenv("FALKORDB_MODE", "embedded").strip().lower()
    host: str = os.getenv("FALKORDB_HOST", "localhost")
    port: int = int(os.getenv("FALKORDB_PORT", "6379"))
    username: str = os.getenv("FALKORDB_USERNAME", "")
    password: str = os.getenv("FALKORDB_PASSWORD", "")
    graph_name: str = os.getenv("GRAPH_NAME", "sunder")
    crown_jewel: str = os.getenv("CROWN_JEWEL", "prod-secrets-vault")
    llm_model: str = os.getenv("SUNDER_LLM_MODEL", "gpt-4o-mini")
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_base_url: str = os.getenv("OPENAI_BASE_URL", "")  # any OpenAI-compatible endpoint


CONFIG = Config()
