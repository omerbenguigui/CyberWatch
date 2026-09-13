"""Environment-based configuration for CyberWatch."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_DEVELOPMENT_KEY = "dev-key-change-me"


@dataclass(frozen=True, slots=True)
class Settings:
    environment: str
    database_path: Path
    api_key: str
    allowed_origins: tuple[str, ...]

    @classmethod
    def from_environment(cls) -> Settings:
        environment = os.getenv("CYBERWATCH_ENV", "development").strip().lower()
        database_path = Path(
            os.getenv("CYBERWATCH_DATABASE_PATH", "data/cyberwatch.db")
        ).expanduser()
        api_key = os.getenv("CYBERWATCH_API_KEY", DEFAULT_DEVELOPMENT_KEY)
        origins = tuple(
            origin.strip()
            for origin in os.getenv("CYBERWATCH_ALLOWED_ORIGINS", "http://localhost:8000").split(
                ","
            )
            if origin.strip()
        )

        if environment == "production" and api_key == DEFAULT_DEVELOPMENT_KEY:
            raise RuntimeError("CYBERWATCH_API_KEY must be changed before running in production")

        return cls(
            environment=environment,
            database_path=database_path,
            api_key=api_key,
            allowed_origins=origins,
        )
