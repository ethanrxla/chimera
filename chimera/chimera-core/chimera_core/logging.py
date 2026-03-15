import json
import logging
from typing import Any, Optional

from .config import load_config


def setup_logging(level: Optional[str] = None) -> logging.Logger:
    config = load_config()
    log_level = (level or config.get("logging", {}).get("level", "INFO")).upper()

    logger = logging.getLogger("chimera")
    if logger.handlers:
        return logger

    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    handler.setFormatter(formatter)

    logger.setLevel(log_level)
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def log_event(logger: logging.Logger, level: str, message: str, **fields: Any) -> None:
    payload = {"message": message, **fields}
    text = json.dumps(payload, ensure_ascii=True, default=str)
    lvl = level.upper()
    if lvl == "DEBUG":
        logger.debug(text)
    elif lvl in {"WARNING", "WARN"}:
        logger.warning(text)
    elif lvl == "ERROR":
        logger.error(text)
    else:
        logger.info(text)
