from __future__ import annotations

import ipaddress
import re
from typing import Dict, Iterable, List


_COMMON_TLDS = {"com", "org", "net", "edu", "gov", "io", "co", "us", "uk", "dev", "app", "xyz", "me"}
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|edu|gov|io|co|us|uk|dev|app|xyz|me)\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_targets_from_command(command: Iterable[str]) -> List[str]:
    targets: List[str] = []
    for index, arg in enumerate(command):
        if index == 0 or not isinstance(arg, str):
            continue
        candidate = arg.strip()
        if not candidate or candidate.startswith("-"):
            continue
        if candidate.startswith(("http://", "https://")):
            targets.append(candidate)
            continue
        if "/" in candidate or "\\" in candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
            targets.append(candidate)
            continue
        except ValueError:
            pass
        if "." in candidate:
            parts = candidate.split(".")
            if len(parts) >= 2 and parts[-1].lower() in _COMMON_TLDS:
                targets.append(candidate)
    return targets


def extract_targets_from_params(params: Dict[str, object], fields: Iterable[str]) -> List[str]:
    targets: List[str] = []
    for field in fields:
        value = params.get(field)
        if isinstance(value, str) and value.strip():
            if field == "targets":
                targets.extend(item.strip() for item in value.split(",") if item.strip())
            else:
                targets.append(value.strip())
    return targets


def extract_targets_from_text(text: str) -> List[str]:
    targets: List[str] = []
    seen: set[str] = set()
    for pattern in (_URL_RE, _DOMAIN_RE, _IP_RE):
        for match in pattern.findall(text or ""):
            if match not in seen:
                seen.add(match)
                targets.append(match)
    return targets
