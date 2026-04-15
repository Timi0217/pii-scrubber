"""PII Scrubber — lightweight PII detection and redaction service.

Scans text for common PII patterns (SSN, email, phone, credit card, API keys)
and redacts them. Designed to be used as middleware for AI agents that may
accidentally leak sensitive data in their responses.

Deploy via Chekk:
    POST https://chekk.dev/api/v1/deploy
    {"github_url": "https://github.com/Timi0217/pii-scrubber"}
"""

import re
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(
    title="PII Scrubber",
    description="Detect and redact PII from text — SSN, email, phone, credit cards, API keys",
    version="1.0.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── PII Patterns ──────────────────────────────────────────────────────
PII_PATTERNS = {
    "ssn": {
        "pattern": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "replacement": "[SSN REDACTED]",
        "description": "Social Security Number",
    },
    "email": {
        "pattern": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        "replacement": "[EMAIL REDACTED]",
        "description": "Email address",
    },
    "phone": {
        "pattern": re.compile(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        "replacement": "[PHONE REDACTED]",
        "description": "Phone number",
    },
    "credit_card": {
        "pattern": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
        "replacement": "[CREDIT CARD REDACTED]",
        "description": "Credit card number",
    },
    "api_key": {
        "pattern": re.compile(
            r"\b(?:sk-[a-zA-Z0-9]{20,}|"
            r"ghp_[a-zA-Z0-9]{36}|"
            r"gho_[a-zA-Z0-9]{36}|"
            r"AIza[a-zA-Z0-9_-]{35}|"
            r"AKIA[A-Z0-9]{12,24}|"
            r"xox[bpas]-[a-zA-Z0-9-]+)\b"
        ),
        "replacement": "[API KEY REDACTED]",
        "description": "API key or token",
    },
    "password_in_text": {
        "pattern": re.compile(
            r"(?i)(?:password|passwd|pwd|secret|token)[\s:=]+['\"]?([^\s'\"]{4,})['\"]?"
        ),
        "replacement": "[CREDENTIAL REDACTED]",
        "description": "Password or secret in text",
    },
    "ip_address": {
        "pattern": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "replacement": "[IP REDACTED]",
        "description": "IP address",
    },
}


# ── Models ────────────────────────────────────────────────────────────
class ScrubRequest(BaseModel):
    text: str
    categories: list[str] | None = None  # None = scrub all


class ScrubResponse(BaseModel):
    scrubbed_text: str
    detections: list[dict]
    total_redactions: int


class DetectRequest(BaseModel):
    text: str
    categories: list[str] | None = None


class DetectResponse(BaseModel):
    has_pii: bool
    detections: list[dict]
    total_found: int


# ── Routes ────────────────────────────────────────────────────────────

from fastapi.responses import PlainTextResponse
from pathlib import Path


@app.get("/llms.txt", response_class=PlainTextResponse)
@app.get("/.well-known/llms.txt", response_class=PlainTextResponse)
def llms_txt():
    return (Path(__file__).parent / "llms.txt").read_text()


@app.get("/")
def home():
    return {
        "service": "PII Scrubber",
        "version": "1.0.0",
        "endpoints": {
            "POST /scrub": "Detect and redact PII from text",
            "POST /detect": "Detect PII without redacting",
            "GET /patterns": "List supported PII patterns",
        },
    }


@app.post("/scrub", response_model=ScrubResponse)
def scrub(req: ScrubRequest):
    """Detect and redact all PII from the input text."""
    text = req.text
    active = req.categories or list(PII_PATTERNS.keys())
    detections = []

    for cat_id in active:
        if cat_id not in PII_PATTERNS:
            continue
        info = PII_PATTERNS[cat_id]
        matches = info["pattern"].findall(text)
        for match in matches:
            match_text = match if isinstance(match, str) else match[0] if match else ""
            if match_text:
                detections.append({
                    "category": cat_id,
                    "description": info["description"],
                    "value_preview": match_text[:4] + "***",
                })
        text = info["pattern"].sub(info["replacement"], text)

    return ScrubResponse(
        scrubbed_text=text,
        detections=detections,
        total_redactions=len(detections),
    )


@app.post("/detect", response_model=DetectResponse)
def detect(req: DetectRequest):
    """Detect PII in text without redacting it."""
    active = req.categories or list(PII_PATTERNS.keys())
    detections = []

    for cat_id in active:
        if cat_id not in PII_PATTERNS:
            continue
        info = PII_PATTERNS[cat_id]
        matches = info["pattern"].findall(req.text)
        for match in matches:
            match_text = match if isinstance(match, str) else match[0] if match else ""
            if match_text:
                detections.append({
                    "category": cat_id,
                    "description": info["description"],
                    "value_preview": match_text[:4] + "***",
                })

    return DetectResponse(
        has_pii=len(detections) > 0,
        detections=detections,
        total_found=len(detections),
    )


@app.get("/patterns")
def patterns():
    """List all supported PII detection patterns."""
    return {
        "patterns": {
            cat_id: {
                "description": info["description"],
                "replacement": info["replacement"],
            }
            for cat_id, info in PII_PATTERNS.items()
        }
    }
