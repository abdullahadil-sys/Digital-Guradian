"""
Digital Guardian - LLM Service (Generation Layer)

This module is the ONLY place that talks to a large language model
provider. It exposes one method, `LLMService.generate_analysis(...)`,
so that swapping providers (Anthropic <-> OpenAI <-> any future
provider) never requires touching the RAG orchestration or API layer.

Design goals:
- Provider abstraction: `LLM_PROVIDER` env var selects "anthropic",
  "openai", or "none".
- Safe fallback: if no provider is configured, no API key is present,
  or the live call fails for any reason (network, auth, malformed
  response), the service transparently falls back to a deterministic,
  rule-based heuristic analyzer. The application NEVER crashes and
  NEVER blocks on a missing/failed LLM call.
- Never trusts the LLM blindly: the JSON returned by the model is
  strictly validated and clamped before it is used.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests

from app.config import Settings

logger = logging.getLogger("digital_guardian.llm")

SYSTEM_PROMPT = """You are Digital Guardian, a defensive cybersecurity analysis engine embedded \
in a scam and fraud detection assistant. You will be given a user-submitted message (email, SMS, \
social media message, or link text) plus a set of TRUSTED, RETRIEVED scam-pattern references. \
Analyze the message using the retrieved references as grounding context.

Rules you must always follow:
- Never request or suggest the user share passwords, OTPs, PINs, or full financial credentials.
- Never encourage clicking suspicious links.
- Always encourage independent verification through official channels.
- Never claim something is 100% safe or 100% fraudulent unless the evidence is truly conclusive; \
  otherwise express calibrated uncertainty.
- Respond with STRICT JSON ONLY, matching this schema, and nothing else (no markdown fences, no prose \
  outside the JSON object):

{
  "risk_score": <integer 0-100>,
  "risk_level": "LOW" | "MEDIUM" | "HIGH",
  "verdict": "<one sentence verdict>",
  "explanation": "<2-4 sentence explanation grounded in the retrieved references and message content>",
  "red_flags": ["<short red flag>", ...],
  "safe_actions": ["<short recommended safe action>", ...],
  "uncertainty_note": "<null, or a short note if evidence is genuinely inconclusive>"
}
"""


@dataclass
class LLMAnalysisResult:
    risk_score: int
    risk_level: str
    verdict: str
    explanation: str
    red_flags: List[str] = field(default_factory=list)
    safe_actions: List[str] = field(default_factory=list)
    uncertainty_note: Optional[str] = None
    mode: str = "heuristic"  # "llm" or "heuristic"


# ---------------------------------------------------------------------------
# Heuristic fallback (no LLM required)
# ---------------------------------------------------------------------------

_HIGH_WEIGHT_TERMS = {
    "otp": 22, "one-time password": 22, "one time password": 22, "pin": 18,
    "password": 18, "verification code": 20, "cvv": 22, "card number": 20,
    "wire transfer": 16, "gift card": 16, "crypto": 12, "bitcoin": 12,
    "suspended": 14, "account will be closed": 16, "act now": 12,
    "urgent": 10, "immediately": 8, "click here": 12, "verify your account": 14,
    "confirm your identity": 12, "limited time": 8, "guaranteed": 10,
    "winner": 10, "you have won": 14, "prize": 8, "refund": 8,
    "tax": 6, "irs": 10, "customs fee": 10, "processing fee": 12,
    "remote access": 14, "team viewer": 14, "anydesk": 14, "social security": 18,
}

_URL_PATTERN = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
_SHORTENER_PATTERN = re.compile(r"(bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|ow\.ly)", re.IGNORECASE)


def _heuristic_analysis(message: str, retrieved_indicators: List[str]) -> LLMAnalysisResult:
    """
    Deterministic, transparent scam-likelihood scorer used when no LLM
    provider is available. It combines keyword weighting, retrieved
    knowledge-base indicators, and simple URL heuristics.
    """
    text = message.lower()
    score = 0
    red_flags: List[str] = []

    for term, weight in _HIGH_WEIGHT_TERMS.items():
        if term in text:
            score += weight
            red_flags.append(term.title())

    # Cross-reference retrieved knowledge-base indicators for extra corroboration.
    for indicator in retrieved_indicators:
        if indicator.lower() in text and indicator.title() not in red_flags:
            score += 6
            red_flags.append(indicator.title())

    urls = _URL_PATTERN.findall(message)
    if urls:
        score += 8
        red_flags.append("Contains a link")
        if any(_SHORTENER_PATTERN.search(u) for u in urls):
            score += 10
            red_flags.append("Shortened/obscured URL")

    score = max(0, min(100, score))

    if score >= 65:
        risk_level = "HIGH"
        verdict = "This message shows strong indicators of a scam. Do not click, pay, or share any sensitive information."
    elif score >= 30:
        risk_level = "MEDIUM"
        verdict = "This message has some suspicious characteristics. Proceed with caution and verify independently."
    else:
        risk_level = "LOW"
        verdict = "This message does not show strong scam indicators based on available signals, but no message can be guaranteed 100% safe."

    uncertainty_note = None
    if 25 <= score <= 45:
        uncertainty_note = (
            "The signals here are mixed. This heuristic assessment is not fully conclusive — "
            "treat the message with caution and verify through an official channel before acting."
        )

    explanation = (
        f"Heuristic keyword and pattern analysis identified {len(red_flags)} notable signal(s) in the message. "
        "This assessment was produced by the built-in fallback analyzer because no live LLM provider is currently "
        "configured, and is grounded in the retrieved trusted scam-pattern references."
    )

    safe_actions = [
        "Do not click any links in the message",
        "Never share OTPs, PINs, passwords, or full card numbers",
        "Verify the sender through the organization's official website or app",
        "Contact the organization directly using a number or address you already trust",
        "Report the message to your email/SMS provider or a national fraud reporting service",
    ]

    return LLMAnalysisResult(
        risk_score=score,
        risk_level=risk_level,
        verdict=verdict,
        explanation=explanation,
        red_flags=red_flags[:8] if red_flags else ["No strong keyword-based red flags detected"],
        safe_actions=safe_actions,
        uncertainty_note=uncertainty_note,
        mode="heuristic",
    )


# ---------------------------------------------------------------------------
# LLM-backed generation
# ---------------------------------------------------------------------------


def _build_user_prompt(message: str, retrieved_context: List[Dict]) -> str:
    context_block = "\n".join(
        f"- [{item['category']}] {item['title']}: {item['summary']}" for item in retrieved_context
    ) or "No closely matching trusted references were retrieved."

    return (
        f"RETRIEVED TRUSTED REFERENCES:\n{context_block}\n\n"
        f"USER-SUBMITTED MESSAGE TO ANALYZE:\n\"\"\"\n{message}\n\"\"\"\n\n"
        "Return only the JSON object described in the system prompt."
    )


def _parse_llm_json(raw_text: str) -> Dict:
    cleaned = raw_text.strip()
    cleaned = re.sub(r"^```(json)?", "", cleaned).strip()
    cleaned = re.sub(r"```$", "", cleaned).strip()
    return json.loads(cleaned)


def _validate_and_clamp(data: Dict) -> LLMAnalysisResult:
    risk_score = int(data.get("risk_score", 0))
    risk_score = max(0, min(100, risk_score))

    risk_level = str(data.get("risk_level", "")).upper()
    if risk_level not in {"LOW", "MEDIUM", "HIGH"}:
        # Derive from score if the model returned an invalid label — never trust blindly.
        risk_level = "HIGH" if risk_score >= 65 else "MEDIUM" if risk_score >= 30 else "LOW"

    verdict = str(data.get("verdict") or "Unable to determine a clear verdict from the available evidence.")
    explanation = str(data.get("explanation") or "No detailed explanation was provided.")
    red_flags = [str(x) for x in data.get("red_flags", []) if str(x).strip()][:10]
    safe_actions = [str(x) for x in data.get("safe_actions", []) if str(x).strip()][:10]
    uncertainty_note = data.get("uncertainty_note")
    uncertainty_note = str(uncertainty_note) if uncertainty_note else None

    if not safe_actions:
        safe_actions = [
            "Do not click any links in the message",
            "Never share OTPs, PINs, or passwords",
            "Verify through the organization's official channel",
        ]

    return LLMAnalysisResult(
        risk_score=risk_score,
        risk_level=risk_level,
        verdict=verdict,
        explanation=explanation,
        red_flags=red_flags or ["No specific red flags returned"],
        safe_actions=safe_actions,
        uncertainty_note=uncertainty_note,
        mode="llm",
    )


class LLMService:
    def __init__(self, settings: Settings):
        self._settings = settings

    def generate_analysis(self, message: str, retrieved_context: List[Dict], retrieved_indicators: List[str]) -> LLMAnalysisResult:
        if not self._settings.llm_enabled:
            logger.info("LLM disabled or unconfigured — using heuristic fallback analyzer.")
            return _heuristic_analysis(message, retrieved_indicators)

        try:
            if self._settings.llm_provider == "anthropic":
                raw = self._call_anthropic(message, retrieved_context)
            elif self._settings.llm_provider == "openai":
                raw = self._call_openai(message, retrieved_context)
            else:
                return _heuristic_analysis(message, retrieved_indicators)

            parsed = _parse_llm_json(raw)
            return _validate_and_clamp(parsed)

        except Exception:  # noqa: BLE001 - any provider/network/parsing failure triggers safe fallback
            logger.exception("LLM generation failed — falling back to heuristic analyzer.")
            result = _heuristic_analysis(message, retrieved_indicators)
            result.uncertainty_note = (
                (result.uncertainty_note + " " if result.uncertainty_note else "")
                + "Note: the live AI analysis service was unavailable, so this result comes from the built-in "
                "fallback analyzer."
            )
            return result

    def _call_anthropic(self, message: str, retrieved_context: List[Dict]) -> str:
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": self._settings.anthropic_api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": self._settings.anthropic_model,
                "max_tokens": 800,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": _build_user_prompt(message, retrieved_context)}],
            },
            timeout=20,
        )
        response.raise_for_status()
        data = response.json()
        text_blocks = [b["text"] for b in data.get("content", []) if b.get("type") == "text"]
        return "\n".join(text_blocks)

    def _call_openai(self, message: str, retrieved_context: List[Dict]) -> str:
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self._settings.openai_api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self._settings.openai_model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": _build_user_prompt(message, retrieved_context)},
                ],
                "temperature": 0.2,
                "response_format": {"type": "json_object"},
            },
            timeout=20,
        )
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]
