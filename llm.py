"""
StrikeARC — LLM Provider Configuration
======================================
GLM-5.3 (Z.AI) with retry logic.
Three-tier: planner (JSON, cheap) + analyst (medium) + report (max output).
Supports --no-llm mode for fully offline operation.
"""

import json
import os
import time
from typing import List, Optional

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage


def load_api_key() -> str:
    """Load GLM API key from environment or .env file."""
    key = os.environ.get("GLM_API_KEY", "").strip()
    if key:
        return key
    for env_path in [
        os.path.expanduser("~/.hermes/profiles/glm/.env"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"),
    ]:
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("GLM_API_KEY") and not line.startswith("#"):
                        val = line.split("=", 1)[1].strip().strip('"').strip("'")
                        if val:
                            print(f"[LLM] Loaded GLM_API_KEY from {env_path}")
                            return val
    print("[!] WARNING: No GLM_API_KEY found. Use --no-llm for offline mode.")
    return ""


API_KEY = load_api_key()
BASE_URL = os.environ.get("GLM_BASE_URL", "https://api.z.ai/api/coding/paas/v4")
MODEL = os.environ.get("GLM_MODEL", "glm-5.3")

# Three-tier LLM
_planner_llm: Optional[ChatOpenAI] = None      # JSON planning (2048 tokens)
_analyst_llm: Optional[ChatOpenAI] = None      # Attack path analysis (4096 tokens)
_report_llm: Optional[ChatOpenAI] = None       # Full report (8192 tokens)

# API call tracking
_llm_call_count: int = 0
_llm_fail_count: int = 0


def get_llm_stats() -> dict:
    return {"calls": _llm_call_count, "failures": _llm_fail_count}


def print_llm_stats():
    global _llm_call_count, _llm_fail_count
    if _llm_call_count > 0:
        print(f"\n[LLM] Total API calls: {_llm_call_count} (failures: {_llm_fail_count})")


def get_planner_llm() -> ChatOpenAI:
    global _planner_llm
    if _planner_llm is None:
        _planner_llm = ChatOpenAI(
            model=MODEL, api_key=API_KEY, base_url=BASE_URL,
            temperature=0, max_tokens=2048, request_timeout=90,
        )
    return _planner_llm


def get_analyst_llm() -> ChatOpenAI:
    global _analyst_llm
    if _analyst_llm is None:
        _analyst_llm = ChatOpenAI(
            model=MODEL, api_key=API_KEY, base_url=BASE_URL,
            temperature=0, max_tokens=4096, request_timeout=120,
        )
    return _analyst_llm


def get_report_llm() -> ChatOpenAI:
    global _report_llm
    if _report_llm is None:
        _report_llm = ChatOpenAI(
            model=MODEL, api_key=API_KEY, base_url=BASE_URL,
            temperature=0.1, max_tokens=8192, request_timeout=180,
        )
    return _report_llm


def llm_invoke(
    messages: list,
    max_retries: int = 8,
    fast_fail: bool = False,
    use_report_llm: bool = False,
    use_planner_llm: bool = False,
) -> str:
    """
    Retry wrapper for LLM calls with escalating backoff.
    Z.AI can reject ALL calls for minutes at a time.
    """
    global _llm_call_count, _llm_fail_count
    _llm_call_count += 1

    if use_planner_llm:
        active_llm = get_planner_llm()
    elif use_report_llm:
        active_llm = get_report_llm()
    else:
        active_llm = get_analyst_llm()

    if fast_fail:
        for attempt in range(3):
            try:
                response = active_llm.invoke(messages)
                return response.content
            except Exception as e:
                err = str(e)
                if "401" in err and attempt < 2:
                    time.sleep(3)
                    continue
                print(f"  LLM error (fast-fail {attempt+1}/3): {err[:80]}")
                _llm_fail_count += 1
                return ""
        _llm_fail_count += 1
        return ""

    wait_times = [5, 10, 15, 20, 30, 40, 60]
    for attempt in range(max_retries):
        try:
            response = active_llm.invoke(messages)
            return response.content
        except Exception as e:
            err_str = str(e)
            retryable = any(
                code in err_str
                for code in ["401", "429", "529", "503", "timed out",
                             "timeout", "Connection", "connection"]
            )
            if retryable and attempt < max_retries - 1:
                wait = wait_times[min(attempt, len(wait_times) - 1)]
                print(f"  LLM error (attempt {attempt+1}/{max_retries}), retry in {wait}s")
                time.sleep(wait)
                continue
            print(f"  LLM error (final): {err_str[:100]}")
            _llm_fail_count += 1
            return ""
    _llm_fail_count += 1
    return ""


def parse_llm_json(text: str) -> Optional[dict]:
    """Parse JSON from LLM output, handling markdown fences and preamble."""
    if not text:
        return None

    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines)

    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1:
        return None

    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        try:
            cleaned = text[start:end + 1].replace(",}", "}").replace(",]", "]")
            return json.loads(cleaned)
        except json.JSONDecodeError:
            return None


def test_connectivity() -> bool:
    try:
        resp = llm_invoke(
            [SystemMessage(content="You are a test."),
             HumanMessage(content="Respond with the word OK.")],
            fast_fail=True,
        )
        return bool(resp and "OK" in resp)
    except Exception:
        return False
