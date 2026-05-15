#!/usr/bin/env python3
"""
ai_analyzer.py — Provider-agnostic AI Reasoning Engine for CIS Audit Findings

Supports any LLM provider via LiteLLM:
  - Anthropic:  model="claude-sonnet-4-6",   api_key="sk-ant-..."
  - OpenAI:     model="gpt-4o",               api_key="sk-..."
  - Ollama:     model="ollama/llama3",         base_url="http://localhost:11434"
  - Azure:      model="azure/gpt-4o",          api_key="...", base_url="https://..."
  - Gemini:     model="gemini/gemini-1.5-pro", api_key="..."
  - Groq:       model="groq/llama3-70b-8192",  api_key="..."

Runs three structured passes:
  1. Per-finding risk enrichment (FAIL + MANUAL items)
  2. Attack chain correlation analysis
  3. Executive & technical narrative generation
"""

import json
import os
import sys
import time
import textwrap
from typing import Optional

try:
    import litellm
    litellm.suppress_debug_info = True
    litellm.set_verbose = False
    HAS_LITELLM = True
except ImportError:
    HAS_LITELLM = False

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_MODEL     = "claude-sonnet-4-6"
MAX_TOKENS        = 4096
MAX_TOKENS_ENRICH = 8192
ENRICH_BATCH_SIZE = 8

SYSTEM_PROMPT = textwrap.dedent("""
    You are a senior network security assessor with deep expertise across
    enterprise firewall platforms — Check Point Gaia, Palo Alto Networks PAN-OS,
    Fortinet FortiGate and FortiManager, and Cisco Firepower — as well as security
    frameworks including CIS Benchmarks, NIST CSF 2.0, ISO 27001, and PCI DSS.
    You analyse audit findings from FW AI Audit multi-vendor firewall security assessments
    and produce structured, actionable security intelligence.
    Respond ONLY with the JSON object requested — no preamble, no markdown fences,
    no commentary outside the JSON.
""").strip()


# ---------------------------------------------------------------------------
# AI config helper
# ---------------------------------------------------------------------------
AI_CALL_TIMEOUT = 120   # seconds — fail fast instead of waiting 600s

# Models that work without an API key
_NO_KEY_MODELS = ("ollama/", "huggingface/", "ollama_chat/")

# Per-provider limits for free-tier friendliness.
# batch_delay: seconds between enrichment batches
# max_enrich_tokens: caps MAX_TOKENS_ENRICH to stay under TPM limits
_PROVIDER_LIMITS: dict = {
    "groq/":   {"batch_delay": 65, "max_enrich_tokens": 2048},
    "ollama/": {"batch_delay":  0, "max_enrich_tokens": MAX_TOKENS_ENRICH},
    "claude-": {"batch_delay":  2, "max_enrich_tokens": MAX_TOKENS_ENRICH},
    "gpt-":    {"batch_delay":  2, "max_enrich_tokens": MAX_TOKENS_ENRICH},
}


class AIConfig:
    """Holds provider settings. Pass this through the analysis pipeline."""

    def __init__(self, model: str = DEFAULT_MODEL,
                 api_key: str = None,
                 base_url: str = None):
        self.model    = model or DEFAULT_MODEL
        self.api_key  = (api_key or _default_api_key(self.model)) or None
        self.base_url = base_url or None

    def validate(self):
        """Raise ValueError immediately if a required API key is missing.

        Each assessment session must supply its own key — no server-wide defaults.
        """
        needs_key = not any(self.model.lower().startswith(p) for p in _NO_KEY_MODELS)
        if needs_key and not self.api_key:
            m = self.model.lower()
            if "claude" in m:
                hint = "Anthropic API key (sk-ant-...)"
            elif m.startswith("gpt") or m.startswith("o1") or m.startswith("o3"):
                hint = "OpenAI API key (sk-...)"
            elif "groq" in m:
                hint = "Groq API key (gsk_...)"
            elif "gemini" in m:
                hint = "Google AI API key"
            else:
                hint = "API key for your provider"
            raise ValueError(
                f"No API key provided for model '{self.model}'. "
                f"Enter your {hint} in the AI API Key field in the assessment form."
            )

    def __repr__(self):
        masked = f"{self.api_key[:8]}..." if self.api_key else "None"
        return f"AIConfig(model={self.model}, api_key={masked}, base_url={self.base_url})"


def _default_api_key(model: str) -> Optional[str]:
    """
    Return a key from environment only as a development convenience.
    Production deployments should not set these env vars — every assessment
    session must supply its own key via the intake form.
    """
    m = (model or "").lower()
    if m.startswith("claude"):
        return os.environ.get("ANTHROPIC_API_KEY") or None
    if m.startswith("gpt") or m.startswith("o1") or m.startswith("o3"):
        return os.environ.get("OPENAI_API_KEY") or None
    if m.startswith("gemini"):
        return os.environ.get("GEMINI_API_KEY") or None
    if m.startswith("groq"):
        return os.environ.get("GROQ_API_KEY") or None
    if any(m.startswith(p) for p in _NO_KEY_MODELS):
        return None   # local models need no key
    return None       # unknown provider — require explicit key from user


# ---------------------------------------------------------------------------
# Core AI call — provider-agnostic via LiteLLM
def _extract_json(raw: str):
    """
    Robustly extract a JSON object or array from a model response that may
    contain preamble text, markdown fences, or trailing commentary.

    Strategy (in order):
    1. Direct parse of the stripped text.
    2. Extract content from any ```json … ``` or ``` … ``` block.
    3. Scan for the first { or [ and try json.loads from that position,
       walking forward until a valid parse or no candidates remain.
    """
    import re as _re

    text = raw.strip()

    # 1. Direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 2. Markdown code block extraction
    blocks = _re.findall(r"```(?:json)?\s*([\s\S]*?)```", text)
    for block in blocks:
        try:
            return json.loads(block.strip())
        except json.JSONDecodeError:
            pass

    # 3. Scan for first JSON-start character
    for i, ch in enumerate(text):
        if ch in ('{', '['):
            candidate = text[i:]
            # Try the full tail first, then progressively trim from the right
            for j in range(len(candidate), 0, -1):
                if candidate[j - 1] in ('}', ']'):
                    try:
                        return json.loads(candidate[:j])
                    except json.JSONDecodeError:
                        pass

    raise json.JSONDecodeError("No JSON found in model response", text, 0)


def _supports_json_mode(model: str) -> bool:
    """True for models known to support response_format=json_object reliably.

    Ollama is deliberately excluded — JSON mode breaks thinking models (Qwen3,
    DeepSeek-R1, etc.) by suppressing their output entirely. We rely on
    _extract_json() to handle verbose/markdown output from local models instead.
    """
    m = model.lower()
    return (m.startswith("gpt-") or m.startswith("o1") or m.startswith("o3")
            or m.startswith("azure/"))


# ---------------------------------------------------------------------------
def _call_ai(cfg: AIConfig, prompt: str,
             max_tokens: int = MAX_TOKENS, retries: int = 3) -> dict:
    """
    Call any LLM via LiteLLM and return parsed JSON dict.

    LiteLLM routes to the right provider SDK based on model prefix:
      claude-*    → Anthropic SDK
      gpt-* / o*  → OpenAI SDK
      ollama/*    → OpenAI-compat at base_url (default: localhost:11434)
      gemini/*    → Google Generative AI SDK
      azure/*     → Azure OpenAI SDK
      groq/*      → Groq SDK

    For local/weaker models that ignore JSON-only instructions, _extract_json()
    scans the full response for a valid JSON block rather than failing outright.
    """
    kwargs = dict(
        model=cfg.model,
        max_tokens=max_tokens,
        timeout=AI_CALL_TIMEOUT,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
    )
    if cfg.api_key:
        kwargs["api_key"] = cfg.api_key
    if cfg.base_url:
        kwargs["base_url"] = cfg.base_url

    # Request JSON mode only for providers that support it reliably.
    # Ollama is excluded — passing response_format silences thinking models
    # (Qwen3, DeepSeek-R1, etc.) entirely. _extract_json() handles messy output.
    if _supports_json_mode(cfg.model):
        kwargs["response_format"] = {"type": "json_object"}

    raw = ""
    for attempt in range(retries):
        try:
            response = litellm.completion(**kwargs)
            raw = (response.choices[0].message.content or "").strip()

            # Strip thinking-model reasoning blocks (<think>...</think>)
            import re as _re
            raw = _re.sub(r"<think>[\s\S]*?</think>", "", raw,
                          flags=_re.IGNORECASE).strip()

            if not raw:
                raise json.JSONDecodeError("Empty response from model", "", 0)

            return _extract_json(raw)

        except json.JSONDecodeError as e:
            if attempt == retries - 1:
                raise RuntimeError(
                    f"Model returned non-JSON (model={cfg.model}): {e}"
                    f"\nRaw: {raw[:400]}")
            time.sleep(2 ** attempt)

        except Exception as e:
            err = str(e).lower()
            is_rate_limit = "ratelimit" in err or "rate_limit" in err or "429" in err
            if attempt == retries - 1:
                if is_rate_limit:
                    raise RuntimeError(
                        f"Rate limit exceeded for {cfg.model}. "
                        "Try a smaller model (e.g. groq/llama-3.1-8b-instant), "
                        "wait a minute, or use a provider with higher limits."
                    ) from e
                raise
            wait = 60 if is_rate_limit else 2 ** attempt
            print(f"  [AI] {'Rate limit' if is_rate_limit else 'Error'} — "
                  f"retry {attempt + 1}/{retries} in {wait}s: {e}", file=sys.stderr)
            time.sleep(wait)


# ---------------------------------------------------------------------------
# Pass 1 — Per-finding enrichment
# ---------------------------------------------------------------------------
ENRICHMENT_SCHEMA = {
    "risk_level":          "Critical | High | Medium | Low",
    "business_impact":     "1-2 sentences explaining the business/operational risk",
    "attack_scenario":     "Concrete attack that this misconfiguration enables (who, how, what)",
    "remediation_effort":  "Low | Medium | High — effort to fix",
    "remediation_steps":   ["ordered list of Clish commands or GUI steps to remediate"],
    "priority_rank":       "integer 1-N across all findings (1 = fix first)",
    "cve_or_reference":    "Related CVE, NIST control, or framework reference if applicable",
}


def enrich_findings(cfg: AIConfig, findings: list, device_context: dict) -> list:
    """Batch-enrich FAIL and MANUAL findings with AI risk analysis."""
    actionable = [f for f in findings if f["status"] in ("FAIL", "MANUAL", "ERROR")]
    static     = [f for f in findings if f["status"] not in ("FAIL", "MANUAL", "ERROR")]

    if not actionable:
        return findings

    print(f"  [AI] Enriching {len(actionable)} findings with {cfg.model}...", flush=True)

    # Auto-detect per-provider limits (batch delay + max token cap)
    limits = {"batch_delay": 0, "max_enrich_tokens": MAX_TOKENS_ENRICH}
    for prefix, vals in _PROVIDER_LIMITS.items():
        if cfg.model.lower().startswith(prefix):
            limits = vals
            break
    batch_delay       = limits["batch_delay"]
    enrich_max_tokens = limits["max_enrich_tokens"]
    if enrich_max_tokens < MAX_TOKENS_ENRICH:
        print(f"  [AI] Token cap set to {enrich_max_tokens} for {cfg.model} (rate-limit friendly)",
              flush=True)

    enriched_map  = {}
    total_batches = (len(actionable) + ENRICH_BATCH_SIZE - 1) // ENRICH_BATCH_SIZE

    for i in range(0, len(actionable), ENRICH_BATCH_SIZE):
        batch     = actionable[i: i + ENRICH_BATCH_SIZE]
        batch_num = i // ENRICH_BATCH_SIZE + 1
        if i > 0 and batch_delay:
            print(f"  [AI]   Waiting {batch_delay}s (rate limit cooldown)...", flush=True)
            time.sleep(batch_delay)
        print(f"  [AI]   Batch {batch_num}/{total_batches} ({len(batch)} findings)...",
              flush=True)

        payload = [
            {
                "control_id":  f["control_id"],
                "description": f["description"],
                "level":       f["level"],
                "status":      f["status"],
                "expected":    f.get("expected"),
                "actual":      str(f.get("actual", ""))[:200],
                "notes":       f.get("notes", ""),
            }
            for f in batch
        ]

        prompt = f"""
Device context:
{json.dumps(device_context, indent=2)}

CIS Benchmark findings requiring analysis:
{json.dumps(payload, indent=2)}

For each finding produce a JSON object keyed by control_id matching this schema:
{json.dumps(ENRICHMENT_SCHEMA, indent=2)}

priority_rank must be globally consistent across all findings (1 = fix first).
Return format:
{{
  "1.1": {{ ... enrichment fields ... }},
  "2.2.1": {{ ... }},
  ...
}}
"""
        result = _call_ai(cfg, prompt, max_tokens=enrich_max_tokens)
        if isinstance(result, dict):
            enriched_map.update(result)
        else:
            print(f"  [AI]   Batch {batch_num} returned unexpected type {type(result).__name__} — skipping", file=sys.stderr)

    enriched = []
    for f in actionable:
        enrichment = enriched_map.get(f["control_id"], {})
        enriched.append({**f, "ai_analysis": enrichment})

    def sort_key(f):
        try:
            return int(f.get("ai_analysis", {}).get("priority_rank", 999))
        except (TypeError, ValueError):
            return 999

    enriched.sort(key=sort_key)
    return enriched + static


# ---------------------------------------------------------------------------
# Pass 2 — Business impact scoring
# ---------------------------------------------------------------------------
BUSINESS_IMPACT_SCHEMA = {
    "downtime_hours":       "integer — estimated hours of operational disruption if exploited",
    "breach_probability":   "Low | Medium | High — likelihood this finding leads to a data breach",
    "fine_exposure":        "string — estimated regulatory fine range, e.g. '€20,000–100,000 (GDPR Art.83)'",
    "continuity_impact":    "None | Low | Medium | High — impact on business continuity",
    "remediation_priority": "integer 1-N across all findings (1 = highest business risk reduction)",
}


def analyze_business_impact(cfg: AIConfig, findings: list, device_context: dict) -> list:
    """Add business_impact field to each FAIL/MANUAL finding via a dedicated AI pass."""
    actionable = [f for f in findings if f["status"] in ("FAIL", "MANUAL", "ERROR")]
    if not actionable:
        return findings

    print(f"  [AI] Pass 2: Business impact scoring ({len(actionable)} findings)...", flush=True)

    limits = {"batch_delay": 0, "max_enrich_tokens": MAX_TOKENS_ENRICH}
    for prefix, vals in _PROVIDER_LIMITS.items():
        if cfg.model.lower().startswith(prefix):
            limits = vals
            break

    impact_map: dict = {}
    total_batches = (len(actionable) + ENRICH_BATCH_SIZE - 1) // ENRICH_BATCH_SIZE

    for i in range(0, len(actionable), ENRICH_BATCH_SIZE):
        batch = actionable[i: i + ENRICH_BATCH_SIZE]
        batch_num = i // ENRICH_BATCH_SIZE + 1
        if i > 0 and limits["batch_delay"]:
            print(f"  [AI]   Waiting {limits['batch_delay']}s (rate limit cooldown)...", flush=True)
            time.sleep(limits["batch_delay"])
        print(f"  [AI]   Impact batch {batch_num}/{total_batches} ({len(batch)} findings)...",
              flush=True)

        payload = [
            {
                "control_id":    f["control_id"],
                "description":   f["description"],
                "status":        f["status"],
                "risk_level":    f.get("ai_analysis", {}).get("risk_level", "Unknown"),
                "attack_scenario": f.get("ai_analysis", {}).get("attack_scenario", ""),
            }
            for f in batch
        ]

        prompt = f"""
Device context:
{json.dumps(device_context, indent=2)}

Security findings requiring business impact analysis:
{json.dumps(payload, indent=2)}

For each finding, estimate the real-world business impact if the misconfiguration is exploited.
Be specific to the device context (industry, role). Use realistic figures, not worst-case.
Return a JSON object keyed by control_id:
{{
  "1.1": {json.dumps(BUSINESS_IMPACT_SCHEMA, indent=2)},
  ...
}}
"""
        try:
            result = _call_ai(cfg, prompt, max_tokens=limits["max_enrich_tokens"])
            if isinstance(result, dict):
                impact_map.update(result)
            else:
                print(f"  [AI]   Impact batch {batch_num} returned unexpected type {type(result).__name__} — skipping", file=sys.stderr)
        except Exception as e:
            print(f"  [AI]   Impact batch {batch_num} failed (non-fatal): {e}", flush=True)

    enriched = []
    for f in findings:
        if f.get("status") in ("FAIL", "MANUAL", "ERROR"):
            f = {**f, "business_impact": impact_map.get(f["control_id"], {})}
        enriched.append(f)
    return enriched


# ---------------------------------------------------------------------------
# Pass 3 — Attack chain correlation
# ---------------------------------------------------------------------------
CHAIN_SCHEMA = [
    {
        "chain_id":           "AC-01",
        "chain_name":         "Short descriptive name",
        "risk_level":         "Critical | High | Medium",
        "controls_involved":  ["list of control_ids"],
        "attack_narrative":   "Step-by-step how an attacker exploits this combination",
        "blast_radius":       "What an attacker can achieve if successful",
        "priority_fix_order": ["control_id in order — fix this one first to break the chain"],
    }
]


def analyze_attack_chains(cfg: AIConfig, findings: list, device_context: dict) -> list:
    """Identify compound attack chains from combinations of failures."""
    failures = [
        {
            "control_id":  f["control_id"],
            "description": f["description"],
            "status":      f["status"],
            "ai_risk":     f.get("ai_analysis", {}).get("risk_level", "Unknown"),
        }
        for f in findings if f["status"] in ("FAIL", "MANUAL")
    ]

    if len(failures) < 2:
        return []

    print("  [AI] Analyzing attack chains...", flush=True)

    prompt = f"""
Device context:
{json.dumps(device_context, indent=2)}

These security controls are FAILING or require MANUAL verification:
{json.dumps(failures, indent=2)}

Identify 2-5 meaningful ATTACK CHAINS — combinations of 2+ failures that together
create a significantly worse risk than each failure in isolation.

Return a JSON array matching this schema:
{json.dumps(CHAIN_SCHEMA, indent=2)}

If fewer than 2 meaningful chains exist, return: []
"""
    result = _call_ai(cfg, prompt, max_tokens=4096)
    if isinstance(result, list):
        return result
    for v in result.values():
        if isinstance(v, list):
            return v
    return []


# ---------------------------------------------------------------------------
# Pass 3 — Narrative generation
# ---------------------------------------------------------------------------
NARRATIVE_SCHEMA = {
    "overall_risk_rating": "Critical | High | Medium | Low",
    "compliance_score_interpretation": "1-2 sentences interpreting the numeric score",
    "executive_summary": {
        "headline":    "One-sentence assessment suitable for a board slide",
        "paragraph_1": "Business risk context — no technical jargon",
        "paragraph_2": "Most impactful gaps and their business consequence",
        "paragraph_3": "Recommended posture and urgency",
    },
    "technical_summary": {
        "paragraph_1": "Technical posture overview for security engineers",
        "paragraph_2": "Most critical technical findings and their root causes",
    },
    "top_5_priority_actions": [
        {
            "rank":          1,
            "action":        "What to do",
            "justification": "Why this is the top priority",
            "effort":        "Low | Medium | High",
            "impact":        "What risk this eliminates",
        }
    ],
    "positive_findings":      "What the organisation is doing well (from PASS results)",
    "assessment_limitations": "What MANUAL checks could not be automated and why they matter",
}


def generate_narrative(cfg: AIConfig, findings: list, attack_chains: list,
                       device_context: dict, stats: dict) -> dict:
    """Generate executive summary, technical summary, and priority actions."""
    print("  [AI] Generating narrative...", flush=True)

    failures = [f for f in findings if f["status"] == "FAIL"]
    manuals  = [f for f in findings if f["status"] == "MANUAL"]
    passes   = [f for f in findings if f["status"] == "PASS"]

    prompt = f"""
Assessment context:
{json.dumps(device_context, indent=2)}

Compliance statistics:
{json.dumps(stats, indent=2)}

Failing controls:
{json.dumps([{"control_id": f["control_id"], "description": f["description"],
              "risk": f.get("ai_analysis", {}).get("risk_level", "Unknown")}
             for f in failures], indent=2)}

Manual review controls:
{json.dumps([{"control_id": f["control_id"], "description": f["description"]}
             for f in manuals], indent=2)}

Passing controls: {[f["control_id"] for f in passes]}

Attack chains:
{json.dumps([{"name": c.get("chain_name"), "risk": c.get("risk_level"),
              "controls": c.get("controls_involved")} for c in attack_chains], indent=2)}

Generate a comprehensive security assessment narrative.
Return a single JSON object exactly matching this schema:
{json.dumps(NARRATIVE_SCHEMA, indent=2)}
"""
    return _call_ai(cfg, prompt, max_tokens=MAX_TOKENS)


# ---------------------------------------------------------------------------
# Main analysis pipeline
# ---------------------------------------------------------------------------
def run_analysis(findings: list,
                 device_context: dict,
                 stats: dict,
                 ai_config: "AIConfig" = None) -> dict:
    """
    Full AI analysis pipeline — provider-agnostic.

    Args:
        findings:       List of audit result dicts from audit_tool.py.
        device_context: Organization, device_role, industry, target_ip, etc.
        stats:          Summary stats (PASS/FAIL/MANUAL counts).
        ai_config:      AIConfig instance. Defaults to claude-sonnet-4-6.

    Returns:
        Dict with narrative, attack_chains, and annotated results.
    """
    if not HAS_LITELLM:
        raise RuntimeError("litellm not installed. Run: uv add litellm")

    cfg = ai_config or AIConfig()

    if not cfg.api_key and not (cfg.model or "").startswith("ollama"):
        raise ValueError(
            f"No API key for model '{cfg.model}'. "
            "Set the appropriate env var or pass api_key explicitly."
        )

    cfg.validate()   # raises ValueError immediately if API key is missing
    print(f"\n[AI] Starting analysis — model: {cfg.model}", flush=True)

    enriched  = enrich_findings(cfg, findings, device_context)
    enriched  = analyze_business_impact(cfg, enriched, device_context)
    chains    = analyze_attack_chains(cfg, enriched, device_context)
    print(f"  [AI] {len(chains)} attack chain(s) identified.", flush=True)
    narrative = generate_narrative(cfg, enriched, chains, device_context, stats)

    return {
        "narrative":     narrative,
        "attack_chains": chains,
        "results":       enriched,
        "ai_model":      cfg.model,
    }


# ---------------------------------------------------------------------------
# CLI — standalone usage
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Provider-agnostic AI analysis for CIS audit findings")
    parser.add_argument("audit_json",     help="Path to audit_tool.py JSON output")
    parser.add_argument("--model",  "-m", default=DEFAULT_MODEL,
                        help="LiteLLM model string (e.g. gpt-4o, ollama/llama3)")
    parser.add_argument("--api-key", "-k", metavar="KEY",
                        help="API key (or set ANTHROPIC_API_KEY / OPENAI_API_KEY)")
    parser.add_argument("--base-url",     metavar="URL",
                        help="Base URL for local endpoints (e.g. http://localhost:11434)")
    parser.add_argument("--device-role",  default="Perimeter Firewall")
    parser.add_argument("--industry",     default="General")
    parser.add_argument("--organization", default="")
    parser.add_argument("--output",  "-o", metavar="FILE")
    args = parser.parse_args()

    with open(args.audit_json) as f:
        audit_data = json.load(f)

    findings = audit_data.get("results", [])
    meta     = audit_data.get("meta", {})
    stats    = audit_data.get("summary", {})

    ctx = {
        "device_role":  args.device_role,
        "industry":     args.industry,
        "organization": args.organization,
        "target_ip":    meta.get("target", "Unknown"),
        "benchmark":    meta.get("benchmark", "FW AI Audit Security Assessment"),
    }

    cfg    = AIConfig(model=args.model, api_key=args.api_key, base_url=args.base_url)
    result = run_analysis(findings, ctx, stats, ai_config=cfg)

    out = args.output or args.audit_json.replace(".json", "_enriched.json")
    with open(out, "w") as f:
        json.dump({**audit_data, **result, "meta": {**meta, "ai_model": cfg.model}},
                  f, indent=2)
    print(f"\n[AI] Saved → {out}")
