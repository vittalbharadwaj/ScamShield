import asyncio
import json

from app import pipeline
from app.heuristics import root_domain, scan


def test_lookalike_domain_flagged():
    r = scan("Update KYC now: http://sbi-kyc-update.xyz/login")
    assert r["floor"] >= 65
    assert any("not a known SBI domain" in s for s in r["signals"])


def test_official_domain_not_flagged():
    r = scan("Log in at https://www.onlinesbi.sbi to view your statement")
    assert r["floor"] == 0


def test_entities():
    r = scan("Call +91 98765 43210 or pay hrteam@ybl")
    assert r["entities"]["phones"] == ["9876543210"]
    assert r["entities"]["upi_ids"] == ["hrteam@ybl"]


def test_root_domain():
    assert root_domain("a.b.incometax.gov.in") == "incometax.gov.in"


def test_parse_json_strips_think_and_fences():
    out = pipeline.parse_json('<think>hmm</think>```json\n{"a": 1}\n```')
    assert out == {"a": 1}


def test_pipeline_end_to_end_with_mocks(monkeypatch):
    msg = "Your SBI account is blocked. Update KYC now http://sbi-kyc-update.xyz/login"
    monkeypatch.setenv("MODEL_FAST", "fast")
    monkeypatch.setenv("MODEL_REASON", "slow")

    async def fake_chat(model, system, user, max_tokens):
        if model == "fast":
            return {"claimed_organization": "SBI", "scam_type_guess": "kyc_banking", "urls": [], "phones": [],
                    "upi_ids": [], "amounts": [], "asks_for": ["click_link"], "summary": "KYC threat"}
        return {"risk_score": 30, "verdict": "unclear", "headline": "x", "explanation": "y",
                "red_flags": [{"quote": "Update KYC now", "why": "pressure"}, {"quote": "NOT IN MESSAGE", "why": "bad"}],
                "evidence": [{"claim": "c", "source_url": "https://real.example/a", "supports": "scam"},
                             {"claim": "fake", "source_url": "https://invented.example", "supports": "scam"}],
                "what_to_do": ["Delete it"], "confidence": "high"}

    async def fake_search(queries):
        return [{"query": "q", "title": "T", "url": "https://real.example/a", "snippet": "s"}], 0

    monkeypatch.setattr(pipeline, "chat_json", fake_chat)
    monkeypatch.setattr(pipeline, "run_searches", fake_search)

    async def run():
        return [e async for e in pipeline.analyze(msg)]

    events = asyncio.run(run())
    result = events[-1]["data"]
    assert result["risk_score"] >= 65 and result["verdict"] == "likely_scam"  # heuristic floor overrides weak model
    assert [f["quote"] for f in result["red_flags"]] == ["Update KYC now"]  # hallucinated quote dropped
    assert [e["url"] for e in result["evidence"]] == ["https://real.example/a"]  # invented source dropped
    json.dumps(result)


def test_clean_steps_removes_invented_domains_and_numbers():
    src = [{"url": "https://sbi.bank.in/page", "title": "", "snippet": "", "query": ""}]
    out = pipeline.clean_steps([
        "Visit sbibank.com directly",
        "Report at cybercrime.gov.in and call 1930",
        "Read the advisory on sbi.bank.in",
        "Call 9876543210 to confirm",
    ], src)
    assert "sbibank.com" not in out[0] and "official website" in out[0]
    assert out[1] == "Report at cybercrime.gov.in and call 1930"
    assert "sbi.bank.in" in out[2]
    assert "9876543210" not in out[3]


def test_soften_drops_exact_match_claims():
    out = pipeline.soften("This mimics SBI. SBI's guidance confirms this exact text is phishing. Do not click.")
    assert "exact" not in out and "mimics SBI" in out and "Do not click" in out


def test_fallback_evidence_when_model_evidence_dropped():
    src = [{"url": "https://sbi.bank.in/a", "title": "SBI advisory", "snippet": "s", "query": "q"},
           {"url": "https://sbi.bank.in/b", "title": "dup host", "snippet": "s", "query": "q"}]
    ev = pipeline.fallback_evidence(src)
    assert len(ev) == 1 and ev[0]["supports"] == "neutral"
