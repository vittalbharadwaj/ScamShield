# ScamShield

Paste a suspicious SMS, WhatsApp message or email. ScamShield returns a verdict, the exact phrases that give the scam away (highlighted in your own message), and live web sources you can check.

Built for the **Nebius x NVIDIA Global AI Hackathon** · Track: **Best Apps and Agents** · Bonus: **Best Use of Tavily**

## How it works

```
message ─► rule-based checks (lookalike domains, UPI IDs, shorteners, urgency)
        ─► NVIDIA Nemotron (fast tier)   extract org, links, phones, UPI IDs, scam type
        ─► Tavily                        parallel live searches on each entity
        ─► NVIDIA Nemotron (reasoning)   weigh evidence → verdict, red flags, next steps
        ─► streamed to the browser (SSE), quotes + sources verified server-side
```

| Stage | Model / service | Why |
|---|---|---|
| Extraction | Nemotron Nano (`MODEL_FAST`) | Fast, cheap structured JSON on every request |
| Evidence | Tavily Search API (runtime call per request) | Checks whether a URL, phone, UPI ID or brand is reported as fraud |
| Verdict | Nemotron Super/Ultra (`MODEL_REASON`) | Needs real reasoning over noisy evidence |
| Inference | Nebius Token Factory (OpenAI-compatible API) | All model calls go through it |

**Trust guardrails** (see `app/pipeline.py::finalize`): red-flag quotes must be exact substrings of the message, evidence URLs must come from the Tavily results, a lookalike-bank-domain rule sets a minimum risk score, and the prompt says that no scam reports is not proof of safety. The message is treated as untrusted data (prompt-injection safe), and its text is never logged or stored.

## Run locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # add NEBIUS_API_KEY and TAVILY_API_KEY
python list_models.py           # prints exact Nemotron model IDs for your key
# put the Nano ID in MODEL_FAST and a Super/Ultra ID in MODEL_REASON
uvicorn app.main:app --reload   # http://localhost:8000
pytest -q                       # unit + mocked end-to-end tests
```

Check `http://localhost:8000/api/health` to confirm keys and models are configured.

## Deploy

The app is a single container:

```bash
docker build -t scamshield . && docker run -p 8000:8000 --env-file .env scamshield
```

Run that image on any host that gives you a public HTTPS URL (Nebius Serverless Endpoints, Render, Fly.io, Railway). Set the variables from `.env.example` in the host's secret settings, not in the image. `RATE_LIMIT_PER_10_MIN` protects your credits on a public demo.

## Project layout

```
app/main.py         FastAPI app, SSE endpoint, rate limiting
app/pipeline.py     3-stage Nemotron + Tavily pipeline and output validation
app/heuristics.py   deterministic scam signals (no network)
app/static/         single-page UI
tests/              heuristics, JSON parsing, mocked full pipeline
list_models.py      helper to find Nemotron model IDs on Token Factory
```

## Limitations

ScamShield gives guidance, not legal or financial advice. It can be wrong; for anything involving money, confirm with your bank using the number on your card. India-focused (UPI, KYC, 1930 helpline), but the pipeline is region-agnostic.

## License

MIT, see `LICENSE`.
