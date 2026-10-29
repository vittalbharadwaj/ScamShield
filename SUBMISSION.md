# Devpost submission kit (copy into the form)

## Track
Best Apps and Agents

## Tagline
Paste a suspicious message. Get a sourced scam verdict in seconds.

## Text description (paste)
**Problem.** Millions of people in India get UPI, KYC, fake-job and prize scam messages every day, and most check them by asking a relative. Losses are fast and often irreversible.

**What it does.** ScamShield takes any SMS, WhatsApp or email text and returns a verdict with a 0-100 risk score, the exact phrases in the message that give the scam away (highlighted in place), live web evidence, and concrete next steps including the 1930 cyber crime helpline. It answers in English or Hindi.

**How it uses Nebius and NVIDIA.** Every request runs a three-stage pipeline through Nebius Token Factory. NVIDIA Nemotron (fast tier) extracts the claimed organisation, links, phone numbers and UPI IDs as structured JSON. Tavily then runs parallel live searches on each entity. NVIDIA Nemotron (reasoning tier) weighs the evidence and writes the verdict. The UI shows which model handled each step and streams progress live.

**Why it can be trusted.** Quotes must be exact substrings of the user's message, every cited source must come from the actual Tavily results, a deterministic lookalike-domain rule sets a minimum risk, and "no reports found" is never treated as proof of safety. Messages are never stored or logged.

**Challenges.** Getting small and large reasoning models to return strict JSON reliably, and preventing hallucinated evidence (solved with server-side validation).

**What's next.** Image/screenshot input, voice notes, and more Indian languages.

## Demo video script (target 2:30, under 3:00)
- 0:00-0:20 Problem: "Scam messages like this reach millions daily." Show the KYC example text.
- 0:20-1:20 Live demo: paste KYC example, show the three live steps and model names, then the verdict, highlighted phrases, sources.
- 1:20-1:50 Show the Normal OTP example to prove it does not cry wolf; flip to Hindi on one result.
- 1:50-2:30 Architecture slide (pipeline diagram from README), mention Token Factory, Nemotron tiers, Tavily, guardrails.
- Use no copyrighted music. Upload to YouTube as Public. Screen-record with a voiceover.

## Feedback section: write real notes on
- Token Factory: signup/credits flow, model-ID discovery, latency by model tier, JSON reliability, streaming, rate limits.
- Nemotron: Nano vs Super/Ultra quality and speed on your task, any reasoning-token overhead.
- Docs gaps and anything that cost you time. Specific, honest feedback scores best for Most Valuable Feedback.

## Final checklist
- [ ] Public GitHub repo, MIT license visible in About
- [ ] README explains Nemotron, Token Factory and Tavily usage
- [ ] Live demo URL works in an incognito window and on a phone
- [ ] YouTube video public, under 3 minutes
- [ ] Track selected, feedback section completed
- [ ] Submitted before the deadline (10:00 AM PT on Oct 30 = 10:30 PM IST)
