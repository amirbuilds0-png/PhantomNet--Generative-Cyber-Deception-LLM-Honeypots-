# Progress tracker (~50% complete)

| Area | Status |
|---|---|
| Requirements & architecture | Done |
| SSH honeypot server (auth policy, interactive + exec sessions) | Done |
| LLM integration (Anthropic, OpenAI-compatible/Ollama, Mock) + prompt engineering | Done (v1 prompt) |
| Session state + consistency (fast path, cache, history window) | Done (cd/mkdir); file contents pending |
| Guardrails (injection detection, leak filter, truncation) | Done (regex v1) |
| Structured logging + ATT&CK tagging + analysis report | Done (14 rules) |
| Tests (unit + SSH end-to-end) | 9 passing |
| Evaluation harness | Skeleton done, mock results recorded |
| Docker/compose hardened deployment | Done |
| Project documentation (README, architecture) | Done |

## Remaining (second half)
1. **Virtual filesystem:** persist files created with `echo > file`, `touch`, `wget` so `ls`/`cat` stay consistent (biggest realism gain).
2. **Vector DB / RAG (scope of work item):** store real-looking command outputs per command family and retrieve few-shot examples into the prompt.
3. **Telnet + HTTP honeypot front-ends** (reuse `HoneypotEngine`).
4. **LLM-as-judge realism evaluation** against real Ubuntu output; compare 2-3 models (latency, cost, leak rate) with real keys.
5. **Smarter guard:** classifier-based leak detection instead of regex only.
6. **Dashboard** (Streamlit/Grafana) over the JSONL log; IP geo/ASN enrichment.
7. **Deliverables:** Project report, PPT, evaluation report with real-model numbers, final demo recording.
8. 7-day live deployment on an isolated cloud VM to collect real attacker data.
