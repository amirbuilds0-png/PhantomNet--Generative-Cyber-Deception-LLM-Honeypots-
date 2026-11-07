# Architecture & Design Decisions

## Problem
Classic low/medium-interaction honeypots (Cowrie, Kippo) answer from a fixed command table. Experienced attackers
fingerprint them quickly with uncommon commands. An LLM can answer *any* command plausibly, but naive use has four risks:
(1) inconsistency between commands, (2) latency/cost, (3) the model leaking that it is an AI, (4) attackers prompt-injecting
the model. PhantomNet addresses each with a dedicated component.

## Components
1. **Session state (`session.py`)** - virtual directory set, cwd, bounded history window. State that must be perfectly
   consistent (cwd, mkdir) is handled locally; the LLM receives the current state in every prompt.
2. **Fast path (`engine._local`)** - `cd/pwd/whoami/hostname/mkdir/clear/exit` never touch the LLM: zero latency, zero cost,
   zero chance of drift.
3. **Idempotent cache** - `uname -a`, `id`, `ps`, `cat /etc/passwd` ... return identical output within a session
   (real hosts do not change `uname` between calls).
4. **Persona prompt (`persona.py`)** - fixed host identity, "output only raw terminal text", `<empty>` sentinel for
   silent commands, fake-data-only rule, download handling rule.
5. **Guard (`guard.py`)** - regex detection of AI-fingerprinting/injection ("are you an AI", "ignore previous
   instructions") -> answered with a normal bash error and flagged in the log; output filter blocks identity leaks, strips
   markdown fences, truncates floods.
6. **Failure handling** - any LLM timeout/error degrades to a believable `command not found` and is logged.
7. **Telemetry** - JSONL events (connection, auth, session, command with techniques/flags/latency) enabling
   `analysis.py` summaries and later dashboards.

## Threat model (what we defend against)
* Attacker identifying the honeypot via AI phrasing -> guard + prompt rules.
* Attacker using the honeypot as a stepping stone -> no command execution, no outbound network from the sandbox.
* Resource abuse (huge outputs, endless sessions) -> line/char limits, `max_commands`, `session_timeout`.
