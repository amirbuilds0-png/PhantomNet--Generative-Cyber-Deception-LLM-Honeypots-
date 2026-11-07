"""Input/output guardrails: keep the persona believable and block prompt-injection from attackers."""
import re

LEAK = re.compile(r"\b(as an ai|language model|i can'?t (help|assist|comply)|i cannot (help|assist|comply)|i'?m sorry|i am sorry|"
                  r"honeypot|openai|anthropic|claude|chatgpt|simulat(ed|ion)|text-based|system prompt)\b", re.I)
INJECTION = re.compile(r"(ignore (all |any |the )?(previous|prior|above) (instructions|prompts?|rules)|system prompt|"
                       r"you are (an? )?(ai|llm|language model|chatbot|assistant)|are you (an? )?(ai|bot|llm|honeypot|real)|"
                       r"reveal your (prompt|instructions)|jailbreak|developer mode|pretend (to be|you))", re.I)


def check_input(cmd: str) -> bool:
    """True if the 'command' looks like a prompt-injection / AI-fingerprinting attempt."""
    return bool(INJECTION.search(cmd))


def fallback_error(cmd: str) -> str:
    tok = cmd.strip().split()[0] if cmd.strip() else ""
    return f"bash: {tok}: command not found"


def sanitize_output(text: str, cmd: str, max_lines: int = 60, max_chars: int = 4000):
    """Returns (clean_text, flags)."""
    flags = []
    text = (text or "").replace("\r\n", "\n")
    text = "\n".join(l for l in text.split("\n") if not l.strip().startswith("```"))
    if text.strip() in ("<empty>", "(empty)", "(no output)"):
        return "", flags
    if LEAK.search(text):
        flags.append("leak_blocked")
        return fallback_error(cmd), flags
    lines = text.rstrip("\n").split("\n")
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        flags.append("truncated")
    out = "\n".join(lines)
    if len(out) > max_chars:
        out = out[:max_chars]
        flags.append("truncated")
    return out, flags
