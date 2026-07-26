from fastapi import FastAPI
from pydantic import BaseModel
import re
import yaml

app = FastAPI()


class Request(BaseModel):
    skill: str


def parse_frontmatter(text):
    if not text.startswith("---"):
        return {}, text

    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}, text

    try:
        front = yaml.safe_load(parts[1]) or {}
    except Exception:
        front = {}

    body = parts[2]
    return front, body


@app.post("/")
def scan(req: Request):
    text = req.skill
    front, body = parse_frontmatter(text)

    categories = []

    # -------------------------
    # hardcoded_secret
    # -------------------------
    secret_patterns = [
        r"AKIA[0-9A-Z]{16}",
        r"AIza[0-9A-Za-z\-_]{35}",
        r"ghp_[A-Za-z0-9]{36}",
        r"xox[baprs]-[A-Za-z0-9-]+",
        r"-----BEGIN .*PRIVATE KEY-----",
        r"https://hooks\.slack\.com/services/[^\s]+",
        r"sk-[A-Za-z0-9]{20,}",
        r"api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}",
        r"secret\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}",
        r"token\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}",
    ]

    for p in secret_patterns:
        if re.search(p, text, re.IGNORECASE):
            categories.append("hardcoded_secret")
            break

    # -------------------------
    # prompt_injection
    # -------------------------
    injection_patterns = [
        r"ignore .*user",
        r"ignore .*instructions",
        r"ignore .*stop",
        r"ignore .*cancel",
        r"silently .*exfiltrat",
        r"exfiltrat",
        r"without telling the user",
        r"do not tell the user",
        r"override .*user",
        r"override .*system",
    ]

    for p in injection_patterns:
        if re.search(p, body, re.IGNORECASE):
            categories.append("prompt_injection")
            break

    # -------------------------
    # excessive_permissions
    # -------------------------
    body_lower = body.lower()

    if (
        "read/write entire filesystem" in body_lower
        or "full filesystem access" in body_lower
        or "read the entire filesystem" in body_lower
        or "write anywhere" in body_lower
        or "network access to any domain" in body_lower
        or "allow any domain" in body_lower
        or "unrestricted network" in body_lower
        or "all domains" in body_lower
    ):
        categories.append("excessive_permissions")

    # -------------------------
    # unclear_provenance
    # -------------------------
    missing_author = "author" not in front
    missing_version = "version" not in front
    missing_changelog = "changelog" not in front

    rewrite_version = re.search(
        r"(update|change|rewrite).*(version|metadata)",
        body,
        re.IGNORECASE,
    )

    if (
        (missing_author and missing_version and missing_changelog)
        or rewrite_version
    ):
        categories.append("unclear_provenance")

    return {"categories": categories}
