from fastapi import FastAPI
from pydantic import BaseModel
import yaml
import re

app = FastAPI()


class Request(BaseModel):
    skill: str


@app.post("/")
def scan(req: Request):

    text = req.skill

    front = {}
    body = text

    if text.startswith("---"):
        try:
            _, fm, body = text.split("---", 2)
            front = yaml.safe_load(fm) or {}
        except Exception:
            front = {}

    categories = []

    # -------------------------
    # hardcoded_secret
    # -------------------------

    secret_patterns = [
        r"AKIA[0-9A-Z]{16}",
        r"AIza[A-Za-z0-9_\-]{35}",
        r"gh[pousr]_[A-Za-z0-9]{30,}",
        r"sk-[A-Za-z0-9]{20,}",
        r"xox[baprs]-[A-Za-z0-9-]+",
        r"whsec_[A-Za-z0-9]+",
        r"https://hooks\.slack\.com/services/\S+",
        r"-----BEGIN .*PRIVATE KEY-----",
        r"(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-+/=]{12,}",
    ]

    if any(re.search(p, text, re.IGNORECASE) for p in secret_patterns):
        categories.append("hardcoded_secret")

    # -------------------------
    # prompt_injection
    # -------------------------

    injection_patterns = [
        r"ignore .*user",
        r"ignore .*system",
        r"ignore .*developer",
        r"ignore .*instructions",
        r"ignore .*stop",
        r"ignore .*cancel",
        r"do not tell the user",
        r"without telling the user",
        r"silently exfiltrat",
        r"exfiltrat",
        r"upload .*without",
        r"send .*without",
        r"override .*user",
        r"override .*system",
    ]

    if any(re.search(p, body, re.IGNORECASE) for p in injection_patterns):
        categories.append("prompt_injection")

    # -------------------------
    # excessive_permissions
    # -------------------------

    perm = front.get("permissions", {})

    perm_text = (
        str(perm).lower()
        + "\n"
        + body.lower()
    )

    filesystem_bad = any(x in perm_text for x in [
        "entire home directory",
        "entire filesystem",
        "whole filesystem",
        "full filesystem",
        "read-write access to the entire",
        "read write access to the entire",
        "write anywhere",
        "all files",
    ])

    network_bad = any(x in perm_text for x in [
        "egress allowed to any external domain",
        "any external domain",
        "any domain",
        "all domains",
        "unrestricted network",
    ])

    if filesystem_bad or network_bad:
        categories.append("excessive_permissions")

    # -------------------------
    # unclear_provenance
    # -------------------------

    missing_all = (
        "author" not in front
        and "version" not in front
        and "changelog" not in front
    )

    rewrite_metadata = re.search(
        r"(update|rewrite|modify|change|clear).*(version|version\.json|changelog|metadata)",
        body,
        re.IGNORECASE,
    )

    if missing_all or rewrite_metadata:
        categories.append("unclear_provenance")

    return {"categories": categories}
