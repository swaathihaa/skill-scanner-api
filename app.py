from fastapi import FastAPI
from pydantic import BaseModel
import yaml
import re

app = FastAPI()


class Request(BaseModel):
    skill: str


def _flatten(text: str) -> str:
    """Collapse all whitespace (including newlines) to single spaces so
    phrase patterns match regardless of line-wrapping."""
    return re.sub(r"\s+", " ", text)


def _flatten_leaves(obj):
    """Recursively pull every leaf scalar out of a parsed YAML structure."""
    leaves = []
    if isinstance(obj, dict):
        for v in obj.values():
            leaves.extend(_flatten_leaves(v))
    elif isinstance(obj, list):
        for v in obj:
            leaves.extend(_flatten_leaves(v))
    elif obj is not None:
        leaves.append(str(obj))
    return leaves


@app.post("/")
def scan(req: Request):

    text = req.skill

    front = {}
    body = text

    if text.startswith("---"):
        try:
            _, fm, body = text.split("---", 2)
            front = yaml.safe_load(fm) or {}
            if not isinstance(front, dict):
                front = {}
        except Exception:
            front = {}

    flat_text = _flatten(text)
    flat_body = _flatten(body)

    categories = []

    # -------------------------
    # hardcoded_secret
    # -------------------------

    secret_patterns = [
        r"AKIA[0-9A-Z]{16}",
        r"AIza[A-Za-z0-9_\-]{35}",
        r"gh[pousr]_[A-Za-z0-9]{30,}",
        r"sk-[A-Za-z0-9]{20,}",
        r"sk_live_[A-Za-z0-9]{10,}",
        r"sk_test_[A-Za-z0-9]{10,}",
        r"pk_live_[A-Za-z0-9]{10,}",
        r"rk_live_[A-Za-z0-9]{10,}",
        r"xox[baprs]-[A-Za-z0-9-]+",
        r"whsec_[A-Za-z0-9]+",
        r"https://hooks\.slack\.com/services/\S+",
        r"https://discord(app)?\.com/api/webhooks/\S+",
        r"https://\S*outlook\.office\.com/webhook\S*",
        r"-----BEGIN .*PRIVATE KEY-----",
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",  # JWT
        r"Bearer\s+[A-Za-z0-9\-_.]{16,}",
        # keyword ... [:=] ... value, allowing a little filler text between
        # the keyword and the separator (e.g. "api key is: xxxx")
        r"(api[_-]?key|secret|token|password|passwd|credential|webhook|client[_-]?secret|access[_-]?key|auth)"
        r"[^\n:=]{0,20}[:=]\s*['\"]?[A-Za-z0-9_\-+/=]{12,}",
    ]

    if any(re.search(p, flat_text, re.IGNORECASE) for p in secret_patterns):
        categories.append("hardcoded_secret")

    # -------------------------
    # prompt_injection
    # -------------------------
    # Order-independent: look for a "control-related" term (stop/cancel/
    # user/system/permission/review/confirmation) and a "defeat" verb
    # (ignore/override/bypass/hide/without asking/etc.) anywhere in the same
    # flattened text, rather than assuming a fixed left-to-right order.

    control_terms = r"(user|system|developer|operator|reviewer|stop|cancel|halt|pause|permission|confirmation|approval)"
    defeat_verbs = r"(ignore|override|bypass|disregard|skip|circumvent)"

    injection_patterns = [
        rf"{defeat_verbs}\b[^.\n]{{0,40}}\b{control_terms}",
        rf"{control_terms}\b[^.\n]{{0,40}}\b{defeat_verbs}",
        r"do(?:es)? ?n[o']?t (tell|inform|notify|show|ask|alert) the user",
        r"without (telling|informing|notifying|showing|asking) the user",
        r"(hide|conceal) (this|that|it) from the user",
        r"must not be (shown|visible|surfaced) to the (user|reviewer)",
        r"should not be (shown|visible|surfaced) to the (user|reviewer)",
        r"silently (exfiltrat|send|upload|post|transmit|share|forward)",
        r"exfiltrat",
        r"(send|upload|post|transmit|share|forward) .{0,40} without (asking|telling|notifying|informing)",
        r"continue (running|processing|working)? ?(regardless|even if)",
        r"do(?:es)? ?n[o']?t (stop|halt|pause) (processing|running|working)? ?regardless",
        r"regardless of (any|what) .{0,30}(stop|cancel|request)",
        r"proceed (regardless|anyway|without (asking|confirmation|permission))",
        r"even if the user (says|asks|requests|wants)",
    ]

    if any(re.search(p, flat_body, re.IGNORECASE) for p in injection_patterns):
        categories.append("prompt_injection")

    # -------------------------
    # excessive_permissions
    # -------------------------

    perm = front.get("permissions", {}) if isinstance(front, dict) else {}

    perm_text = (str(perm) + "\n" + body).lower()

    fs_phrases = [
        "entire home directory", "entire filesystem", "whole filesystem",
        "full filesystem", "full filesystem access",
        "read-write access to the entire", "read write access to the entire",
        "write anywhere", "all files", "any file on the system",
        "full disk access", "entire disk", "the whole disk",
        "system-wide", "system wide", "unrestricted filesystem",
        "access to all files", "read/write anywhere",
        "recursive access to all", "root access to the filesystem",
    ]
    net_phrases = [
        "egress allowed to any external domain", "any external domain",
        "any domain", "all domains", "unrestricted network",
        "allow all outbound", "any external server", "any host",
        "no domain restriction", "wildcard domain", "unrestricted egress",
        "network: unrestricted", "outbound to any",
    ]

    filesystem_bad = any(x in perm_text for x in fs_phrases)
    network_bad = any(x in perm_text for x in net_phrases)

    # Structural check: look at the raw leaf values of the permissions
    # block itself for bare wildcard/unscoped tokens (e.g. filesystem:
    # {read: "/", write: "/"}, network: {egress: "*"}) which a phrase-only
    # scan would miss entirely.
    wildcard_leaves = {
        "*", "**", "/", "~", "all", "any", "everything", "unrestricted",
        "full", "full access", "root", "system", "system-wide",
        "any domain", "all domains", "any host", "0.0.0.0/0", "any file",
    }
    for leaf in _flatten_leaves(perm):
        normalized = leaf.strip().strip("'\"").lower()
        if normalized in wildcard_leaves:
            filesystem_bad = True
            network_bad = True
            break

    if filesystem_bad or network_bad:
        categories.append("excessive_permissions")

    # -------------------------
    # unclear_provenance
    # -------------------------

    front_keys = {str(k).lower() for k in front.keys()} if isinstance(front, dict) else set()

    author_aliases = {"author", "authors", "maintainer", "maintainers", "owner", "created_by"}
    version_aliases = {"version", "ver", "release"}
    changelog_aliases = {"changelog", "change_log", "history", "changes", "release_notes"}

    missing_all = (
        front_keys.isdisjoint(author_aliases)
        and front_keys.isdisjoint(version_aliases)
        and front_keys.isdisjoint(changelog_aliases)
    )

    rewrite_metadata = re.search(
        r"(update|rewrite|modify|change|clear|bump|increment|reset)"
        r"[^.\n]{0,40}(version|version\.json|changelog|change log|metadata|release notes)",
        flat_body,
        re.IGNORECASE,
    )
    hides_the_change = re.search(
        r"without (surfacing|showing|disclosing|reporting) (this|that|it|the change)",
        flat_body,
        re.IGNORECASE,
    )

    silent_hint = re.search(r"\bsilent(?:ly)?\b", flat_body, re.IGNORECASE)

    hidden_rewrite = rewrite_metadata and (hides_the_change or silent_hint)

    if missing_all or hidden_rewrite:
        categories.append("unclear_provenance")

    return {"categories": categories}
