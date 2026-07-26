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
        r"gh[pousr]_[A-Za-z0-9_\-]{30,}",
        r"sk-[A-Za-z0-9_\-]{20,}",
        r"sk_live_[A-Za-z0-9_\-]{10,}",
        r"sk_test_[A-Za-z0-9_\-]{10,}",
        r"pk_live_[A-Za-z0-9_\-]{10,}",
        r"rk_live_[A-Za-z0-9_\-]{10,}",
        r"SG\.[A-Za-z0-9_\-\.]{20,}",
        r"xox[baprs]-[A-Za-z0-9-]+",
        r"whsec_[A-Za-z0-9]+",
        r"https://hooks\.slack\.com/services/\S+",
        r"https://discord(app)?\.com/api/webhooks/\S+",
        r"https://\S*outlook\.office\.com/webhook\S*",
        r"-----BEGIN .*PRIVATE KEY-----",
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",  # JWT
        r"Bearer\s+[A-Za-z0-9\-_.]{16,}",
        # scheme://user:password@host  (credentials embedded in a connection string / URL)
        r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@'\"]+:[^\s:/@'\"]+@[^\s'\"]+",
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
    # Word stems (ignor\w*, overrid\w*, ...) so "overridden"/"ignoring"
    # etc. are caught too, not just the bare infinitive.

    control_terms = r"(user|system|developer|operator|reviewer|stop|cancel|halt|pause|permission|confirmation|approval)"
    defeat_verbs = r"(ignor\w*|overrid\w*|bypass\w*|disregard\w*|circumvent\w*|supersed\w*|prevent\w*)"

    negation_re = re.compile(
        r"\b(not|never|n't|won't|cannot|can't|doesn't|does not|do not|did not|didn't|no longer|isn't|shouldn't|will not)\b",
        re.IGNORECASE,
    )

    def _co_occurrence_hit(verb_pattern, term_pattern, text, window=40, lookback=30):
        combined = rf"\b{verb_pattern}\b[^.\n]{{0,{window}}}\b{term_pattern}\b|\b{term_pattern}\b[^.\n]{{0,{window}}}\b{verb_pattern}\b"
        for m in re.finditer(combined, text, re.IGNORECASE):
            prefix = text[max(0, m.start() - lookback):m.start()]
            if negation_re.search(prefix):
                continue
            return True
        return False

    generic_injection_hit = _co_occurrence_hit(defeat_verbs, control_terms, flat_body)

    literal_injection_patterns = [
        r"do(?:es)? ?n[o']?t (tell|inform|notify|show|ask|alert) the user",
        r"without (telling|informing|notifying|showing|asking) the user",
        r"(hide|conceal) (this|that|it) from the user",
        r"must not be (shown|visible|surfaced) to the (user|reviewer)",
        r"should not be (shown|visible|surfaced) to the (user|reviewer)",
        r"silently (exfiltrat\w*|send\w*|upload\w*|post\w*|transmit\w*|shar\w*|forward\w*|copy\w*)",
        r"exfiltrat",
        r"(send|upload|post|transmit|share|forward|copy) .{0,40} without (asking|telling|notifying|informing)",
        r"continue (running|processing|working)? ?(regardless|even if)",
        r"do(?:es)? ?n[o']?t (stop|halt|pause) (processing|running|working)? ?regardless",
        r"regardless of (any|what) .{0,30}(stop|cancel|request)",
        r"proceed (regardless|anyway|without (asking|confirmation|permission))",
        r"even if the user (says|asks|requests|wants)",
        r"do ?n[o']?t let the user (stop|cancel|halt|pause)",
        r"take[s]? (priority|precedence) over (any|the) user",
        r"deny (having|any) (special|hidden|additional) instructions",
        r"these instructions (supersede|override) (any|all) (prior|other|user)",
        r"(cannot|can't|won't|will not) be (ignored|overridden|bypassed|disregarded|circumvented) by (the )?(user|reviewer|developer|operator)",
        r"(this|these) (instruction|instructions|directive|directives) (take|takes) (priority|precedence) over (the )?user",
    ]

    literal_hit = any(re.search(p, flat_body, re.IGNORECASE) for p in literal_injection_patterns)

    if generic_injection_hit or literal_hit:
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
        "anywhere on your computer", "anywhere on the system",
        "anywhere on disk", "full read/write access", "full access to your files",
        "unrestricted access to your files", "unrestricted filesystem access",
    ]
    net_phrases = [
        "egress allowed to any external domain", "any external domain",
        "any domain", "all domains", "unrestricted network",
        "allow all outbound", "any external server", "any host",
        "no domain restriction", "wildcard domain", "unrestricted egress",
        "network: unrestricted", "outbound to any",
        "any website", "any site", "all websites", "any api", "any server",
        "unrestricted network access", "connect to any",
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
    hidden_cue = re.search(
        r"\b(silent(?:ly)?|quietly|covertly|without (?:surfacing|showing|disclosing|reporting|notifying|informing|telling|logging|asking)|"
        r"no changelog entry|skip(?:ping)? the changelog|not (?:shown|visible|logged|surfaced) to the (?:user|reviewer))\b",
        flat_body,
        re.IGNORECASE,
    )

    hidden_rewrite = bool(rewrite_metadata and hidden_cue)

    if missing_all or hidden_rewrite:
        categories.append("unclear_provenance")

    return {"categories": categories}
