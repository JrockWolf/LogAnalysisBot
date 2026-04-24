"""Privacy / redaction module for LogAnalysisBot.

Scrubs PII and sensitive identifiers from log text before any data is sent
to an external LLM API.  Replacements are deterministic within a session so
that the same IP always maps to the same token (e.g. ``[IP_0]``), allowing
evidence reconstruction when needed.

Usage
-----
::

    from src.redactor import Redactor

    r = Redactor()
    clean = r.redact("Failed login from 192.168.1.5 for user alice@corp.com")
    # → "Failed login from [IP_0] for user [EMAIL_0]"

    # Redact a whole list of records (mutates 'raw' / 'message' fields)
    records = r.redact_records(records)

    # Reverse-map for display purposes
    original = r.restore(clean)

Supported entity types
----------------------
- IPv4 addresses             → ``[IP_N]``
- IPv6 addresses             → ``[IPv6_N]``
- Email addresses            → ``[EMAIL_N]``
- Usernames from auth events → ``[USER_N]``
- Hostnames (FQDN)           → ``[HOST_N]``
- Custom regex patterns      → ``[REDACTED_N]``
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_IPV6 = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
    r"|\b::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:)+:\b"
)
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

# Usernames: "user alice", "for user bob", "sudo: alice :", "su - alice", "login: bob"
_RE_USERNAME = re.compile(
    r"(?:for\s+(?:user\s+|invalid\s+user\s+)|"
    r"(?:sudo|su)\s*[:\-]\s*\S+\s+|"
    r"login(?:ed)?\s+(?:as\s+)?(?:user\s+)?|"
    r"Accepted\s+\S+\s+for\s+|"
    r"Failed\s+\S+\s+for\s+(?:invalid\s+user\s+)?)"
    r"([A-Za-z0-9._\-]{2,64})",
    re.IGNORECASE,
)

# Hostnames: sub.domain.tld — minimum two labels, each label-valid
_RE_HOSTNAME = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.){1,}"
    r"(?:[A-Za-z]{2,})\b"
)

# Labels that are not hostnames (common log keywords, protocols, TLDs alone)
_NOT_HOSTNAME = frozenset({
    "localhost", "severity", "warning", "error", "critical", "notice",
    "debug", "info", "alert", "emerg", "kern", "daemon", "auth", "cron",
    "user", "mail", "syslog", "local0", "local7",
    "tcp", "udp", "icmp", "http", "https", "ftp", "ssh", "smtp", "dns",
    "true", "false", "null", "none", "yes", "no",
    "com", "org", "net", "edu", "gov", "io", "co",
})


# ---------------------------------------------------------------------------
# RedactionContext — tracks replacements within one session
# ---------------------------------------------------------------------------

class RedactionContext:
    """Holds the bidirectional replacement map for one analysis session."""

    def __init__(self) -> None:
        # entity_type → {original_value → token}
        self._fwd: Dict[str, Dict[str, str]] = {
            "IP": {}, "IPv6": {}, "EMAIL": {}, "USER": {}, "HOST": {}, "REDACTED": {}
        }
        # token → original_value (reverse map for restoration)
        self._rev: Dict[str, str] = {}

    def token_for(self, entity_type: str, value: str) -> str:
        """Return (and if necessary create) the deterministic token for *value*."""
        bucket = self._fwd.setdefault(entity_type, {})
        if value not in bucket:
            idx = len(bucket)
            token = f"[{entity_type}_{idx}]"
            bucket[value] = token
            self._rev[token] = value
        return bucket[value]

    def restore(self, text: str) -> str:
        """Replace all tokens in *text* with their original values."""
        for token, original in self._rev.items():
            text = text.replace(token, original)
        return text

    def mapping(self) -> Dict[str, str]:
        """Return the full token → original mapping."""
        return dict(self._rev)


# ---------------------------------------------------------------------------
# Redactor
# ---------------------------------------------------------------------------

class Redactor:
    """Apply PII / identifier redaction to text and records.

    Parameters
    ----------
    redact_ips:
        Replace IPv4 addresses (default: True).
    redact_ipv6:
        Replace IPv6 addresses (default: True).
    redact_emails:
        Replace email addresses (default: True).
    redact_usernames:
        Replace usernames extracted from auth-event patterns (default: True).
    redact_hostnames:
        Replace fully-qualified hostnames (default: False — can be lossy).
    custom_patterns:
        List of additional compiled or string regex patterns whose matches
        will be replaced with ``[REDACTED_N]`` tokens.
    context:
        Reuse an existing :class:`RedactionContext` (e.g. across multiple
        files in one session).  A fresh context is created if not provided.
    """

    def __init__(
        self,
        redact_ips: bool = True,
        redact_ipv6: bool = True,
        redact_emails: bool = True,
        redact_usernames: bool = True,
        redact_hostnames: bool = False,
        custom_patterns: Optional[List[str]] = None,
        context: Optional[RedactionContext] = None,
    ) -> None:
        self.redact_ips = redact_ips
        self.redact_ipv6 = redact_ipv6
        self.redact_emails = redact_emails
        self.redact_usernames = redact_usernames
        self.redact_hostnames = redact_hostnames
        self._custom: List[re.Pattern[str]] = []
        for pat in (custom_patterns or []):
            if isinstance(pat, str):
                self._custom.append(re.compile(pat))
            else:
                self._custom.append(pat)
        self.context: RedactionContext = context or RedactionContext()

    # ------------------------------------------------------------------
    # Core text redaction
    # ------------------------------------------------------------------

    def redact(self, text: str) -> str:
        """Return a redacted copy of *text*."""
        if not text:
            return text

        # 1. Emails first (contain '@' which might confuse hostname pattern)
        if self.redact_emails:
            text = _RE_EMAIL.sub(lambda m: self.context.token_for("EMAIL", m.group()), text)

        # 2. IPv6 before IPv4 (longer match)
        if self.redact_ipv6:
            text = _RE_IPV6.sub(lambda m: self.context.token_for("IPv6", m.group()), text)

        # 3. IPv4
        if self.redact_ips:
            text = _RE_IPV4.sub(lambda m: self.context.token_for("IP", m.group()), text)

        # 4. Usernames extracted from auth-event patterns
        if self.redact_usernames:
            text = _RE_USERNAME.sub(
                lambda m: m.group(0).replace(
                    m.group(1), self.context.token_for("USER", m.group(1))
                ),
                text,
            )

        # 5. Hostnames (optional, potentially lossy)
        if self.redact_hostnames:
            def _replace_host(m: re.Match) -> str:
                val = m.group(0)
                if val.lower() in _NOT_HOSTNAME:
                    return val
                return self.context.token_for("HOST", val)
            text = _RE_HOSTNAME.sub(_replace_host, text)

        # 6. Custom patterns
        for pat in self._custom:
            text = pat.sub(
                lambda m: self.context.token_for("REDACTED", m.group()), text
            )

        return text

    def restore(self, text: str) -> str:
        """Reverse all redactions in *text* using the session context."""
        return self.context.restore(text)

    # ------------------------------------------------------------------
    # Record-level helpers
    # ------------------------------------------------------------------

    def redact_records(
        self,
        records: List[Dict[str, Any]],
        fields: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Redact the specified *fields* in every record (default: raw, message).

        Returns the same list with records mutated in-place.
        """
        target_fields = fields or ["raw", "message"]
        for rec in records:
            for fld in target_fields:
                if fld in rec and rec[fld]:
                    rec[fld] = self.redact(str(rec[fld]))
        return records

    def redact_findings(self, findings: List[str]) -> List[str]:
        """Redact a list of finding strings."""
        return [self.redact(f) for f in findings]

    @property
    def mapping(self) -> Dict[str, str]:
        """Token → original value mapping for this session."""
        return self.context.mapping()
