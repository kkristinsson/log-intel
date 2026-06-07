from __future__ import annotations

import logging
import os
import secrets
import ssl
from dataclasses import dataclass
from typing import Literal

from flask_login import UserMixin
from werkzeug.security import check_password_hash

from log_intel.syslogb.app import config

logger = logging.getLogger(__name__)

AuthMethod = Literal["ldap", "local"]


@dataclass
class AuthUser(UserMixin):
    username: str
    method: AuthMethod

    @property
    def id(self) -> str:
        return self.username


def auth_required() -> bool:
    if not config.AUTH_ENABLED:
        return False
    has_ldap = bool(config.LDAP_URI.strip())
    has_local = bool(config.LOCAL_AUTH_USERNAME.strip() and config.LOCAL_AUTH_PASSWORD)
    if has_ldap or has_local:
        return True
    logger.error(
        "AUTH_ENABLED=1 but no LDAP URI or local admin password configured — locking down HTTP API"
    )
    return True


def authenticate(username: str, password: str) -> AuthUser | None:
    username = username.strip()
    if not username or not password:
        return None

    if config.LDAP_URI.strip():
        ldap_user = _ldap_authenticate(username, password)
        if ldap_user:
            return ldap_user

    if _local_authenticate(username, password):
        return AuthUser(username=username, method="local")

    return None


def _local_authenticate(username: str, password: str) -> bool:
    expected_user = config.LOCAL_AUTH_USERNAME.strip()
    expected_pass = config.LOCAL_AUTH_PASSWORD
    if not expected_user or not expected_pass:
        return False
    if username != expected_user:
        return False
    if expected_pass.startswith(("pbkdf2:", "scrypt:")):
        return check_password_hash(expected_pass, password)
    return secrets.compare_digest(password, expected_pass)


def _ldap_authenticate(username: str, password: str) -> AuthUser | None:
    try:
        from ldap3 import ALL_ATTRIBUTES, SUBTREE, Connection, Server, Tls
        from ldap3.core.exceptions import LDAPException
        from ldap3.utils.conv import escape_filter_chars
    except ImportError:
        logger.error("ldap3 is not installed; LDAP authentication unavailable")
        return None

    uri = config.LDAP_URI.strip()
    use_ssl = uri.lower().startswith("ldaps://") or config.LDAP_USE_SSL
    if use_ssl:
        insecure = os.environ.get("LDAP_TLS_INSECURE", "").strip().lower() in (
            "1",
            "true",
            "yes",
            "on",
        )
        tls = Tls(validate=ssl.CERT_NONE if insecure else ssl.CERT_REQUIRED)
    else:
        tls = None
    server = Server(uri, use_ssl=use_ssl, tls=tls, connect_timeout=config.LDAP_TIMEOUT_SEC)

    user_dn, user_ident = _resolve_ldap_user_identity(
        server, username, escape_filter_chars
    )
    if not user_dn and not user_ident:
        logger.warning("LDAP: could not resolve identity for user %s", username)
        return None

    bind_user = user_ident or user_dn
    if not bind_user:
        return None

    try:
        conn = Connection(
            server,
            user=bind_user,
            password=password,
            receive_timeout=config.LDAP_TIMEOUT_SEC,
            auto_bind=False,
        )
        if not conn.bind():
            logger.info("LDAP bind failed for %s: %s", username, conn.result)
            return None

        resolved_dn = user_dn or conn.extend.standard.who_am_i()
        if resolved_dn and resolved_dn.startswith("dn:"):
            resolved_dn = resolved_dn[3:]

        if not _ldap_group_allowed(conn, resolved_dn or bind_user, username, escape_filter_chars):
            logger.info("LDAP user %s authenticated but is not in required group", username)
            conn.unbind()
            return None

        conn.unbind()
        return AuthUser(username=username, method="ldap")
    except LDAPException as e:
        logger.warning("LDAP error for %s: %s", username, e)
        return None


def _resolve_ldap_user_identity(server, username: str, escape_filter_chars):
    from ldap3 import SUBTREE, Connection

    template = config.LDAP_USER_DN_TEMPLATE.strip()
    if template:
        ident = template.format(username=username)
        return ident, ident

    search_filter = config.LDAP_USER_SEARCH_FILTER.strip()
    search_base = config.LDAP_USER_SEARCH_BASE.strip()
    if not search_filter or not search_base:
        return None, None

    filt = search_filter.format(username=escape_filter_chars(username))
    bind_dn = config.LDAP_BIND_DN.strip()
    bind_password = config.LDAP_BIND_PASSWORD

    try:
        if bind_dn:
            lookup = Connection(
                server,
                user=bind_dn,
                password=bind_password,
                receive_timeout=config.LDAP_TIMEOUT_SEC,
                auto_bind=True,
            )
        else:
            lookup = Connection(server, receive_timeout=config.LDAP_TIMEOUT_SEC, auto_bind=True)

        if not lookup.search(search_base, filt, search_scope=SUBTREE, attributes=["distinguishedName"]):
            lookup.unbind()
            return None, None
        if not lookup.entries:
            lookup.unbind()
            return None, None

        entry = lookup.entries[0]
        dn = str(entry.entry_dn)
        lookup.unbind()
        return dn, dn
    except Exception as e:
        logger.warning("LDAP user lookup failed for %s: %s", username, e)
        return None, None


def _ldap_group_allowed(conn, user_dn: str, username: str, escape_filter_chars) -> bool:
    required_dn = config.LDAP_REQUIRED_GROUP.strip()
    required_cn = config.LDAP_REQUIRED_GROUP_CN.strip()
    if not required_dn and not required_cn:
        return True

    member_of = _ldap_member_of(conn, user_dn, username, escape_filter_chars)
    if required_dn:
        required = required_dn.lower()
        if any(g.lower() == required for g in member_of):
            return True

    if required_cn:
        needle = f"cn={required_cn.lower()},"
        if any(g.lower().startswith(needle) or f",cn={required_cn.lower()}," in g.lower() for g in member_of):
            return True
        # Active Directory groups are sometimes returned as CN=Group,...
        if any(g.lower().startswith(f"cn={required_cn.lower()}") for g in member_of):
            return True

    if user_dn and required_cn:
        group_filter = (
            f"(&(objectClass=group)(cn={escape_filter_chars(required_cn)})(member={escape_filter_chars(user_dn)}))"
        )
        search_base = config.LDAP_GROUP_SEARCH_BASE.strip() or config.LDAP_USER_SEARCH_BASE.strip()
        if search_base and conn.search(search_base, group_filter, search_scope=SUBTREE, size_limit=1):
            if conn.entries:
                return True

    return not (required_dn or required_cn)


def _ldap_member_of(conn, user_dn: str, username: str, escape_filter_chars) -> list[str]:
    from ldap3 import SUBTREE

    groups: list[str] = []
    search_base = config.LDAP_USER_SEARCH_BASE.strip()
    user_filter = config.LDAP_USER_SEARCH_FILTER.strip()
    if search_base and user_filter:
        filt = user_filter.format(username=escape_filter_chars(username))
        if conn.search(search_base, filt, search_scope=SUBTREE, attributes=["memberOf"]):
            for entry in conn.entries:
                if "memberOf" in entry:
                    groups.extend(str(v) for v in entry.memberOf.values)

    if not groups and user_dn:
        attr = config.LDAP_MEMBER_OF_ATTR
        filt = f"(distinguishedName={escape_filter_chars(user_dn)})"
        base = config.LDAP_USER_SEARCH_BASE.strip() or ""
        if base and conn.search(base, filt, search_scope=SUBTREE, attributes=[attr]):
            for entry in conn.entries:
                if attr in entry:
                    groups.extend(str(v) for v in entry[attr].values)
    return groups
