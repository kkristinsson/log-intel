from __future__ import annotations

import os

from flask_login import current_user

from log_intel.syslogb.app import config
from log_intel.syslogb.app.settings_registry import SETUP_COMPLETE_KEY
from log_intel.syslogb.app.store import AppStore


def is_setup_complete(store: AppStore) -> bool:
    return store.get(SETUP_COMPLETE_KEY) == "1"


def can_access_settings(store: AppStore) -> bool:
    if not is_setup_complete(store):
        return True
    if not config.AUTH_ENABLED:
        return True
    return is_settings_admin()


def is_settings_admin() -> bool:
    if not config.AUTH_ENABLED:
        return True
    if not current_user.is_authenticated:
        return False
    admins = os.environ.get("SETTINGS_ADMIN_USERS", "").strip()
    if admins:
        allowed = {u.strip() for u in admins.split(",") if u.strip()}
        return current_user.username in allowed
    local = config.LOCAL_AUTH_USERNAME.strip()
    if local and current_user.username == local:
        return True
    return current_user.method == "local" and bool(local)
