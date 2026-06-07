"""Well-known local log subdirectories under /var/log (not remote host folders)."""

from __future__ import annotations

import re

# Common first-level dirs on Debian/Ubuntu, RHEL/Fedora, openSUSE, and cousins.
LOCAL_LOG_SUBDIRS = frozenset({
    "anaconda",
    "apache2",
    "apt",
    "audit",
    "auth",
    "chrony",
    "cups",
    "dist-upgrade",
    "gdm",
    "gdm3",
    "glusterfs",
    "hosts",
    "httpd",
    "installer",
    "kerberos",
    "landscape",
    "letsencrypt",
    "libvirt",
    "lighttpd",
    "lxc",
    "mail",
    "meldung",
    "mysql",
    "nginx",
    "openvpn",
    "php",
    "postfix",
    "postgres",
    "postgresql",
    "private",
    "qemu-ga",
    "redis",
    "rhsm",
    "samba",
    "speech-dispatcher",
    "sssd",
    "supervisor",
    "sysstat",
    "tuned",
    "unattended-upgrades",
    "wicked",
    "wpa_supplicant",
    "xen",
    "yast",
    "zypp",
})

_IPV4_DIR = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_IPV6_DIR = re.compile(r"^[0-9a-fA-F:]+$")


def is_local_log_subdir(name: str) -> bool:
    return name.lower() in LOCAL_LOG_SUBDIRS


def looks_like_remote_host_dir(name: str) -> bool:
    """IP-like or unknown top-level dir → treat as a remote/host group."""
    if _IPV4_DIR.match(name):
        return True
    if ":" in name and _IPV6_DIR.match(name):
        return True
    return not is_local_log_subdir(name)
