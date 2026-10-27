#!/usr/bin/env python3
# Filename: check-emudhra-purge.py
"""Validates pip version, certifi version, and absence of eMudhra/emSign certificates."""

import os
import sys
import pip
import certifi

MIN_PIP_VERSION = (26, 2, 2)
MIN_CERTIFI_VERSION = (2026, 10, 19)
TARGET_KEYWORDS = ("eMudhra", "emSign", "AAA Certificate Services")

COLOR_GREEN = "\033[0;32m"
COLOR_RED = "\033[0;31m"
COLOR_RESET = "\033[0m"


def parse_version(version_string: str) -> tuple[int, ...]:
    """Extracts numeric version components from a version string."""
    clean_version = version_string.split("+")[0].split("a")[0].split("b")[0]
    return tuple(int(component) for component in clean_version.split(".")[:3])


def check_pip_version() -> bool:
    """Verifies that the installed pip version meets or exceeds the minimum threshold."""
    current_version = parse_version(pip.__version__)
    is_valid = current_version >= MIN_PIP_VERSION
    status_symbol = f"{COLOR_GREEN}✅{COLOR_RESET}" if is_valid else f"{COLOR_RED}❌{COLOR_RESET}"
    print(f"{status_symbol} pip version: {pip.__version__}")
    return is_valid


def check_certifi_version() -> bool:
    """Verifies that the installed certifi version meets or exceeds the minimum threshold."""
    current_version = parse_version(certifi.__version__)
    is_valid = current_version >= MIN_CERTIFI_VERSION
    status_symbol = f"{COLOR_GREEN}✅{COLOR_RESET}" if is_valid else f"{COLOR_RED}❌{COLOR_RESET}"
    print(f"{status_symbol} certifi version: {certifi.__version__}")
    return is_valid


def check_certificate_purging() -> bool:
    """Verifies the complete absence of blacklisted CA strings in active certifi bundle."""
    bundle_path = certifi.where()
    if not os.path.exists(bundle_path):
        print(f"{COLOR_RED}❌{COLOR_RESET} Certificate bundle not found at {bundle_path}")
        return False

    with open(bundle_path, "r", encoding="utf-8", errors="ignore") as bundle_file:
        content = bundle_file.read()

    found_keywords = [keyword for keyword in TARGET_KEYWORDS if keyword in content]
    is_clean = len(found_keywords) == 0

    if is_clean:
        print(f"{COLOR_GREEN}✅{COLOR_RESET} eMudhra/emSign/AAA certificates removed from {bundle_path}")
    else:
        keywords_str = ", ".join(found_keywords)
        print(f"{COLOR_RED}❌{COLOR_RESET} Blacklisted certificates present in bundle: {keywords_str}")

    return is_clean


def main() -> None:
    """Executes all validation checks and exits with appropriate status code."""
    pip_ok = check_pip_version()
    certifi_ok = check_certifi_version()
    purge_ok = check_certificate_purging()

    if pip_ok and certifi_ok and purge_ok:
        sys.exit(0)
    sys.exit(1)


if __name__ == "__main__":
    main()