#!/usr/bin/env python3
"""Test Python TLS trust against the eMudhra incident endpoints."""

import ssl
import sys
import urllib.error
import urllib.request

C_PASS = "\033[0;32;40m"
C_WARN = "\033[0;33;40m"
C_FAIL = "\033[0;31;40m"
C_RESET = "\033[0m"


# https://bugzilla.mozilla.org/show_bug.cgi?id=2083449
HOSTS = (
    "dv-g3b-emudhra.we-have-a-problem.com",
    "dv-g3b-aaa-emudhra.we-have-a-problem.com",
    "dv-g3b-noct-emudhra.we-have-a-problem.com",
    "dv-g3b-aaa-noct-emudhra.we-have-a-problem.com",
)

TIMEOUT = 12


def is_cert_error(exc):
    """Recognize certificate validation failures."""
    seen = set()

    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))

        if isinstance(exc, ssl.SSLCertVerificationError):
            return True

        reason = str(exc).lower()
        markers = (
            "certificate_verify_failed",
            "certificate verify failed",
            "unable to get local issuer certificate",
            "self-signed certificate",
            "certificate has expired",
            "certificate is not yet valid",
            "certificate revoked",
        )

        if any(marker in reason for marker in markers):
            return True

        exc = (
            getattr(exc, "reason", None)
            or getattr(exc, "__cause__", None)
            or getattr(exc, "__context__", None)
        )

    return False


def urllib_default(url):
    return urllib.request.urlopen(url, timeout=TIMEOUT)


def urllib_certifi(url):
    import certifi

    context = ssl.create_default_context(cafile=certifi.where())
    return urllib.request.urlopen(
        url, timeout=TIMEOUT, context=context
    )


def requests_default(url):
    import requests

    return requests.get(url, timeout=TIMEOUT, stream=True)


def requests_certifi(url):
    import certifi
    import requests

    return requests.get(
        url,
        timeout=TIMEOUT,
        stream=True,
        verify=certifi.where(),
    )


def probe(label, url, request):
    response = None

    try:
        response = request(url)

    except urllib.error.HTTPError:
        # HTTP response received: TLS verification succeeded.
        print(
            f"{C_FAIL}FAIL{C_RESET}  {label:16} {url} "
            "(TLS accepted; HTTP error)"
        )
        return 1

    except Exception as exc:
        if is_cert_error(exc):
            print(
                f"{C_PASS}PASS{C_RESET}  {label:16} {url} "
                "(certificate rejected)"
            )
            return 0

        print(
            f"{C_WARN}WARN{C_RESET}  {label:16} {url} "
            f"({type(exc).__name__}: {exc})"
        )
        return 2

    finally:
        if response is not None:
            response.close()

    print(
        f"{C_FAIL}FAIL{C_RESET}  {label:16} {url} "
        "(TLS accepted)"
    )
    return 1


def main():
    print(f"Python:  {sys.executable}")
    print(f"OpenSSL: {ssl.OPENSSL_VERSION}")
    print(f"Default CA paths: {ssl.get_default_verify_paths()}")

    try:
        import certifi

        print(f"certifi: {certifi.__version__} ({certifi.where()})")
    except ImportError:
        print("certifi: not installed")

    tests = (
        ("urllib-system", urllib_default),
        ("requests-default", requests_default),
        ("urllib-certifi", urllib_certifi),
        ("requests-certifi", requests_certifi),
    )

    failures = 0
    warnings = 0

    for label, request in tests:
        for host in HOSTS:
            result = probe(label, f"https://{host}/", request)
            failures += result == 1
            warnings += result == 2

    print("\nSummary: ", end="")
    print(
        f"{C_FAIL}{failures} FAIL{C_RESET}, "
        f"{C_WARN}{warnings} WARN{C_RESET}"
    )

    if failures:
        return 1
    if warnings:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
