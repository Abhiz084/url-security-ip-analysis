"""
SSRF (Server-Side Request Forgery) Protection

Prevents the URL scanner from being weaponized to:
- Scan internal networks (192.168.x.x, 10.x.x.x)
- Access cloud metadata services (169.254.169.254)
- Reach localhost services (127.0.0.1, ::1)
- Hit reserved / broadcast ranges

Also defends against:
- IP encoding tricks (decimal, octal, hex, IPv4-mapped IPv6)
- DNS rebinding (re-check before actual request)
- Redirect chains pointing to internal IPs

Workflow:
    URL → parse → resolve → get IPs → validate → ALLOW or BLOCK
"""

import ipaddress
import socket
import re
from urllib.parse import urlparse
from dataclasses import dataclass
from typing import List, Optional
from loguru import logger


# ============================================
# EXCEPTIONS
# ============================================

class SSRFProtectionError(Exception):
    """Raised when a URL targets an internal/forbidden resource"""
    def __init__(self, message, url=None, ip=None, reason=None):
        self.url = url
        self.ip = ip
        self.reason = reason
        super().__init__(message)


# ============================================
# CONFIGURATION
# ============================================

# Cloud metadata endpoints (very sensitive!)
METADATA_IPS = {
    '169.254.169.254',  # AWS, Azure, GCP, DigitalOcean
    'fd00:ec2::254',    # AWS IPv6 metadata
    '100.100.100.200',  # Alibaba Cloud
}

# Additional blocked hostnames (case-insensitive)
BLOCKED_HOSTNAMES = {
    'localhost',
    'localhost.localdomain',
    'metadata.google.internal',
    'metadata',
    'instance-data',
}

# Schemes we accept (everything else is refused)
ALLOWED_SCHEMES = {'http', 'https'}

# Max URL length (defense against buffer tricks)
MAX_URL_LENGTH = 4096

# Default socket timeout for DNS resolution
DNS_TIMEOUT_SECONDS = 5


# ============================================
# RESULT DATACLASS
# ============================================

@dataclass
class SSRFCheckResult:
    """Result of SSRF validation"""
    is_safe: bool
    url: str
    hostname: str
    resolved_ips: List[str]
    reason: Optional[str] = None
    blocked_ip: Optional[str] = None

    def to_dict(self):
        return {
            'is_safe': self.is_safe,
            'url': self.url,
            'hostname': self.hostname,
            'resolved_ips': self.resolved_ips,
            'reason': self.reason,
            'blocked_ip': self.blocked_ip,
        }


# ============================================
# IP CLASSIFICATION
# ============================================

def is_private_ip(ip_str):
    """
    Check if an IP is private / loopback / link-local / reserved / etc.

    Returns: (is_blocked: bool, reason: str | None)
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, "invalid_ip_format"

    # Cloud metadata (highest priority)
    if str(ip) in METADATA_IPS:
        return True, "cloud_metadata_endpoint"

    # IPv4-mapped IPv6 (::ffff:127.0.0.1 — an encoding trick)
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            # Recurse on the mapped IPv4
            return is_private_ip(str(ip.ipv4_mapped))

    # Explicit checks
    if ip.is_loopback:
        return True, "loopback"
    if ip.is_private:
        return True, "private_range"
    if ip.is_link_local:
        return True, "link_local"
    if ip.is_reserved:
        return True, "reserved"
    if ip.is_multicast:
        return True, "multicast"
    if ip.is_unspecified:
        return True, "unspecified"

    # Broadcast
    if isinstance(ip, ipaddress.IPv4Address) and str(ip) == '255.255.255.255':
        return True, "broadcast"

    return False, None


# ============================================
# IP ENCODING DETECTION
# ============================================

def _looks_like_decimal_ip(host):
    """Detect decimal IP encoding, e.g. 2130706433 == 127.0.0.1"""
    if host.isdigit():
        try:
            n = int(host)
            if 0 <= n <= 0xFFFFFFFF:
                return True
        except ValueError:
            pass
    return False


def _looks_like_hex_ip(host):
    """Detect hex IP like 0x7f000001"""
    return bool(re.match(r'^0x[0-9a-fA-F]+$', host))


def _looks_like_octal_ip(host):
    """Detect octal IP like 0177.0.0.1"""
    parts = host.split('.')
    if len(parts) != 4:
        return False
    return all(re.match(r'^0[0-7]+$', p) or p.isdigit() for p in parts)


def _decode_decimal_ip(host):
    """Convert 2130706433 → 127.0.0.1"""
    try:
        n = int(host)
        return str(ipaddress.IPv4Address(n))
    except Exception:
        return None


def _decode_hex_ip(host):
    """Convert 0x7f000001 → 127.0.0.1"""
    try:
        n = int(host, 16)
        return str(ipaddress.IPv4Address(n))
    except Exception:
        return None


def _decode_octal_ip(host):
    """Convert 0177.0.0.1 → 127.0.0.1"""
    try:
        parts = host.split('.')
        decimal_parts = [int(p, 8) if p.startswith('0') else int(p) for p in parts]
        ip_int = (
            (decimal_parts[0] << 24) |
            (decimal_parts[1] << 16) |
            (decimal_parts[2] << 8) |
            decimal_parts[3]
        )
        return str(ipaddress.IPv4Address(ip_int))
    except Exception:
        return None


def normalize_host_if_ip_encoded(host):
    """
    Detect encoded IP tricks and return the canonical dotted form.
    Returns None if host is not an encoded IP.
    """
    if _looks_like_decimal_ip(host):
        return _decode_decimal_ip(host)
    if _looks_like_hex_ip(host):
        return _decode_hex_ip(host)
    if _looks_like_octal_ip(host):
        return _decode_octal_ip(host)
    return None


# ============================================
# DNS RESOLUTION
# ============================================

def resolve_hostname(hostname, timeout=DNS_TIMEOUT_SECONDS):
    """
    Resolve a hostname to a list of IPs (IPv4 + IPv6).

    Returns: list of IP strings
    """
    ips = set()
    original_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)

        # Get IPv4
        try:
            for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
                ips.add(info[4][0])
        except socket.gaierror:
            pass

        # Get IPv6
        try:
            for info in socket.getaddrinfo(hostname, None, socket.AF_INET6):
                ips.add(info[4][0])
        except socket.gaierror:
            pass

    except Exception as e:
        logger.debug(f"DNS resolution failed for {hostname}: {e}")
    finally:
        socket.setdefaulttimeout(original_timeout)

    return list(ips)


# ============================================
# MAIN VALIDATOR
# ============================================

def validate_external_destination(url, resolve=True):
    """
    Validate that a URL points to an external (safe) destination.

    Args:
        url: URL to validate
        resolve: If True, perform DNS resolution and validate all IPs

    Returns:
        SSRFCheckResult

    Raises:
        SSRFProtectionError: if the destination is unsafe
    """
    # -------- Basic input checks --------
    if not url or not isinstance(url, str):
        raise SSRFProtectionError(
            "URL must be a non-empty string",
            url=url, reason="invalid_input"
        )

    if len(url) > MAX_URL_LENGTH:
        raise SSRFProtectionError(
            f"URL exceeds max length ({MAX_URL_LENGTH})",
            url=url[:100], reason="url_too_long"
        )

    # -------- Parse --------
    try:
        # Add scheme if missing (so urlparse works)
        parsed_url = url if '://' in url else 'http://' + url
        parsed = urlparse(parsed_url)
    except Exception as e:
        raise SSRFProtectionError(
            f"Failed to parse URL: {e}",
            url=url, reason="parse_error"
        )

    # -------- Scheme check --------
    scheme = (parsed.scheme or '').lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SSRFProtectionError(
            f"Scheme '{scheme}' not allowed. Only {ALLOWED_SCHEMES} permitted.",
            url=url, reason=f"blocked_scheme:{scheme}"
        )

    # -------- Hostname check --------
    hostname = (parsed.hostname or '').lower().strip()
    if not hostname:
        raise SSRFProtectionError(
            "No hostname found in URL",
            url=url, reason="missing_hostname"
        )

    # Block known bad hostnames
    if hostname in BLOCKED_HOSTNAMES:
        raise SSRFProtectionError(
            f"Blocked hostname: {hostname}",
            url=url, reason="blocked_hostname"
        )

    # Block hostnames ending in .local, .internal, .localhost, etc.
    forbidden_suffixes = ['.local', '.internal', '.localhost', '.test', '.example']
    for suffix in forbidden_suffixes:
        if hostname.endswith(suffix):
            raise SSRFProtectionError(
                f"Reserved hostname suffix: {suffix}",
                url=url, reason=f"blocked_suffix:{suffix}"
            )

    # -------- Encoded IP checks --------
    decoded = normalize_host_if_ip_encoded(hostname)
    if decoded:
        # It's an encoded IP — validate the decoded form
        is_blocked, reason = is_private_ip(decoded)
        if is_blocked:
            raise SSRFProtectionError(
                f"Encoded IP ({hostname} → {decoded}) blocked: {reason}",
                url=url, ip=decoded, reason=f"encoded_ip:{reason}"
            )
        # Encoded IP to a public destination → allow but log
        logger.debug(f"Encoded IP decoded: {hostname} → {decoded}")
        hostname = decoded

    # -------- Direct IP check (no resolution needed) --------
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        is_blocked, reason = is_private_ip(hostname)
        if is_blocked:
            raise SSRFProtectionError(
                f"Direct IP target blocked: {hostname} ({reason})",
                url=url, ip=hostname, reason=reason
            )
        return SSRFCheckResult(
            is_safe=True,
            url=url,
            hostname=hostname,
            resolved_ips=[hostname],
        )

    # -------- DNS resolution --------
    if not resolve:
        return SSRFCheckResult(
            is_safe=True,
            url=url,
            hostname=hostname,
            resolved_ips=[],
            reason="skipped_resolution"
        )

    ips = resolve_hostname(hostname)
    if not ips:
        raise SSRFProtectionError(
            f"Could not resolve hostname: {hostname}",
            url=url, reason="dns_resolution_failed"
        )

    # -------- Validate ALL resolved IPs --------
    for ip in ips:
        is_blocked, reason = is_private_ip(ip)
        if is_blocked:
            raise SSRFProtectionError(
                f"Hostname {hostname} resolves to blocked IP {ip} ({reason})",
                url=url, ip=ip, reason=f"resolved_to_{reason}"
            )

    return SSRFCheckResult(
        is_safe=True,
        url=url,
        hostname=hostname,
        resolved_ips=ips,
    )


# ============================================
# SAFE WRAPPER (for requests library)
# ============================================

def safe_request(method, url, timeout=10, max_redirects=5, allow_redirects=False, **kwargs):
    """
    Perform an HTTP request only AFTER validating the destination.

    Use INSTEAD of requests.get / requests.post when the URL may be
    user-supplied.

    Redirects are NOT followed automatically — each redirect target
    is validated separately (SSRF-safe redirect handling).

    Returns: requests.Response

    Raises: SSRFProtectionError, requests.RequestException
    """
    try:
        import requests
    except ImportError:
        raise SSRFProtectionError("requests library not installed")

    # Validate initial URL
    validate_external_destination(url, resolve=True)

    current_url = url
    response = None
    history = []

    for _ in range(max_redirects + 1):
        response = requests.request(
            method,
            current_url,
            timeout=timeout,
            allow_redirects=False,
            **kwargs
        )

        # If not a redirect, we're done
        if not response.is_redirect and not response.is_permanent_redirect:
            break

        # Extract next URL
        next_url = response.headers.get('Location')
        if not next_url:
            break

        # Resolve relative redirects
        from urllib.parse import urljoin
        next_url = urljoin(current_url, next_url)

        # Validate the redirect target BEFORE following
        validate_external_destination(next_url, resolve=True)
        history.append(current_url)
        current_url = next_url

    return response


# ============================================
# SELF TEST
# ============================================

if __name__ == "__main__":
    print(f"\n{'=' * 80}")
    print("SSRF PROTECTION — SELF TEST")
    print(f"{'=' * 80}\n")

    test_urls = [
        # ✅ Should ALLOW
        ("https://www.google.com", "ALLOW"),
        ("https://github.com/torvalds", "ALLOW"),
        ("https://api.github.com/users", "ALLOW"),

        # 🚨 Should BLOCK — Direct private IPs
        ("http://127.0.0.1:8000/admin", "BLOCK"),
        ("http://localhost:3000", "BLOCK"),
        ("http://192.168.1.1/router", "BLOCK"),
        ("http://10.0.0.1/internal", "BLOCK"),
        ("http://172.16.0.1/vpn", "BLOCK"),

        # 🚨 Should BLOCK — Cloud metadata
        ("http://169.254.169.254/latest/meta-data/", "BLOCK"),
        ("http://metadata.google.internal/computeMetadata/", "BLOCK"),

        # 🚨 Should BLOCK — Encoded IPs
        ("http://2130706433/", "BLOCK"),           # Decimal 127.0.0.1
        ("http://0x7f000001/", "BLOCK"),           # Hex 127.0.0.1
        ("http://0177.0.0.1/", "BLOCK"),           # Octal 127.0.0.1
        ("http://[::1]/admin", "BLOCK"),           # IPv6 loopback

        # 🚨 Should BLOCK — Dangerous schemes
        ("file:///etc/passwd", "BLOCK"),
        ("gopher://internal:8080/", "BLOCK"),
        ("dict://internal:11211/", "BLOCK"),

        # 🚨 Should BLOCK — Reserved hostname suffixes
        ("http://something.local/", "BLOCK"),
        ("http://printer.internal/", "BLOCK"),
        ("http://myapp.test/", "BLOCK"),
    ]

    passed = 0
    for url, expected in test_urls:
        try:
            result = validate_external_destination(url, resolve=True)
            actual = "ALLOW"
            detail = f"→ {', '.join(result.resolved_ips) or 'no IPs'}"
        except SSRFProtectionError as e:
            actual = "BLOCK"
            detail = f"→ {e.reason or str(e)[:50]}"
        except Exception as e:
            actual = "ERROR"
            detail = f"→ {str(e)[:50]}"

        ok = "✅" if actual == expected else "❌"
        if actual == expected:
            passed += 1

        print(f"{ok} [{actual:<5}] {url[:55]:<55} {detail}")

    print(f"\n{'=' * 80}")
    print(f"📊 Passed: {passed}/{len(test_urls)} ({passed/len(test_urls)*100:.0f}%)")
    print(f"{'=' * 80}\n")