import ipaddress
import socket
from pathlib import Path
from urllib.parse import urlparse

BLOCKED_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

BLOCKED_HOSTNAMES = {
    "localhost",
    "host.docker.internal",
    "metadata.google.internal",
    "169.254.169.254",
}

BLOCKED_PORTS = {6379, 5432, 3306, 27017, 9200, 8500, 2379}


def validate_scan_url(url: str) -> str:
    if not url:
        raise ValueError("URL vacia")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Scheme no permitido: {parsed.scheme}")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL sin hostname")
    hostname_lower = hostname.lower()
    if hostname_lower in BLOCKED_HOSTNAMES:
        raise ValueError(f"Hostname bloqueado: {hostname}")
    port = parsed.port
    if port and port in BLOCKED_PORTS:
        raise ValueError(f"Puerto bloqueado: {port}")
    try:
        resolved_ips = socket.getaddrinfo(hostname, port or 443)
        for family, type_, proto, canonname, sockaddr in resolved_ips:
            ip_str = sockaddr[0]
            ip = ipaddress.ip_address(ip_str)
            for blocked_range in BLOCKED_IP_RANGES:
                if ip in blocked_range:
                    raise ValueError(f"URL resuelve a IP interna: {hostname} -> {ip_str}")
    except socket.gaierror as exc:
        raise ValueError(f"No se pudo resolver DNS: {hostname}") from exc
    dangerous_chars = set(";|&`$(){}[]<>\n\r\\")
    if dangerous_chars.intersection(set(url)):
        raise ValueError("URL contiene caracteres peligrosos")
    return url


def validate_scan_path(path: str, base_dir: str = "/app/data") -> str:
    if not path:
        raise ValueError("Path vacio")
    base = Path(base_dir).resolve()
    base.mkdir(parents=True, exist_ok=True)
    target = Path(path).resolve()
    try:
        target.relative_to(base)
    except ValueError as exc:
        raise ValueError(f"Path fuera del directorio permitido: {target}") from exc
    dangerous = set(";|&`$(){}[]<>\n\r")
    if dangerous.intersection(set(path)):
        raise ValueError("Path contiene caracteres peligrosos")
    dangerous_extensions = {".py", ".sh", ".bash", ".js", ".php", ".rb", ".pl", ".conf", ".service"}
    if target.suffix.lower() in dangerous_extensions:
        raise ValueError(f"Extension no permitida: {target.suffix}")
    target.parent.mkdir(parents=True, exist_ok=True)
    return str(target)


def validate_target_path(path: str, base_dir: str = "/app/data") -> str:
    validated = validate_scan_path(path, base_dir=base_dir)
    target = Path(validated)
    if not target.exists():
        raise ValueError(f"Path no existe: {validated}")
    sensitive_patterns = {
        ".env",
        ".git",
        ".ssh",
        "id_rsa",
        "password",
        "secret",
        "credentials",
        ".pem",
        ".key",
        "shadow",
        "passwd",
    }
    name_lower = target.name.lower()
    if any(pattern in name_lower for pattern in sensitive_patterns):
        raise ValueError(f"No se permite escanear archivos sensibles: {target.name}")
    return validated
