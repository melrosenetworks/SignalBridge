#!/usr/bin/env python3
"""
SignalVault ingest HTTP server for SignalBridge streaming output.

Receives POST data at /frames/{uuid} or /ingest/{uuid}. The UUID identifies the
endpoint configuration (see config/ingest_endpoints.yaml).

Configuration per endpoint:
  - destination: "signalvault" (writes to year/month/day/hour under {base_dir}/{uuid}/)
  - decryption_key: optional hex-encoded 32-byte key for AES-256-GCM
    - When present: decrypt, decompress gzip, append NDJSON to hourly .ndjson files
    - When absent: store encrypted payload as-is, append to hourly .bin files
  - ip_allow: optional list of allowed client IPs or CIDR ranges
  - credentials: optional { username, password } for HTTP Basic auth
  - api_key: optional API key; client sends X-API-Key or Authorization: Bearer <key>
  - mtls: optional { allowed_cns: [...] } to restrict to specific client cert CNs (requires --tls-client-ca)

Usage:
  python signalvault_ingest.py [--port PORT] [--config CONFIG] [--base-dir DIR]
  python signalvault_ingest.py --tls-cert cert.pem --tls-key key.pem [--tls-client-ca ca.pem]
"""

import argparse
import base64
import gzip
import ipaddress
import os
import re
import ssl
import sys
from datetime import datetime
from pathlib import Path

import yaml
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from http.server import HTTPServer, BaseHTTPRequestHandler

# Path pattern: /frames/{uuid} or /ingest/{uuid}
UUID_PATTERN = re.compile(
    r"^/(?:frames|ingest)/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/?$"
)

# AES-256-GCM layout from SignalBridge: [iv(12)][ciphertext][tag(16)]
IV_LEN = 12
TAG_LEN = 16


def hex_decode(hex_str: str) -> bytes | None:
    """Decode hex string to bytes. Returns None if invalid."""
    if len(hex_str) % 2 != 0:
        return None
    try:
        return bytes.fromhex(hex_str)
    except ValueError:
        return None


def aes_256_gcm_decrypt(key: bytes, ciphertext: bytes) -> bytes | None:
    """Decrypt AES-256-GCM. Input: [iv(12)][ciphertext][tag(16)]. Returns None on failure."""
    if len(key) != 32:
        return None
    if len(ciphertext) < IV_LEN + TAG_LEN:
        return None
    iv = ciphertext[:IV_LEN]
    tag = ciphertext[-TAG_LEN:]
    ct = ciphertext[IV_LEN:-TAG_LEN]
    try:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(iv, ct + tag, None)
    except Exception:
        return None


def load_config(config_path: str) -> dict:
    """Load ingest endpoint configuration from YAML."""
    with open(config_path, "r") as f:
        data = yaml.safe_load(f)
    return data.get("endpoints", {})


def client_ip_allowed(client_addr: str, ip_allow: list[str] | None) -> bool:
    """Return True if client IP is allowed (empty/None ip_allow = allow all)."""
    if not ip_allow:
        return True
    try:
        client_ip = ipaddress.ip_address(client_addr)
    except ValueError:
        return False
    for entry in ip_allow:
        try:
            if "/" in entry:
                if client_ip in ipaddress.ip_network(entry, strict=False):
                    return True
            else:
                if client_ip == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            continue
    return False


def check_basic_auth(auth_header: str | None, username: str, password: str) -> bool:
    """Return True if Authorization header matches expected Basic credentials."""
    if not username and not password:
        return True  # No auth required
    if not auth_header or not auth_header.strip().lower().startswith("basic "):
        return False
    try:
        decoded = base64.b64decode(auth_header[6:].strip()).decode("utf-8")
        if ":" not in decoded:
            return False
        u, p = decoded.split(":", 1)
        return u == username and p == password
    except Exception:
        return False


def check_api_key(headers: dict, expected_key: str) -> bool:
    """Return True if X-API-Key or Authorization: Bearer matches expected key."""
    if not expected_key:
        return True
    api_key = headers.get("X-Api-Key", "").strip()
    if api_key and api_key == expected_key:
        return True
    auth = headers.get("Authorization", "")
    if auth.strip().lower().startswith("bearer "):
        token = auth[7:].strip()
        if token == expected_key:
            return True
    return False


def get_client_cert_cn(connection) -> str | None:
    """Extract Common Name from client certificate, or None if not present."""
    try:
        cert = connection.getpeercert()
        if not cert:
            return None
        # subject is ((('commonName', 'cn'),),) or similar
        for sub in cert.get("subject", []):
            for k, v in sub:
                if k == "commonName":
                    return v
    except Exception:
        pass
    return None


def check_mtls_allowed(connection, mtls_config: dict | None, require_client_cert: bool) -> bool:
    """Return True if client cert is allowed. When require_client_cert, connection must have cert."""
    allowed_cns = mtls_config.get("allowed_cns") if mtls_config else None
    need_cert = require_client_cert or bool(allowed_cns)
    if not need_cert:
        return True
    cn = get_client_cert_cn(connection)
    if not cn:
        return False
    if not allowed_cns:
        return True
    return cn in allowed_cns


def get_hourly_path(base_dir: str, endpoint_id: str, dt: datetime, ext: str) -> Path:
    """Return path for hourly file: {base_dir}/{uuid}/{year}/{month}/{day}/{hour}.{ext}"""
    return (
        Path(base_dir)
        / endpoint_id
        / str(dt.year)
        / f"{dt.month:02d}"
        / f"{dt.day:02d}"
        / f"{dt.hour:02d}.{ext}"
    )


def append_to_file(path: Path, data: bytes) -> None:
    """Append data to file, creating parent dirs if needed."""
    import os

    os.makedirs(path.parent, exist_ok=True)
    with open(path, "ab") as f:
        f.write(data)


def create_handler(config_path: str, base_dir: str, require_client_cert: bool = False):
    """Create request handler with config and base_dir in closure."""

    class SignalVaultIngestHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            print(f"[Server] {args[0]}", flush=True)

        def do_POST(self):
            # Extract UUID from path
            match = UUID_PATTERN.match(self.path)
            if not match:
                self.send_error(404, f"Not found: path must be /frames/{{uuid}} or /ingest/{{uuid}}")
                return

            endpoint_id = match.group(1).lower()
            endpoints = load_config(config_path)
            cfg = endpoints.get(endpoint_id)

            if not cfg:
                self.send_error(404, f"Unknown endpoint: {endpoint_id}")
                return

            destination = cfg.get("destination")
            if destination != "signalvault":
                self.send_error(501, f"Destination '{destination}' not implemented")
                return

            # Optional IP whitelist
            ip_allow = cfg.get("ip_allow")
            if ip_allow is not None and not client_ip_allowed(self.client_address[0], ip_allow):
                self.send_error(403, "Forbidden: client IP not allowed")
                return

            # Optional mTLS: require client cert and/or restrict to allowed CNs
            mtls_config = cfg.get("mtls")
            if not check_mtls_allowed(self.connection, mtls_config, require_client_cert):
                self.send_error(403, "Forbidden: client certificate required or not allowed")
                return

            # Optional API key (X-API-Key or Authorization: Bearer)
            api_key = cfg.get("api_key") or ""
            if api_key:
                if not check_api_key(self.headers, api_key):
                    self.send_response(401)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"Unauthorized: invalid or missing API key\n")
                    return
            else:
                # Optional HTTP Basic auth (fallback when api_key not set)
                credentials = cfg.get("credentials") or {}
                expected_user = credentials.get("username") or ""
                expected_pass = credentials.get("password") or ""
                if expected_user or expected_pass:
                    auth_header = self.headers.get("Authorization")
                    if not check_basic_auth(auth_header, expected_user, expected_pass):
                        self.send_response(401)
                        self.send_header("WWW-Authenticate", 'Basic realm="SignalVault Ingest"')
                        self.send_header("Content-Type", "text/plain")
                        self.end_headers()
                        self.wfile.write(b"Unauthorized\n")
                        return

            decryption_key_hex = cfg.get("decryption_key")
            decryption_key = None
            if decryption_key_hex:
                decryption_key = hex_decode(decryption_key_hex)
                if not decryption_key or len(decryption_key) != 32:
                    self.send_error(500, "Invalid decryption_key in config")
                    return

            # Read body (Content-Length or read until EOF)
            content_length = self.headers.get("Content-Length")
            if content_length is not None:
                try:
                    body = self.rfile.read(int(content_length))
                except (ValueError, OSError):
                    body = b""
            else:
                body = b""
                while True:
                    chunk = self.rfile.read(8192)
                    if not chunk:
                        break
                    body += chunk

            # Respond early so client doesn't block
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"OK\n")
            except (BrokenPipeError, ConnectionResetError):
                pass

            if not body:
                print(f"[Server] Empty body for endpoint {endpoint_id}", flush=True)
                return

            now = datetime.utcnow()

            if decryption_key:
                # Decrypt and decompress, append NDJSON
                x_encryption = self.headers.get("X-Encryption", "").strip().lower()
                if x_encryption == "aes-256-gcm":
                    plain = aes_256_gcm_decrypt(decryption_key, body)
                    if not plain:
                        print(f"[Server] Decryption failed for endpoint {endpoint_id}", flush=True)
                        return
                    body = plain
                # Decompress if gzip
                x_content_encoding = self.headers.get("X-Content-Encoding", "").strip().lower()
                if x_content_encoding == "gzip" or body[:2] == b"\x1f\x8b":
                    try:
                        body = gzip.decompress(body)
                    except gzip.BadGzipFile:
                        print(f"[Server] Gzip decompress failed for endpoint {endpoint_id}", flush=True)
                        return
                # Ensure newline at end for NDJSON
                if body and not body.endswith(b"\n"):
                    body += b"\n"
                path = get_hourly_path(base_dir, endpoint_id, now, "ndjson")
                append_to_file(path, body)
                print(f"[Server] Appended {len(body)} bytes (decrypted) to {path}", flush=True)
            else:
                # Store encrypted as-is, append to binary file
                path = get_hourly_path(base_dir, endpoint_id, now, "bin")
                append_to_file(path, body)
                print(f"[Server] Appended {len(body)} bytes (encrypted) to {path}", flush=True)

    return SignalVaultIngestHandler


def main():
    parser = argparse.ArgumentParser(
        description="SignalVault ingest server for SignalBridge HTTP streaming"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=9876,
        help="Port to listen on (default: 9876)",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config/ingest_endpoints.yaml",
        help="Path to ingest endpoint config YAML",
    )
    parser.add_argument(
        "--base-dir",
        type=str,
        default="signalvault",
        help="Base directory for signalvault storage (default: signalvault)",
    )
    parser.add_argument(
        "--bind",
        type=str,
        default="127.0.0.1",
        help="Address to bind (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--tls-cert",
        type=str,
        default="",
        help="Path to TLS certificate (enables HTTPS)",
    )
    parser.add_argument(
        "--tls-key",
        type=str,
        default="",
        help="Path to TLS private key (required with --tls-cert)",
    )
    parser.add_argument(
        "--tls-client-ca",
        type=str,
        default="",
        help="Path to CA cert for client verification (enables mTLS)",
    )
    args = parser.parse_args()

    if args.tls_cert or args.tls_key:
        if not args.tls_cert or not args.tls_key:
            print("Error: --tls-cert and --tls-key must both be provided", file=sys.stderr)
            sys.exit(1)
        if not os.path.isfile(args.tls_cert) or not os.path.isfile(args.tls_key):
            print("Error: TLS cert or key file not found", file=sys.stderr)
            sys.exit(1)
    if args.tls_client_ca and not os.path.isfile(args.tls_client_ca):
        print("Error: TLS client CA file not found", file=sys.stderr)
        sys.exit(1)

    config_path = args.config
    if not os.path.isfile(config_path):
        # Try relative to script
        script_dir = Path(__file__).resolve().parent.parent
        config_path = script_dir / "config" / "ingest_endpoints.yaml"
        if not config_path.is_file():
            print(f"Error: Config not found: {args.config}", file=sys.stderr)
            sys.exit(1)
        config_path = str(config_path)

    require_client_cert = bool(args.tls_client_ca)
    handler = create_handler(config_path, args.base_dir, require_client_cert)
    server = HTTPServer((args.bind, args.port), handler)

    if args.tls_cert and args.tls_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.tls_cert, args.tls_key)
        if args.tls_client_ca:
            context.load_verify_locations(cafile=args.tls_client_ca)
            context.verify_mode = ssl.CERT_REQUIRED
        server.socket = context.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    else:
        scheme = "http"

    print(
        f"SignalVault ingest server on {scheme}://{args.bind}:{args.port}",
        f"(config: {config_path}, base-dir: {args.base_dir})",
        flush=True,
    )
    if require_client_cert:
        print("mTLS enabled: client certificate required", flush=True)
    print("POST /frames/{uuid} or /ingest/{uuid} to receive data", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
