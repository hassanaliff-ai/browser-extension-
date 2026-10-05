"""Bounded public HTTPS reading. No script execution, redirects or private networks."""
import hashlib
import http.client
import ipaddress
import socket
import ssl
import time
import idna
from html.parser import HTMLParser
from urllib.parse import urlsplit, urlunsplit

MAX_BYTES = 256 * 1024


class ContentReadError(ValueError):
    pass


class PageText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hidden = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in {'script', 'style', 'noscript', 'template'}:
            self.hidden += 1

    def handle_endtag(self, tag):
        if tag in {'script', 'style', 'noscript', 'template'} and self.hidden:
            self.hidden -= 1

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def extract_text(data: bytes, content_type: str) -> dict:
    if len(data) > MAX_BYTES:
        raise ContentReadError('Content exceeds the 256 KiB reading limit')
    if content_type.split(';')[0].strip().lower() not in {'text/html', 'text/plain', 'application/json', 'text/javascript', 'application/javascript', 'text/markdown', 'text/csv'}:
        raise ContentReadError('Only bounded UTF-8 text is read; binary files use hash evidence')
    try:
        text = data.decode('utf-8-sig', errors='strict')
    except UnicodeError:
        raise ContentReadError('Only UTF-8 text content is supported') from None
    if '\x00' in text:
        raise ContentReadError('Binary content is not supported')
    if content_type.split(';')[0].strip().lower() == 'text/html':
        parser = PageText()
        parser.feed(text)
        text = ' '.join(parser.parts)
    return {'text': ' '.join(text.split())[:12000], 'sha256': hashlib.sha256(data).hexdigest(), 'bytes_read': len(data)}


def public_url(value: str) -> tuple[str, str]:
    try:
        parsed = urlsplit(value)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.port not in {None, 443}:
            raise ValueError()
        if any(ord(c) <= 32 for c in value) or '\\' in value or len(value) > 2048:
            raise ValueError()
        host = parsed.hostname.rstrip('.').lower()
        if ':' not in host:
            host = idna.encode(host, uts46=True, transitional=False).decode('ascii')
        if host in {'localhost', 'localhost.localdomain'} or host.endswith(('.localhost', '.local', '.internal')):
            raise ValueError()
        clean = urlunsplit(('https', '['+host+']' if ':' in host else host, parsed.path or '/', '', ''))
    except (ValueError, UnicodeError):
        raise ContentReadError('Choose a public HTTPS URL without credentials or a custom port') from None
    return clean, host


def resolve_public(host: str) -> list[str]:
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
    except OSError:
        raise ContentReadError('Public hostname lookup failed') from None
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ContentReadError('Private, local and reserved networks cannot be read')
    return addresses


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str):
        super().__init__(host, timeout=8, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        # Connect to the validated IP without resolving the hostname again.
        raw = socket.create_connection((self.address, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def read_public_page(value: str) -> dict:
    clean, host = public_url(value)
    addresses = resolve_public(host)
    connection = PinnedHTTPS(host, addresses[0])
    try:
        connection.request('GET', urlsplit(clean).path or '/', headers={
            'User-Agent': 'ExtSecure/0.6 public-text-review', 'Accept': 'text/html,text/plain,application/json',
            'Accept-Encoding': 'identity', 'Connection': 'close',
        })
        response = connection.getresponse()
        if response.status != 200:
            raise ContentReadError('Page unavailable; redirects are not followed')
        if response.getheader('Content-Encoding', 'identity').lower() != 'identity':
            raise ContentReadError('Compressed responses are not read')
        length = response.getheader('Content-Length')
        if length and (not length.isdigit() or int(length) > MAX_BYTES):
            raise ContentReadError('Page exceeds the bounded reading limit')
        deadline = time.monotonic() + 10
        chunks, size = [], 0
        while size <= MAX_BYTES:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ContentReadError('Page reading exceeded its time limit')
            if connection.sock:
                connection.sock.settimeout(min(remaining, 3))
            chunk = response.read1(min(8192, MAX_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        data = b''.join(chunks)
        return {**extract_text(data, response.getheader('Content-Type', '')), 'url': clean}
    except ContentReadError:
        raise
    except (OSError, http.client.HTTPException, ValueError):
        raise ContentReadError('Public page could not be read securely') from None
    finally:
        connection.close()
