import socket
from codecs import encode

WHOIS_SERVER = "whois.iana.org"


def whois_lookup(domain: str):
    domain_bytes = encode(domain.strip(), "idna")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((WHOIS_SERVER, 43))
    s.send(domain_bytes + b"\r\n")
    response = read_response(s)
    s.close()
    record = parse_record(response)
    whois_server = record.get(b"whois")
    if not whois_server:
        raise ValueError("No whois server found")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((whois_server, 43))
    s.send(domain_bytes + b"\r\n")
    response = read_response(s)
    s.close()
    return response.decode()


def read_response(s: socket.socket) -> bytes:
    response = b""
    while True:
        data = s.recv(1024)
        if not data:
            break
        response += data
    return response


def parse_record(record: bytes) -> dict[bytes, bytes]:
    result: dict[bytes, bytes] = {}
    for line in record.split(b"\n"):
        if line.startswith(b"%"):
            continue
        if b":" not in line:
            continue
        key, value = line.split(b":", 1)
        result[key.strip()] = value.strip()
    return result
