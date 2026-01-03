import json
import os
import struct
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

# Minimal Amazon EventStream framing:
# total_len (4) + headers_len (4) + prelude_crc (4) + headers + payload + msg_crc (4)
# NOTE: This version emits zeros for CRCs for simplicity.
# If your client validates CRCs strictly, re-implement in Rust with aws_smithy_eventstream.

FIXTURES_DIR = os.environ.get("MOCK_BEDROCK_FIXTURES", ".dev/mocks/mock-bedrock/fixtures")


def encode_headers(event_type):
    # headers are: name_len(1) name bytes + type(1) + value...
    # We'll send:
    # :message-type = "event"
    # :event-type = event_type
    # :content-type = "application/json"
    def h(name, val):
        nb = name.encode()
        vb = val.encode()
        return (
            struct.pack("!B", len(nb))
            + nb
            + struct.pack("!B", 7)
            + struct.pack("!H", len(vb))
            + vb
        )  # type=7 string

    return b"".join(
        [
            h(":message-type", "event"),
            h(":event-type", event_type),
            h(":content-type", "application/json"),
        ]
    )


def encode_message(event_type, payload_bytes):
    headers = encode_headers(event_type)
    headers_len = len(headers)
    total_len = 4 + 4 + 4 + headers_len + len(payload_bytes) + 4
    prelude = struct.pack("!II", total_len, headers_len)
    prelude_crc = struct.pack("!I", 0)
    msg_wo_crc = prelude + prelude_crc + headers + payload_bytes
    msg_crc = struct.pack("!I", 0)
    return msg_wo_crc + msg_crc


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        p = urlparse(self.path).path
        if "/converse-stream" not in p:
            self.send_response(404)
            self.end_headers()
            return

        fixture = self.headers.get("x-mock-fixture", "basic_text")
        fixture_path = os.path.join(FIXTURES_DIR, f"{fixture}.json")
        if not os.path.exists(fixture_path):
            self.send_response(400)
            self.end_headers()
            self.wfile.write(f"unknown fixture: {fixture}".encode("utf-8"))
            return

        with open(fixture_path, "rb") as f:
            events = json.loads(f.read().decode())

        self.send_response(200)
        self.send_header("content-type", "application/vnd.amazon.eventstream")
        self.end_headers()

        for ev in events:
            b = json.dumps(ev["payload"]).encode("utf-8")
            msg = encode_message(ev["event_type"], b)
            self.wfile.write(msg)
            self.wfile.flush()
            time.sleep(0.02)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8081), H).serve_forever()
