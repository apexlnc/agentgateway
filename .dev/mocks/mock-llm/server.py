import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


def send_json(h, code, obj):
    b = json.dumps(obj).encode("utf-8")
    h.send_response(code)
    h.send_header("content-type", "application/json")
    h.send_header("content-length", str(len(b)))
    h.end_headers()
    h.wfile.write(b)


def send_sse(h, events):
    h.send_response(200)
    h.send_header("content-type", "text/event-stream")
    h.send_header("cache-control", "no-cache")
    h.send_header("connection", "keep-alive")
    h.end_headers()
    for ev in events:
        h.wfile.write(f"event: {ev.get('event', 'message')}\n".encode())
        h.wfile.write(f"data: {json.dumps(ev['data'])}\n\n".encode())
        h.wfile.flush()
        time.sleep(ev.get("sleep", 0.02))


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(n).decode("utf-8") if n else ""
        try:
            req = json.loads(raw) if raw else {}
        except Exception:
            req = {"_raw": raw}

        # OpenAI Chat Completions mock
        if self.path.startswith("/v1/chat/completions"):
            return send_json(
                self,
                200,
                {
                    "id": "chatcmpl_mock",
                    "object": "chat.completion",
                    "created": 0,
                    "model": req.get("model") or "mock-model",
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": "hello from mock /v1/chat/completions",
                            },
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 1,
                        "completion_tokens": 1,
                        "total_tokens": 2,
                    },
                },
            )

        # Anthropic Messages mock
        if self.path.startswith("/v1/messages"):
            if req.get("stream"):
                # minimal SSE-ish stream used for your gateway streaming regression tests
                events = [
                    {
                        "event": "message_start",
                        "data": {
                            "type": "message_start",
                            "message": {
                                "id": "msg_mock",
                                "role": "assistant",
                                "model": req.get("model", "mock"),
                            },
                        },
                    },
                    {
                        "event": "content_block_start",
                        "data": {
                            "type": "content_block_start",
                            "index": 0,
                            "content_block": {"type": "text", "text": ""},
                        },
                    },
                    {
                        "event": "content_block_delta",
                        "data": {
                            "type": "content_block_delta",
                            "index": 0,
                            "delta": {"type": "text_delta", "text": "hel"},
                        },
                    },
                    {
                        "event": "content_block_delta",
                        "data": {
                            "type": "content_block_delta",
                            "index": 0,
                            "delta": {"type": "text_delta", "text": "lo"},
                        },
                    },
                    {
                        "event": "content_block_stop",
                        "data": {"type": "content_block_stop", "index": 0},
                    },
                    {
                        "event": "message_delta",
                        "data": {
                            "type": "message_delta",
                            "delta": {
                                "stop_reason": "end_turn",
                                "stop_sequence": None,
                            },
                        },
                    },
                    {"event": "message_stop", "data": {"type": "message_stop"}},
                ]
                return send_sse(self, events)

            return send_json(
                self,
                200,
                {
                    "id": "msg_mock",
                    "type": "message",
                    "role": "assistant",
                    "model": req.get("model") or "mock-claude",
                    "content": [{"type": "text", "text": "hello from mock /v1/messages"}],
                    "stop_reason": "end_turn",
                    "stop_sequence": None,
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                },
            )

        return send_json(self, 404, {"error": f"no route for {self.path}"})


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), H).serve_forever()
