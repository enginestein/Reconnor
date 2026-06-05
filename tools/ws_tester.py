import json
import socket
import threading
import time
import urllib.request
import struct
import base64
import hashlib
from utils.output import section, info, success, warning, error, result, table


class WebSocketTester:
    description = "Advanced WebSocket security tester: origin bypass, message fuzzing, DoS, protocol weaknesses"

    @staticmethod
    def run(url="", target="", origin="", message="", fuzz=False, dos=False, timeout=15, **kwargs):
        section("WebSocket Security Tester")

        ws_url = url or target or ""
        if not ws_url:
            error("No WebSocket URL (use --url, e.g., ws://host/path)")
            return {"error": "no url"}

        if not ws_url.startswith("ws"):
            ws_url = f"ws://{ws_url}"

        result_data = {
            "url": ws_url,
            "origin_bypass": {"vulnerable": False, "tested_origins": []},
            "fuzzing": {"findings": []},
            "dos": {"vulnerable": False},
            "ssl": False,
        }

        if ws_url.startswith("wss://"):
            result_data["ssl"] = True

        parsed = ws_url.replace("ws://", "").replace("wss://", "").split("/")
        host = parsed[0].split(":")[0] if ":" in parsed[0] else parsed[0]
        port = int(parsed[0].split(":")[1]) if ":" in parsed[0] else (443 if ws_url.startswith("wss") else 80)
        path_comp = ws_url.split("/", 3)
        path = "/" + path_comp[3] if len(path_comp) > 3 else "/"

        # Origin bypass tests
        section("Origin Bypass Testing")
        test_origins = [origin] if origin else [
            "null",
            "http://evil.com",
            "https://evil.com",
            "http://evil.com:8080",
            f"http://{host}.evil.com",
            "file://",
            "http://localhost",
            "data:",
        ]

        for test_origin in test_origins:
            try:
                result = WebSocketTester._ws_connect(host, port, path, test_origin, timeout, ws_url.startswith("wss"))
                if result:
                    result_data["origin_bypass"]["tested_origins"].append(test_origin)
                    result_data["origin_bypass"]["vulnerable"] = True
                    warning(f"Origin bypass: {test_origin}")
                    break
            except:
                pass
        else:
            success("Origin validation enforced")

        # Connection info
        section("Connection Test")
        try:
            connect_result = WebSocketTester._ws_connect(host, port, path, None, timeout, ws_url.startswith("wss"))
            if connect_result:
                info(f"WebSocket connection successful to {ws_url}")
                result_data["connectable"] = True
            else:
                result_data["connectable"] = False
        except:
            warning("Could not establish WebSocket connection")
            result_data["connectable"] = False

        # Message fuzzing
        if fuzz:
            section("Message Fuzzing")
            fuzz_payloads = [
                "<script>alert(1)</script>",
                "' OR '1'='1",
                "../../etc/passwd",
                '{"__proto__": {"admin": true}}',
                '{"constructor": {"prototype": {"admin": true}}}',
                "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
                "A" * 10000,
                json.dumps({"cmd": "eval", "args": ["process.env"]}),
                '{"type": "subscribe", "channel": "admin"}',
                '{"method": "__proto__", "params": {"admin": true}}',
            ]

            if message:
                fuzz_payloads.insert(0, message)

            for payload in fuzz_payloads:
                try:
                    response = WebSocketTester._ws_send(host, port, path, payload, timeout, ws_url.startswith("wss"))
                    if response:
                        finding = {"payload": payload[:50], "response": response[:100]}
                        result_data["fuzzing"]["findings"].append(finding)
                        if len(response) > 5000:
                            warning(f"Large response ({len(response)} bytes) to payload: {payload[:30]}")
                except:
                    pass

        # DoS testing
        if dos:
            section("DoS Resistance Testing")
            try:
                start = time.time()
                sent = 0
                threads = []
                burst_lock = threading.Lock()

                def send_burst():
                    nonlocal sent
                    for _ in range(50):
                        try:
                            WebSocketTester._ws_send(host, port, path, "ping", timeout / 2, ws_url.startswith("wss"))
                            with burst_lock:
                                sent += 1
                        except:
                            pass

                for _ in range(10):
                    t = threading.Thread(target=send_burst)
                    threads.append(t)
                    t.start()

                for t in threads:
                    t.join(timeout=timeout)

                elapsed = time.time() - start
                rate = sent / elapsed if elapsed > 0 else 0
                info(f"Sent {sent} messages in {elapsed:.1f}s ({rate:.0f} msg/s)")

                if rate < 10:
                    warning(f"Connection degraded or closed at {rate:.0f} msg/s — possible DoS")
                    result_data["dos"]["vulnerable"] = True
                elif rate > 100:
                    success(f"Handled {rate:.0f} msg/s — resilient")
            except:
                pass

        section("WebSocket Scan Complete")
        return result_data

    @staticmethod
    def _ws_connect(host, port, path, origin, timeout, tls):
        try:
            import ssl
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.connect((host, port))

            key = base64.b64encode(hashlib.sha1(str(time.time()).encode()).digest()).decode()
            headers = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
            )
            if origin:
                headers += f"Origin: {origin}\r\n"
            headers += "\r\n"

            sock.send(headers.encode())
            response = sock.recv(4096).decode("utf-8", errors="replace")
            sock.close()
            return "101" in response
        except:
            return False

    @staticmethod
    def _ws_send(host, port, path, message, timeout, tls):
        try:
            import ssl
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.connect((host, port))

            key = base64.b64encode(hashlib.sha1(str(time.time()).encode()).digest()).decode()
            headers = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"\r\n"
            )
            sock.send(headers.encode())
            resp = sock.recv(4096)
            if b"101" not in resp:
                sock.close()
                return None

            # Send WebSocket frame
            payload = message.encode() if isinstance(message, str) else message
            frame = bytearray()
            frame.append(0x81)
            length = len(payload)
            if length < 126:
                frame.append(0x80 | length)
            elif length < 65536:
                frame.append(0x80 | 126)
                frame.extend(struct.pack(">H", length))
            else:
                frame.append(0x80 | 127)
                frame.extend(struct.pack(">Q", length))

            mask_key = b"abcd"
            frame.extend(mask_key)
            masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
            frame.extend(masked)
            sock.send(frame)

            # Read response frame
            response = sock.recv(4096)
            sock.close()

            if len(response) > 2:
                payload_len = response[1] & 0x7f
                if payload_len > 0:
                    return response[2:2+payload_len].decode("utf-8", errors="replace") if len(response) > 2 else ""
            return ""
        except:
            return None
