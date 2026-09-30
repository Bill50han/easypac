"""Black-box tests: YAML -> CGI response -> execute the generated PAC."""
import json
import http.client
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parent
BINARY = os.environ.get("PAC_BINARY", str(ROOT / "pac.cgi"))
NODE = os.environ.get("PAC_NODE") or shutil.which("node.exe") or shutil.which("node")

CONFIG = """
"校园 直连": &campus
  - NUAA.EDU.CN.
  - chaoxing.com
  - nuaa.edu.cn
另一个名字: *campus
代理:
  - example.com
  - a.example.com
直连例外:
  - cn.example.com
恢复代理:
  - deep.cn.example.com
proxy:
  - method: direct
    domains: ["校园 直连", 另一个名字, 直连例外]
  - method: http
    url: 127.0.0.1
    port: 7890
    domains: [代理, 恢复代理]
default:
  method: direct
"""


def execute(config=CONFIG, *, method=None, etag=None, args=()):
    env = os.environ.copy()
    for key in ("REQUEST_METHOD", "HTTP_IF_NONE_MATCH", "PAC_RULES"):
        env.pop(key, None)
    if method is not None:
        env["REQUEST_METHOD"] = method
    if etag is not None:
        env["HTTP_IF_NONE_MATCH"] = etag
    with tempfile.TemporaryDirectory(prefix="easypac-test-") as directory:
        path = Path(directory) / "rules.yaml"
        path.write_text(config, encoding="utf-8")
        return subprocess.run([BINARY, *args, str(path)], env=env, capture_output=True)


def response(result):
    headers, body = result.stdout.split(b"\r\n\r\n", 1)
    fields = dict(line.decode().split(": ", 1) for line in headers.split(b"\r\n"))
    return fields, body


def evaluate(body, hosts):
    if not NODE:
        raise RuntimeError("PAC execution tests require node or node.exe")
    script = body.decode() + '\nrequire("fs").writeSync(1, JSON.stringify(' + json.dumps(hosts) + ".map(function(h) {\n"
    script += 'return FindProxyForURL("https://" + h + "/", h); })));\n'
    result = subprocess.run([NODE, "--eval", script], capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace"))
    return json.loads(result.stdout)


class PacTests(unittest.TestCase):
    def test_groups_suffix_matching_and_exceptions(self):
        result = execute(method="GET")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        headers, body = response(result)
        self.assertEqual(headers["Status"], "200 OK")
        self.assertEqual(int(headers["Content-Length"]), len(body))
        hosts = ["nuaa.edu.cn", "WWW.NUAA.EDU.CN.", "example.com", "a.example.com",
                 "cn.example.com", "x.cn.example.com", "deep.cn.example.com",
                 "x.deep.cn.example.com", "notexample.com", "example.com.evil.org",
                 "unmatched.net", "127.0.0.1", "localhost", "constructor"]
        proxy = "PROXY 127.0.0.1:7890"
        self.assertEqual(evaluate(body, hosts), ["DIRECT", "DIRECT", proxy, proxy,
                         "DIRECT", "DIRECT", proxy, proxy, "DIRECT", "DIRECT",
                         "DIRECT", "DIRECT", "DIRECT", "DIRECT"])
        self.assertNotIn(b'"a.example.com"', body)
        self.assertNotIn(b'"chaoxing.com"', body)  # identical to the default

    def test_etag_and_head(self):
        headers, body = response(execute(method="GET"))
        tag = headers["ETag"]
        for conditional in [tag, "W/" + tag, '"other", W/' + tag, "*"]:
            cached, empty = response(execute(method="GET", etag=conditional))
            self.assertEqual(cached["Status"], "304 Not Modified")
            self.assertEqual(empty, b"")
        head, empty = response(execute(method="HEAD"))
        self.assertEqual(head["ETag"], tag)
        self.assertEqual(int(head["Content-Length"]), len(body))
        self.assertEqual(empty, b"")
        for conditional in ['"other"', tag + "invalid", "W/", "*invalid"]:
            fresh, _ = response(execute(method="GET", etag=conditional))
            self.assertEqual(fresh["Status"], "200 OK")

    def test_reordering_duplicates_and_case_do_not_change_pac(self):
        changed = CONFIG.replace("  - example.com\n  - a.example.com",
                                 "  - A.EXAMPLE.COM.\n  - example.com\n  - example.com")
        changed = changed.replace("  - NUAA.EDU.CN.\n  - chaoxing.com\n  - nuaa.edu.cn",
                                  "  - chaoxing.com\n  - nuaa.edu.cn")
        original, body = response(execute())
        reordered, other = response(execute(changed))
        self.assertEqual(body, other)
        self.assertEqual(original["ETag"], reordered["ETag"])
        unused = CONFIG.replace("proxy:\n", "未使用: [dormant.example]\nproxy:\n"
                                "  - {method: socks5, url: localhost, port: 1080, domains: []}\n")
        self.assertEqual(response(execute(unused))[1], body)
        changed_tag, _ = response(execute(CONFIG.replace("port: 7890", "port: 7891")))
        self.assertNotEqual(original["ETag"], changed_tag["ETag"])

    def test_crossing_private_psl_boundaries(self):
        config = """
parent: [amazonaws.com]
child: [a.bucket.s3.amazonaws.com]
same: [b.bucket.s3.amazonaws.com]
proxy:
  - {method: http, url: proxy.example.com, port: 8080, domains: [parent, same]}
  - {method: direct, domains: [child]}
default: {method: direct}
"""
        _, body = response(execute(config))
        hosts = ["amazonaws.com", "bucket.s3.amazonaws.com", "a.bucket.s3.amazonaws.com",
                 "x.a.bucket.s3.amazonaws.com", "b.bucket.s3.amazonaws.com",
                 "c.bucket.s3.amazonaws.com", "different.s3.amazonaws.com"]
        proxy = "PROXY proxy.example.com:8080"
        self.assertEqual(evaluate(body, hosts), [proxy, proxy, "DIRECT", "DIRECT", proxy, proxy, proxy])
        self.assertNotIn(b'"b.bucket.s3.amazonaws.com"', body)

    def test_psl_wildcard_exception_and_idn(self):
        config = """
任意: [www.ck, a.b.ck, 食狮.com.cn]
proxy:
  - {method: http, url: proxy.example.com, port: 8080, domains: [任意]}
default: {method: direct}
"""
        _, body = response(execute(config))
        self.assertEqual(evaluate(body, ["www.ck", "a.www.ck", "a.b.ck", "b.ck",
                         "xn--85x722f.com.cn", "a.xn--85x722f.com.cn"]),
                         ["PROXY proxy.example.com:8080"] * 3 + ["DIRECT"] +
                         ["PROXY proxy.example.com:8080"] * 2)

    def test_methods_default_and_ipv6(self):
        for method, expected in [("direct", "DIRECT"), ("http", "PROXY"), ("https", "HTTPS"),
                                 ("socks", "SOCKS"), ("socks4", "SOCKS4"), ("socks5", "SOCKS5")]:
            for address in ["::1", "[::1]"]:
                route = "{method: direct}" if method == "direct" else (
                    '{method: ' + method + ', url: "' + address + '", port: 1080}')
                _, body = response(execute("proxy: []\ndefault: " + route + "\n"))
                action = expected if method == "direct" else expected + " [::1]:1080"
                self.assertEqual(evaluate(body, ["unmatched.example"]), [action])

    def test_errors(self):
        cases = [CONFIG.replace("domains: [代理, 恢复代理]", "domains: [不存在]"),
                 CONFIG.replace("  - a.example.com", "  - cn.example.com"),
                 CONFIG.replace("port: 7890", "port: 65536"),
                 CONFIG.replace("port: 7890", "port: -1"),
                 CONFIG.replace("port: 7890", "ports: 7890"),
                 CONFIG.replace("method: http", "method: unknown"),
                 CONFIG.replace("  - example.com", "  - co.uk"),
                 CONFIG.replace("  - example.com", "  - '*.example.com'"),
                 CONFIG.replace("  - example.com", "  - 'example_com'"),
                 CONFIG.replace("  - example.com", "  - 'example..com'"),
                 CONFIG.replace("  - example.com", "  - 'example/com'"),
                 CONFIG.replace("  - example.com", "  - '-example.com'"),
                 CONFIG + "\ndefault: {method: direct}\n",
                 CONFIG + "\n---\nproxy: []\n",
                 "invalid: [\n", "", "default: {method: direct}\n",
                 "proxy: []\n", "proxy: []\ndefault: {method: direct, url: localhost}\n"]
        for config in cases:
            with self.subTest(config=config):
                result = execute(config, method="GET")
                self.assertNotEqual(result.returncode, 0)
                headers, _ = response(result)
                self.assertEqual(headers["Status"], "500 Internal Server Error")
                self.assertIn(b"easypac:", result.stderr)

    def test_other_http_methods(self):
        headers, body = response(execute(method="POST"))
        self.assertEqual(headers["Status"], "405 Method Not Allowed")
        self.assertEqual(headers["Allow"], "GET, HEAD")
        self.assertEqual(body, b"")

    def test_cli(self):
        result = execute(args=("--check",))
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b"retained rules", result.stdout)
        raw = execute(args=("--pac",))
        _, body = response(execute())
        self.assertEqual(raw.stdout, body)

    @unittest.skipUnless(shutil.which("nginx") and shutil.which("fcgiwrap"), "requires nginx and fcgiwrap")
    def test_nginx_cgi_round_trip(self):
        def free_port():
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                return sock.getsockname()[1]

        http_port = free_port()
        processes = []
        with tempfile.TemporaryDirectory(prefix="easypac-nginx-") as directory:
            path = Path(directory)
            yaml = path / "rules.yaml"
            fcgi_socket = path / "fcgi.socket"
            yaml.write_text(CONFIG, encoding="utf-8")
            config = path / "nginx.conf"
            config.write_text(f"""
pid {path}/nginx.pid;
error_log stderr;
events {{}}
http {{
  access_log off;
  client_body_temp_path {path}/body;
  fastcgi_temp_path {path}/fastcgi;
  proxy_temp_path {path}/proxy;
  uwsgi_temp_path {path}/uwsgi;
  scgi_temp_path {path}/scgi;
  server {{
    listen 127.0.0.1:{http_port};
    location = /proxy.pac {{
      include /etc/nginx/fastcgi_params;
      fastcgi_param SCRIPT_FILENAME {BINARY};
      fastcgi_param PAC_RULES {yaml};
      fastcgi_param HTTP_IF_NONE_MATCH $http_if_none_match;
      fastcgi_pass unix:{fcgi_socket};
    }}
  }}
}}
""", encoding="utf-8")

            def request(method="GET", tag=None):
                connection = http.client.HTTPConnection("127.0.0.1", http_port, timeout=5)
                try:
                    connection.request(method, "/proxy.pac", headers={"If-None-Match": tag} if tag else {})
                    reply = connection.getresponse()
                    return reply.status, dict(reply.getheaders()), reply.read()
                finally:
                    connection.close()

            try:
                processes.append(subprocess.Popen(["fcgiwrap", "-f", "-s", f"unix:{fcgi_socket}"],
                                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE))
                processes.append(subprocess.Popen(["nginx", "-e", "stderr", "-p", directory + "/",
                                                  "-c", str(config), "-g", "daemon off;"],
                                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE))
                deadline = time.monotonic() + 5
                while True:
                    try:
                        status, headers, body = request()
                        if status == 200:
                            break
                    except (OSError, http.client.HTTPException):
                        pass
                    if time.monotonic() >= deadline or any(p.poll() is not None for p in processes):
                        self.fail("nginx/fcgiwrap did not become ready")
                    time.sleep(0.05)
                _, expected = response(execute())
                self.assertEqual(body, expected)
                tag = headers["ETag"]
                status, headers, body = request(tag="W/" + tag)
                self.assertEqual((status, body), (304, b""))
                self.assertEqual(headers["ETag"], tag)
                self.assertEqual(request("HEAD")[2], b"")
                self.assertEqual(request("POST")[0], 405)
                yaml.write_text(CONFIG.replace("port: 7890", "port: 7891"), encoding="utf-8")
                status, headers, body = request(tag=tag)
                self.assertEqual(status, 200)
                self.assertNotEqual(headers["ETag"], tag)
                self.assertIn(b"PROXY 127.0.0.1:7891", body)
                yaml.write_text("broken: [", encoding="utf-8")
                self.assertEqual(request()[0], 500)
                status, _, body = request("HEAD")
                self.assertEqual((status, body), (500, b""))
            finally:
                failed = sys.exc_info()[0] is not None
                for process in reversed(processes):
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                    log = process.stderr.read()
                    process.stderr.close()
                    if failed and log:
                        print(log.decode(errors="replace"), file=sys.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
