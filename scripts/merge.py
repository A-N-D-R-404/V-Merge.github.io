#!/usr/bin/env python3
"""
V-Merge: объединённый скрипт сбора, проверки и публикации VPN-конфигов.
Заменяет merge.py + cl.py. Не создаёт новых файлов в репозитории.

Поток:
1. Читает источники из scripts/sources.txt (динамически).
2. Скачивает и дедуплицирует конфиги.
3. Проверяет работоспособность каждого конфига через Xray/Hysteria.
4. Определяет страну для рабочих конфигов (ip-api.com).
5. Переименовывает с флагами и сохраняет в output/merged.txt.
6. Обновляет output/happ_link.txt через API Happ.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from json import JSONEncoder
from pathlib import Path
from typing import Any, Dict, List, Optional
import base64
import hashlib
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from requests import RequestException
from retrying import retry
import psutil
import requests
import yaml

# ============================================================
# Пути
# ============================================================
ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "scripts" / "sources.txt"
GEO_CACHE = ROOT / "scripts" / "geo_cache.json"
STATE_FILE = ROOT / "scripts" / "sources_state.json"
CONF_PATH = ROOT / "scripts" / "config.json"  # config.json теперь в scripts/
OUT_PLAIN = ROOT / "output" / "merged.txt"
OUT_B64 = ROOT / "output" / "merged.base64.txt"
OUT_HAPP = ROOT / "output" / "happ_link.txt"

# Бинарники и временные файлы — в корне
XRAY_BIN = ROOT / "xray" / "xray"
HY2_BIN = ROOT / "hy2" / "hysteria"
XRAY_TMP_DIR = ROOT / "xray"
HY2_TMP_DIR = ROOT / "hy2"

UA = "Mozilla/5.0 (compatible; V-Merge-Bot/1.0)"

# ============================================================
# Настройки
# ============================================================
GEO_ENABLED = True
MAX_NEW = 200
DELAY_BETWEEN = 1.5
RENAME_ENABLED = True
FORCE_REBUILD = False

CHECK_ENABLED = True
TH_MAX_WORKER = 10  # 🚀 Увеличено с 5 до 10 одновременных проверок
MAX_WORKING_LIMIT = 500  # 🎯 Лимит рабочих конфигов (при достижении проверка останавливается)
CHECK_TIMEOUT = 10  # секунд на HTTP-запрос через прокси
CHECK_LOC = True  # определять страну для рабочих конфигов

# 🌍 Расширенная карта флагов стран (ISO 3166-1 alpha-2)
FLAGS = {
    "RU": "🇷🇺",
    "US": "🇺🇸",
    "DE": "🇩🇪",
    "NL": "🇳🇱",
    "FR": "🇫🇷",
    "GB": "🇬🇧",
    "FI": "🇫🇮",
    "SE": "🇸🇪",
    "TR": "🇹🇷",
    "JP": "🇯🇵",
    "KR": "🇰🇷",
    "SG": "🇸🇬",
    "CA": "🇨🇦",
    "PL": "🇵🇱",
    "UA": "🇺🇦",
    "KZ": "🇰🇿",
    "CN": "🇨🇳",
    "HK": "🇭🇰",
    "IN": "🇮🇳",
    "BR": "🇧🇷",
    "IR": "🇮🇷",
    "AE": "🇦🇪",
    "IT": "🇮🇹",
    "ES": "🇪🇸",
    "CH": "🇨🇭",
    "AT": "🇦🇹",
    "CZ": "🇨🇿",
    "RO": "🇷🇴",
    "MD": "🇲🇩",
    "LV": "🇱🇻",
    "LT": "🇱🇹",
    "EE": "🇪🇪",
    "AM": "🇦🇲",
    "GE": "🇬🇪",
    "AZ": "🇦🇿",
    "IL": "🇮🇱",
    "AU": "🇦🇺",
    "NZ": "🇳🇿",
    "MX": "🇲🇽",
    "AR": "🇦🇷",
    "BG": "🇧🇬",
    "RS": "🇷🇸",
    "HR": "🇭🇷",
    "SK": "🇸🇰",
    "SI": "🇸🇮",
    "TH": "🇹🇭",
    "VN": "🇻🇳",
    "MY": "🇲🇾",
    "ID": "🇮🇩",
    "PH": "🇵🇭",
    "NO": "🇳🇴",
    "DK": "🇩🇰",
    "BE": "🇧🇪",
    "IE": "🇮🇪",
    "PT": "🇵🇹",
    "GR": "🇬🇷",
    "HU": "🇭🇺",
    "AL": "🇦🇱",
    "IM": "🇮🇲",
    "UZ": "🇺🇿",
    "KG": "🇰🇬",
    "TW": "🇹🇼",
    "CY": "🇨🇾",
    "LU": "🇱🇺",
    "MT": "🇲🇹",
    "IS": "🇮🇸",
}


def flag(cc):
    if not cc:
        return "🏴"
    code = cc.upper()
    if code in FLAGS:
        return FLAGS[code]
    # Автогенерация из Unicode regional indicator symbols для остальных стран
    if len(code) == 2 and code.isalpha():
        return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)
    return "🏴"


# ============================================================
# Часть 1: сбор источников
# ============================================================


def fetch(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")


def decode_subscription(text):
    text = text.strip()
    if not text:
        return ""
    if "://" in text:
        return text
    try:
        cleaned = re.sub(r"\s+", "", text)
        cleaned += "=" * (-len(cleaned) % 4)
        decoded = base64.b64decode(cleaned).decode("utf-8", errors="ignore")
        if "://" in decoded:
            return decoded
    except Exception:
        pass
    return text


RE_FI = re.compile(
    r"обновлено:\s*(\d{1,2})/(\d{1,2})/(\d{4})\s+(\d{1,2}):(\d{2})\s*(AM|PM)?",
    re.IGNORECASE,
)
RE_IGARECK = re.compile(
    r"Date/Time:\s*(\d{4})-(\d{2})-(\d{2})\s*/\s*(\d{1,2}):(\d{2})",
    re.IGNORECASE,
)


def parse_source_updated_at(text):
    head = "\n".join(text.splitlines()[:15])
    m = RE_FI.search(head)
    if m:
        mm, dd, yy, hh, mi, ampm = m.groups()
        hh, mi = int(hh), int(mi)
        if ampm:
            ampm = ampm.upper()
            if ampm == "PM" and hh != 12:
                hh += 12
            if ampm == "AM" and hh == 12:
                hh = 0
        try:
            return f"{int(yy):04d}-{int(mm):02d}-{int(dd):02d} {hh:02d}:{mi:02d}"
        except Exception:
            return None
    m = RE_IGARECK.search(head)
    if m:
        yy, mm, dd, hh, mi = m.groups()
        try:
            return f"{int(yy):04d}-{int(mm):02d}-{int(dd):02d} {int(hh):02d}:{int(mi):02d}"
        except Exception:
            return None
    return None


def load_state():
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(
        json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def check_sources_changed(urls, force=False):
    if force:
        print("[i] --force: пропускаю проверку источников")
        return True, load_state(), {}
    old = load_state()
    new_state = dict(old)
    changed = False
    contents = {}
    for url in urls:
        try:
            raw = fetch(url)
            contents[url] = raw
            dt = parse_source_updated_at(raw)
            prev = old.get(url)
            if dt is None:
                h = hashlib.md5(
                    raw.encode("utf-8", errors="ignore")
                ).hexdigest()[:12]
                dt = f"hash:{h}"
            if dt != prev:
                changed = True
                print(f"[~] {url}\n    было: {prev or '—'} → стало: {dt}")
            else:
                print(f"[=] {url}\n    без изменений ({dt})")
            new_state[url] = dt
        except Exception as e:
            print(f"[!] {url}: {e}", file=sys.stderr)
            contents[url] = ""
            new_state[url] = old.get(url)
    return changed, new_state, contents


def parse_link(link):
    try:
        if link.startswith("vmess://"):
            b64 = link[len("vmess://") :]
            b64 += "=" * (-len(b64) % 4)
            data = json.loads(
                base64.b64decode(b64).decode("utf-8", errors="ignore")
            )
            host = (data.get("add") or data.get("host") or "").strip().lower()
            port = str(data.get("port", "")).strip()
            return "vmess", host, port
        type_ = link.split("://", 1)[0].lower()
        parsed = urllib.parse.urlparse(link)
        host = (parsed.hostname or "").strip().lower()
        port = str(parsed.port or "").strip()
        if not host and "@" in link:
            after = link.split("@", 1)[1]
            host_port = after.split("/", 1)[0].split("?", 1)[0]
            if ":" in host_port:
                h, p = host_port.rsplit(":", 1)
                host = h.strip().lower()
                port = p.strip()
            else:
                host = host_port.strip().lower()
        return type_, host, port
    except Exception:
        return None, None, None


def rename_link(link, tag):
    if not RENAME_ENABLED:
        return link
    if link.startswith("vmess://"):
        try:
            b64 = link[len("vmess://") :]
            b64 += "=" * (-len(b64) % 4)
            raw = base64.b64decode(b64).decode("utf-8", errors="ignore")
            data = json.loads(raw)
            data["ps"] = tag
            new_b64 = base64.b64encode(
                json.dumps(data, ensure_ascii=False).encode("utf-8")
            ).decode()
            return "vmess://" + new_b64
        except Exception:
            return link
    base = link.split("#", 1)[0]
    return f"{base}#{urllib.parse.quote(tag)}"


def load_geo():
    if not GEO_CACHE.exists():
        return {}
    try:
        data = json.loads(GEO_CACHE.read_text(encoding="utf-8"))
        return {
            str(k).strip().lower(): str(v).strip().upper()
            for k, v in data.items()
        }
    except Exception as e:
        print(f"[!] Ошибка чтения geo_cache.json: {e}", file=sys.stderr)
        return {}


def save_geo(data):
    GEO_CACHE.parent.mkdir(parents=True, exist_ok=True)
    GEO_CACHE.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def resolve_ip(host):
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        try:
            return socket.gethostbyname(host)
        except Exception:
            return None


def lookup_country_ip(ip):
    url = f"http://ip-api.com/json/{ip}?fields=status,countryCode"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
            if data.get("status") == "success":
                return (data.get("countryCode") or "XX").upper()
    except urllib.error.HTTPError as e:
        if e.code == 429:
            print("[!] 429 Too Many Requests — пауза 60 сек")
            time.sleep(60)
    except Exception as e:
        print(f"  [!] ip-api: {e}")
    return "XX"


def update_geo_cache(hosts, geo):
    if not GEO_ENABLED:
        return geo
    missing, seen = [], set()
    for h in hosts:
        hl = h.strip().lower()
        if not hl or hl == "-" or hl in seen:
            continue
        if hl in geo and geo[hl] != "XX":
            continue
        seen.add(hl)
        missing.append(hl)
    print(f"[=] Хостов к обработке (новые + XX): {len(missing)}")
    if not missing:
        return geo
    to_process = missing[:MAX_NEW]
    print(f"[=] Обрабатываю {len(to_process)} (лимит {MAX_NEW})")
    added = 0
    improved = 0
    for i, host in enumerate(to_process, 1):
        was = geo.get(host, "")
        ip = resolve_ip(host)
        if not ip:
            geo[host] = "XX"
            print(f"  [{i}/{len(to_process)}] {host} — не резолвится (XX)")
            continue
        cc = lookup_country_ip(ip)
        geo[host] = cc
        if cc != "XX":
            added += 1
            if was == "XX":
                improved += 1
        print(f"  [{i}/{len(to_process)}] {host} → {ip} → {cc}")
        time.sleep(DELAY_BETWEEN)
    remaining = len(missing) - len(to_process)
    if remaining > 0:
        print(f"[i] Осталось на следующий прогон: {remaining}")
    print(f"[=] Определено стран: {added} (исправлено XX→страна: {improved})")
    return geo


# ============================================================
# Часть 2: проверка конфигов через Xray/Hysteria
# ============================================================

# Загружаем тестовый URL из config.json
try:
    with open(CONF_PATH, "r") as f:
        _cfg = json.load(f)
        TEST_URL = _cfg["core"]["test_url"]
except Exception as e:
    print(
        f"[!] Не удалось загрузить {CONF_PATH}: {e}. Проверка будет отключена."
    )
    TEST_URL = None
    CHECK_ENABLED = False


class ProcessManager:
    """Управляет фоновыми процессами Xray/Hysteria."""

    def __init__(self):
        self.active_processes = {}
        self.lock = threading.Lock()

    def add_process(self, name: str, pid: int):
        with self.lock:
            self.active_processes[name] = pid

    def stop_process(self, name: str):
        pid_to_stop = None
        with self.lock:
            if name in self.active_processes:
                pid_to_stop = self.active_processes.pop(name)
            else:
                return
        try:
            if psutil.pid_exists(pid_to_stop):
                os.kill(pid_to_stop, signal.SIGTERM)
                time.sleep(0.5)
                if psutil.pid_exists(pid_to_stop):
                    os.kill(pid_to_stop, signal.SIGKILL)
        except (ProcessLookupError, psutil.NoSuchProcess):
            pass
        except Exception as e:
            print(f"  [!] Ошибка остановки PID {pid_to_stop}: {e}")

    def stop_all(self):
        with self.lock:
            names = list(self.active_processes.keys())
        for name in names:
            self.stop_process(name)


process_manager = ProcessManager()

# ---- Парсинг конфигов для Xray ----


@dataclass
class ConfigParams:
    protocol: str
    address: str
    port: int
    security: Optional[str] = ""
    encryption: Optional[str] = "none"
    header_type: Optional[str] = "none"
    network: Optional[str] = "tcp"
    flow: Optional[str] = ""
    sni: Optional[str] = ""
    fp: Optional[str] = ""
    alpn: Optional[str] = None
    pbk: Optional[str] = ""
    sid: Optional[str] = ""
    spx: Optional[str] = ""
    tag: Optional[str] = ""
    id: Optional[str] = ""
    type: Optional[str] = "tcp"
    alter_id: Optional[str] = ""
    mode: Optional[str] = None
    host: Optional[str] = None
    path: Optional[str] = None
    scy: Optional[str] = ""
    socks_user: Optional[str] = ""
    ss_method: Optional[str] = "chacha20-poly1305"
    ss_password: Optional[str] = ""
    hy2_insecure: Optional[str] = "0"
    hy2_obfs_password: Optional[str] = ""
    hy2_hop_interval: Optional[str] = "30"
    hy2_pinsha256: Optional[str] = ""
    hy2_obfs: Optional[str] = ""
    wg_reserved: Optional[str] = ""
    wg_public_key: Optional[str] = ""
    wg_endpoint: Optional[str] = ""
    wg_secret_key: Optional[str] = ""
    wg_keep_alive: Optional[int] = 10
    wg_mtu: Optional[int] = 0
    wg_address: Optional[str] = ""
    wnoise: Optional[str] = "quic"
    wnoisecount: Optional[str] = "15"
    wnoisedelay: Optional[str] = "1-3"
    wpayloadsize: Optional[str] = "1-8"
    extra_params: Dict[str, Any] = field(default_factory=dict)


def _parse_query_params(query: str) -> Dict[str, str]:
    params = {}
    for pair in query.split("&"):
        if "=" in pair:
            key, value = pair.split("=", 1)
            params[key] = urllib.parse.unquote(value)
    return params


def parse_config_params(config: str) -> ConfigParams:
    """Упрощённый парсер ссылки в ConfigParams (для проверки)."""
    config = urllib.parse.unquote(config.strip())
    main_config, _, tag = config.partition("#")
    tag = urllib.parse.unquote(tag)

    protocol = next(
        (
            p
            for p in [
                "vless",
                "vmess",
                "trojan",
                "hy2",
                "hysteria2",
                "ss",
                "socks",
                "wireguard",
            ]
            if main_config.startswith(p + "://")
        ),
        None,
    )
    if not protocol:
        raise ValueError("Неизвестный протокол")

    common = {"protocol": protocol, "tag": tag}

    if protocol in ("vless", "trojan"):
        m = re.search(r"([^:]+)@([^:]+):(\d+)", main_config)
        if m:
            common.update(
                {
                    "id": m.group(1).replace("//", "")
                    if protocol != "trojan"
                    else "",
                    "address": m.group(2),
                    "port": int(m.group(3)),
                }
            )
    elif protocol == "wireguard":
        m = re.search(r"([^@]+)@([^:]+):(\d+)", main_config)
        if m:
            common.update(
                {
                    "wg_secret_key": m.group(1).split("wireguard://")[1],
                    "address": m.group(2),
                    "port": int(m.group(3)),
                }
            )
    elif protocol in ("hy2", "hysteria2"):
        m = re.search(rf"{protocol}://([^@]+)@([^:/?#]+):(\d+)", main_config)
        if m:
            common.update(
                {
                    "ss_password": m.group(1),
                    "address": m.group(2),
                    "port": int(m.group(3)),
                }
            )
    else:
        m = re.search(r"@([^:]+):(\d+)", main_config)
        if m:
            common.update(
                {
                    "address": m.group(1),
                    "port": int(m.group(2)),
                }
            )

    if protocol == "vless":
        query = main_config.split("?", 1)[1] if "?" in main_config else ""
        p = _parse_query_params(query)
        host_params = {
            "tcp": p.get("host"),
            "ws": p.get("host"),
            "h2": p.get("host"),
            "httpupgrade": p.get("host"),
            "xhttp": p.get("host"),
            "splithttp": p.get("host"),
            "quic": p.get("quicSecurity"),
            "grpc": p.get("authority"),
        }
        path_params = {
            "ws": p.get("path"),
            "h2": p.get("path"),
            "httpupgrade": p.get("path"),
            "splithttp": p.get("path"),
            "xhttp": p.get("path"),
            "kcp": p.get("seed"),
            "grpc": p.get("serviceName"),
            "quic": p.get("key"),
        }
        typ = p.get("type", "tcp")
        return ConfigParams(
            **common,
            security=p.get("security", ""),
            encryption=p.get("encryption", "none"),
            type=typ,
            host=host_params.get(typ),
            path=path_params.get(typ),
            flow=p.get("flow", ""),
            sni=p.get("sni", ""),
            fp=p.get("fp", ""),
            alpn=p.get("alpn"),
            pbk=p.get("pbk", ""),
            sid=p.get("sid", ""),
            spx=p.get("spx", ""),
            mode=p.get("mode"),
        )

    if protocol == "vmess":
        try:
            encoded = main_config.split("://")[1]
            encoded += "=" * (-len(encoded) % 4)
            vm = json.loads(base64.b64decode(encoded).decode("utf-8"))
        except Exception:
            raise ValueError("Битый vmess-конфиг")
        return ConfigParams(
            protocol="vmess",
            address=vm.get("add", ""),
            port=int(vm.get("port", 0)),
            tag=vm.get("ps", ""),
            security=vm.get("tls", ""),
            id=vm.get("id", ""),
            alter_id=int(vm.get("aid", 0)),
            scy=vm.get("scy", ""),
            sni=vm.get("sni", ""),
            fp=vm.get("fp", ""),
            type=vm.get("net", "tcp"),
            host=vm.get("host"),
            path=vm.get("path"),
            alpn=vm.get("alpn"),
            mode=vm.get("mode"),
        )

    if protocol == "trojan":
        query = main_config.split("?", 1)[1] if "?" in main_config else ""
        p = _parse_query_params(query)
        m = re.search(r"trojan://([^@]+)@", main_config)
        pwd = m.group(1) if m else ""
        host_params = {
            "tcp": p.get("host"),
            "ws": p.get("host"),
            "h2": p.get("host"),
            "httpupgrade": p.get("host"),
            "xhttp": p.get("host"),
            "splithttp": p.get("host"),
            "quic": p.get("quicSecurity"),
            "grpc": p.get("authority"),
        }
        path_params = {
            "ws": p.get("path"),
            "h2": p.get("path"),
            "httpupgrade": p.get("path"),
            "splithttp": p.get("path"),
            "xhttp": p.get("path"),
            "kcp": p.get("seed"),
            "grpc": p.get("serviceName"),
            "quic": p.get("key"),
        }
        typ = p.get("type", "tcp")
        return ConfigParams(
            **common,
            security="tls",
            ss_password=pwd,
            sni=p.get("sni", ""),
            fp=p.get("fp", ""),
            alpn=p.get("alpn"),
            pbk=p.get("pbk", ""),
            sid=p.get("sid", ""),
            type=typ,
            host=host_params.get(typ),
            path=path_params.get(typ),
            spx=p.get("spx", ""),
            mode=p.get("mode"),
        )

    if protocol in ("hy2", "hysteria2"):
        query = main_config.split("?", 1)[1] if "?" in main_config else ""
        p = _parse_query_params(query)
        return ConfigParams(
            **common,
            security="tls",
            hy2_insecure=p.get("insecure", "0") == "1",
            hy2_obfs_password=p.get("obfs-password", ""),
            hy2_hop_interval=int(p.get("hopInterval", 30)),
            hy2_pinsha256=p.get("pinSHA256", ""),
            hy2_obfs=p.get("obfs", ""),
            sni=p.get("sni", common.get("address", "")),
            alpn=p.get("alpn"),
        )

    if protocol == "ss":
        main_part = main_config.split("ss://", 1)[1].split("#", 1)[0]
        method, password = "chacha20-poly1305", ""
        address, port = common.get("address", ""), common.get("port", 0)
        try:
            if "@" in main_part:
                auth, server = main_part.split("@", 1)
                auth = base64.b64decode(auth + "=" * (-len(auth) % 4)).decode()
                if ":" in auth:
                    method, password = auth.split(":", 1)
                if ":" in server:
                    address, port = server.rsplit(":", 1)
                    port = int(port)
            else:
                dec = base64.b64decode(
                    main_part + "=" * (-len(main_part) % 4)
                ).decode()
                if "@" in dec:
                    auth, server = dec.split("@", 1)
                    if ":" in auth:
                        method, password = auth.split(":", 1)
                    if ":" in server:
                        address, port = server.rsplit(":", 1)
                        port = int(port)
        except Exception:
            raise ValueError("Битый ss-конфиг")
        common.update({"address": address, "port": port})
        return ConfigParams(
            **common,
            ss_method=method,
            ss_password=password,
            security="none",
        )

    if protocol == "socks":
        auth = main_config.split("://")[1].split("@")[0]
        try:
            dec = base64.b64decode(auth + "=" * (-len(auth) % 4)).decode()
            user, pwd = dec.split(":", 1)
        except Exception:
            user, pwd = "", ""
        return ConfigParams(
            **common,
            socks_user=user,
            ss_password=pwd,
            security="none",
        )

    if protocol == "wireguard":
        query = main_config.split("?", 1)[1] if "?" in main_config else ""
        p = _parse_query_params(query)
        return ConfigParams(
            **common,
            wg_reserved=p.get("reserved", ""),
            wg_public_key=p.get("publickey", ""),
            wg_endpoint=p.get("endpoint", ""),
            wg_keep_alive=int(p.get("keepalive", 5)),
            wg_mtu=int(p.get("mtu", 0)),
            wg_address=p.get("address", ""),
            wnoise=p.get("wnoise", "quic"),
            wnoisecount=p.get("wnoisecount", "15"),
            wnoisedelay=p.get("wnoisedelay", "1-3"),
            wpayloadsize=p.get("wpayloadsize", "1-8"),
        )

    raise ValueError(f"Неподдерживаемый протокол: {protocol}")


def build_xray_config(params: ConfigParams, local_port: int) -> str:
    """Строит JSON-конфиг Xray для проверки одного прокси."""
    with open(CONF_PATH, "r") as f:
        cfg = json.load(f)
    core = cfg["core"]
    dns_sets = core["dns"]
    mux_sets = core["mux"]
    frag_sets = core["fragment"]
    routing_sets = core["routing_rules"]
    inbound_ports = core["inbound_ports"]
    SOCKS_PORT = inbound_ports["socks"]
    HTTP_PORT = inbound_ports["http"]
    LOGLEVEL = core["log_level"]
    SNIFFING = core["sniffing_enabled"]
    DOMAINSTRATEGY = core["domain_strategy"]
    REMOTEDNS = dns_sets["remote_server"]
    DOMESTICDNS = dns_sets["domestic_server"]
    ENABLELOCALDNS = dns_sets["enabled"]
    ENABLEFAKEDNS = dns_sets["fake_dns_enabled"]
    LOCALDNSPORT = dns_sets["local_port"]
    MUX_ENABLE = mux_sets["enabled"]
    CONCURRENCY = mux_sets["concurrency"]
    FRAGMENT = frag_sets["enabled"]
    PACKETS = frag_sets["packets"]
    LENGTH = frag_sets["length"]
    INTERVAL = frag_sets["interval"]
    ALLOWINCREASE = core["allow_insecure_tls"]

    LOCAL_HOST = f"127.0.0.{local_port}"
    DEFAULT_PORT = 443
    DEFAULT_LEVEL = 8
    TLS = "tls"
    REALITY = "reality"
    HTTP = "http"

    # inbounds
    inbounds = [
        {
            "tag": "socks",
            "port": SOCKS_PORT,
            "protocol": "socks",
            "listen": LOCAL_HOST,
            "sniffing": {
                "enabled": SNIFFING,
                "destOverride": ["http", "tls"],
                "routeOnly": False,
            },
            "settings": {"auth": "noauth", "udp": True, "allowTransparent": False},
        },
        {
            "tag": "http",
            "port": HTTP_PORT,
            "protocol": "http",
            "listen": LOCAL_HOST,
            "settings": {"userLevel": 8},
        },
    ]
    if ENABLELOCALDNS:
        inbounds.append(
            {
                "tag": "dns-in",
                "listen": LOCAL_HOST,
                "port": LOCALDNSPORT,
                "protocol": "dokodemo-door",
                "settings": {"address": "8.8.8.8", "network": "tcp,udp", "port": 53},
            }
        )

    # outbound
    stream = {"network": params.type or "tcp", "security": params.security or ""}

    if params.type == "tcp":
        header = {"type": params.header_type or "none"}
        if params.header_type == "http" and params.host:
            header["request"] = {
                "path": [params.path or "/"],
                "headers": {"Host": [params.host]},
            }
        stream["tcpSettings"] = {"header": header}
    elif params.type == "ws":
        stream["wsSettings"] = {
            "path": params.path or "/",
            "headers": {"Host": params.host or ""},
        }
    elif params.type == "httpupgrade":
        stream["httpupgradeSettings"] = {
            "path": params.path or "/",
            "host": params.host or "",
        }
    elif params.type == "xhttp":
        stream["xhttpSettings"] = {
            "path": params.path or "/",
            "host": params.host or "",
            "mode": params.mode,
        }
    elif params.type == "splithttp":
        stream["splithttpSettings"] = {
            "path": params.path or "/",
            "host": params.host or "",
        }
    elif params.type == "h2":
        stream["httpSettings"] = {
            "path": params.path or "/",
            "host": [params.host] if params.host else [],
        }
    elif params.type == "quic":
        stream["quicSettings"] = {
            "security": params.host or "none",
            "key": params.path or "",
            "header": {"type": params.header_type or "none"},
        }
    elif params.type == "grpc":
        stream["grpcSettings"] = {
            "serviceName": params.path or "",
            "authority": params.host or "",
            "multiMode": params.mode == "multi",
        }

    # tls / reality
    tls_settings = {
        "allowInsecure": ALLOWINCREASE,
        "serverName": params.sni or "",
        "fingerprint": params.fp or "",
    }
    if params.alpn:
        tls_settings["alpn"] = [
            a.strip() for a in params.alpn.split(",") if a.strip()
        ]
    if params.security == REALITY:
        tls_settings.update(
            {
                "publicKey": params.pbk or "",
                "shortId": params.sid or "",
                "spiderX": params.spx or "",
            }
        )
        stream["realitySettings"] = tls_settings
    elif params.security == TLS:
        stream["tlsSettings"] = tls_settings

    if FRAGMENT:
        stream["sockopt"] = {
            "dialerProxy": "fragment",
            "tcpKeepAliveIdle": 100,
            "mark": 255,
        }

    mux = {
        "enabled": MUX_ENABLE,
        "concurrency": CONCURRENCY,
        "xudpConcurrency": CONCURRENCY,
        "xudpProxyUDP443": "",
    }

    if params.protocol == "vless":
        outbound = {
            "tag": "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": params.address,
                        "port": params.port,
                        "users": [
                            {
                                "id": params.id,
                                "security": "auto",
                                "level": 8,
                                "encryption": params.encryption or "none",
                                "flow": params.flow or "",
                                "alterId": 0,
                            }
                        ],
                    }
                ],
            },
            "mux": mux,
            "streamSettings": stream,
        }
    elif params.protocol == "vmess":
        outbound = {
            "tag": "proxy",
            "protocol": "vmess",
            "settings": {
                "vnext": [
                    {
                        "address": params.address,
                        "port": params.port,
                        "users": [
                            {
                                "id": params.id,
                                "security": params.scy or "auto",
                                "level": 8,
                                "encryption": "",
                                "flow": "",
                                "alterId": params.alter_id or 0,
                            }
                        ],
                    }
                ],
            },
            "mux": mux,
            "streamSettings": stream,
        }
    elif params.protocol == "trojan":
        outbound = {
            "tag": "proxy",
            "protocol": "trojan",
            "settings": {
                "servers": [
                    {
                        "address": params.address,
                        "port": params.port,
                        "method": "chacha20-poly1305",
                        "ota": False,
                        "level": 8,
                        "password": params.ss_password,
                    }
                ],
            },
            "mux": mux,
            "streamSettings": stream,
        }
    elif params.protocol == "ss":
        sockopt = (
            {
                "dialerProxy": "fragment",
                "tcpKeepAliveIdle": 100,
                "mark": 255,
            }
            if FRAGMENT
            else None
        )
        outbound = {
            "tag": "proxy",
            "protocol": "shadowsocks",
            "settings": {
                "servers": [
                    {
                        "address": params.address,
                        "method": params.ss_method,
                        "port": params.port,
                        "ota": False,
                        "level": 8,
                        "password": params.ss_password,
                    }
                ],
            },
            "mux": mux,
            "streamSettings": {
                "network": "tcp",
                "security": "",
                **({"sockopt": sockopt} if sockopt else {}),
            },
        }
    elif params.protocol == "socks":
        outbound = {
            "tag": "proxy",
            "protocol": "socks",
            "settings": {
                "servers": [
                    {
                        "address": params.address,
                        "port": params.port,
                        "method": params.ss_method,
                        "ota": False,
                        "level": 8,
                        "password": params.ss_password,
                        **(
                            {
                                "users": [
                                    {
                                        "level": 8,
                                        "pass": params.ss_password,
                                        "user": params.socks_user,
                                    }
                                ]
                            }
                            if params.socks_user or params.ss_password
                            else {}
                        ),
                    }
                ],
            },
            "mux": mux,
            "streamSettings": {"network": "tcp", "security": ""},
        }
    elif params.protocol == "wireguard":
        reserved = (
            [int(x) for x in params.wg_reserved.split(",")]
            if params.wg_reserved
            else []
        )
        outbound = {
            "tag": "proxy",
            "protocol": "wireguard",
            "settings": {
                "address": params.wg_address.split(",")
                if params.wg_address
                else [],
                "mtu": params.wg_mtu,
                "reserved": reserved,
                "secretKey": params.wg_secret_key,
                "wnoise": params.wnoise,
                "wnoisecount": params.wnoisecount,
                "wnoisedelay": params.wnoisedelay,
                "wpayloadsize": params.wpayloadsize,
                "keepAlive": params.wg_keep_alive,
                "peers": [
                    {
                        "endpoint": f"{params.wg_endpoint}:{params.port}",
                        "publicKey": params.wg_public_key,
                    }
                ],
            },
        }
    else:
        raise ValueError(
            f"Неподдерживаемый протокол для Xray: {params.protocol}"
        )

    outbounds = [outbound]
    if FRAGMENT:
        outbounds.append(
            {
                "tag": "fragment",
                "protocol": "freedom",
                "settings": {
                    "fragment": {
                        "packets": PACKETS,
                        "length": LENGTH,
                        "interval": INTERVAL,
                    },
                },
                "streamSettings": {
                    "sockopt": {
                        "TcpNoDelay": True,
                        "tcpKeepAliveIdle": 100,
                        "mark": 255,
                    },
                },
            }
        )
    outbounds.append({"tag": "direct", "protocol": "freedom", "settings": {}})
    outbounds.append(
        {
            "tag": "block",
            "protocol": "blackhole",
            "settings": {"response": {"type": "http"}},
        }
    )

    # dns
    dns_servers = [REMOTEDNS]
    if ENABLELOCALDNS and not ENABLEFAKEDNS:
        dns_servers.insert(
            0,
            {
                "address": DOMESTICDNS,
                "domains": ["geosite:cn"],
                "expectIPs": ["geoip:cn"],
                "port": 53,
            },
        )
    elif ENABLELOCALDNS and ENABLEFAKEDNS:
        dns_servers.insert(
            0,
            {
                "address": DOMESTICDNS,
                "domains": ["geosite:cn"],
                "expectIPs": ["geoip:cn"],
                "port": 53,
            },
        )
        dns_servers.insert(1, {"address": "fakedns", "domains": ["geosite:cn"]})

    dns = {
        "hosts": {
            "domain:googleapis.cn": "googleapis.com",
            "dns.google": ["8.8.8.8", "8.8.4.4"],
        },
        "servers": dns_servers,
    }
    if ENABLELOCALDNS and ENABLEFAKEDNS:
        dns["fakedns"] = {"ipPool": "198.18.0.0/15", "poolSize": 10000}

    # routing
    rules = []
    for key, tag in (
        ("proxy", "proxy"),
        ("direct", "direct"),
        ("block", "block"),
    ):
        val = routing_sets.get(key, "")
        if not val:
            continue
        domains, ips = [], []
        for item in val.split(","):
            item = item.strip()
            if not item:
                continue
            if any(ch.isdigit() for ch in item) or "geoip" in item:
                ips.append(item)
            else:
                domains.append(item)
        if domains:
            rules.append(
                {
                    "type": "field",
                    "domain": domains,
                    "outboundTag": tag,
                    "enabled": True,
                }
            )
        if ips:
            rules.append(
                {
                    "type": "field",
                    "ip": ips,
                    "outboundTag": tag,
                    "enabled": True,
                }
            )

    routing = {"domainStrategy": DOMAINSTRATEGY, "rules": rules}

    config = {
        "log": {"access": "", "error": "", "loglevel": LOGLEVEL},
        "dns": dns,
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": routing,
    }
    return json.dumps(config, indent=4)


def start_xray(conf_path: Path, idx: int):
    if not XRAY_BIN.exists():
        raise FileNotFoundError(f"Xray не найден: {XRAY_BIN}")
    proc = subprocess.Popen(
        [str(XRAY_BIN), "run", "-c", str(conf_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    process_manager.add_process(f"xray_{idx}", proc.pid)


def start_hy2(yaml_path: Path, idx: int):
    if not HY2_BIN.exists():
        raise FileNotFoundError(f"Hysteria не найден: {HY2_BIN}")
    proc = subprocess.Popen(
        [str(HY2_BIN), "client", "-c", str(yaml_path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    process_manager.add_process(f"hysteria_{idx}", proc.pid)


def build_hy2_yaml(params: ConfigParams, local_port: int) -> dict:
    """Строит YAML-конфиг для Hysteria2."""
    with open(CONF_PATH, "r") as f:
        cfg = json.load(f)
    SOCKS_PORT = cfg["core"]["inbound_ports"]["socks"]
    HTTP_PORT = cfg["core"]["inbound_ports"]["http"]
    LOCAL_HOST = f"127.0.0.{local_port}"

    y = {
        "server": f"{params.address}:{params.port}",
        "auth": params.ss_password,
        "transport": {
            "type": "udp",
            "udp": {"hopInterval": f"{params.hy2_hop_interval}s"},
        },
    }
    if params.security == "tls":
        tls = {"insecure": params.hy2_insecure}
        if params.sni:
            tls["sni"] = params.sni
        if params.hy2_pinsha256:
            tls["pinSHA256"] = params.hy2_pinsha256
        y["tls"] = tls
    if params.hy2_obfs == "salamander":
        y["obfs"] = {
            "type": "salamander",
            "salamander": {"password": params.hy2_obfs_password},
        }
    y.update(
        {
            "bandwidth": {"up": "20 mbps", "down": "100 mbps"},
            "quic": {
                "initStreamReceiveWindow": 8388608,
                "maxStreamReceiveWindow": 8388608,
                "initConnReceiveWindow": 20971520,
                "maxConnReceiveWindow": 20971520,
                "maxIdleTimeout": "30s",
                "keepAlivePeriod": "10s",
                "disablePathMTUDiscovery": False,
            },
            "fastOpen": True,
            "lazy": True,
            "socks5": {"listen": f"{LOCAL_HOST}:{SOCKS_PORT + 2}"},
            "http": {"listen": f"{LOCAL_HOST}:{HTTP_PORT + 2}"},
        }
    )
    return y


def _get_http_port() -> int:
    with open(CONF_PATH, "r") as f:
        cfg = json.load(f)
    return cfg["core"]["inbound_ports"]["http"]


def check_one_config(link: str, idx: int, total: int) -> Optional[str]:
    """
    Проверяет один конфиг с выводом детального прогресса в консоль.
    Возвращает исходную ссылку, если она рабочая, иначе None.
    """
    print(f"[{idx + 1}/{total}] 🔍 Проверяется узел: {link[:50]}...")

    if not CHECK_ENABLED or not TEST_URL:
        print(f"[{idx + 1}/{total}] ⚠️ Проверка отключена или нет TEST_URL")
        return link

    try:
        params = parse_config_params(link)
        if not params.address or not params.port:
            print(
                f"[{idx + 1}/{total}] ❌ Пропуск: не удалось извлечь address/port"
            )
            return None

        local_port = (idx % 50) + 2
        xray_conf_path = XRAY_TMP_DIR / f"check_{idx}.json"
        hy2_yaml_path = HY2_TMP_DIR / f"check_{idx}.yaml"

        if params.protocol in ("hy2", "hysteria2"):
            hy2_yaml = build_hy2_yaml(params, local_port)
            with open(hy2_yaml_path, "w") as f:
                yaml.dump(hy2_yaml, f)
            start_hy2(hy2_yaml_path, idx)
            socks_params = ConfigParams(
                protocol="socks",
                address=f"127.0.0.{local_port}",
                port=0,
                socks_user="",
                ss_password="",
            )
            socks_port = hy2_yaml["socks5"]["listen"].split(":")[-1]
            socks_params.port = int(socks_port)
            xray_conf = build_xray_config(socks_params, local_port)
        else:
            xray_conf = build_xray_config(params, local_port)

        with open(xray_conf_path, "w") as f:
            f.write(xray_conf)
        start_xray(xray_conf_path, idx)

        time.sleep(2.5)

        proxies = {
            "http": f"http://127.0.0.{local_port}:{_get_http_port()}",
            "https": f"http://127.0.0.{local_port}:{_get_http_port()}",
        }
        try:
            r = requests.get(
                TEST_URL,
                proxies=proxies,
                timeout=CHECK_TIMEOUT,
                headers={"Connection": "close"},
            )
            ok = r.status_code in (200, 204)
        except Exception:
            ok = False

        for p in (xray_conf_path, hy2_yaml_path):
            try:
                p.unlink()
            except Exception:
                pass

        if params.protocol in ("hy2", "hysteria2"):
            process_manager.stop_process(f"hysteria_{idx}")
        process_manager.stop_process(f"xray_{idx}")

        if ok:
            print(f"[{idx + 1}/{total}] ✅ Успешно рабочий узел")
            return link
        else:
            print(f"[{idx + 1}/{total}] ❌ Недоступен / Ошибка соединения")
            return None

    except Exception as e:
        print(f"[{idx + 1}/{total}] ❌ Ошибка проверки: {e}")
        try:
            process_manager.stop_process(f"xray_{idx}")
            process_manager.stop_process(f"hysteria_{idx}")
        except Exception:
            pass
        return None


def check_configs(links: List[str]) -> List[str]:
    """Проверяет список конфигов с лимитом: останавливается, как наберет MAX_WORKING_LIMIT рабочих."""
    if not CHECK_ENABLED:
        print("[i] Проверка отключена (CHECK_ENABLED=False)")
        return links

    total = len(links)
    print(
        f"\n🚀 Запуск проверки {total} конфигураций (цель: набрать {MAX_WORKING_LIMIT} рабочих) в {TH_MAX_WORKER} потоков...\n"
    )

    working = []
    stop_event = threading.Event()  # Флаг для досрочной остановки потоков

    with ThreadPoolExecutor(max_workers=TH_MAX_WORKER) as executor:
        futures = {}
        for i, link in enumerate(links):
            if stop_event.is_set():
                break
            fut = executor.submit(check_one_config, link, i, total)
            futures[fut] = link

        for fut in as_completed(futures):
            if stop_event.is_set():
                continue
            try:
                res = fut.result()
            except Exception as e:
                print(f"[!] Ошибка future: {e}")
                res = None

            if res is not None:
                working.append(res)
                print(
                    f"🎯 Набрано рабочих конфигов: {len(working)}/{MAX_WORKING_LIMIT}"
                )

                if len(working) >= MAX_WORKING_LIMIT:
                    print(
                        f"\n🛑 Достигнут лимит в {MAX_WORKING_LIMIT} рабочих конфигов. Останавливаем проверку!"
                    )
                    stop_event.set()
                    break

    print(
        f"\n🎉 Проверка завершена досрочно! Отобрано рабочих конфигов: {len(working)}"
    )
    return working


# ============================================================
# Часть 3: Happ API
# ============================================================


def encrypt_happ_link(raw_url):
    api_url = "https://crypto.happ.su/api-v2.php"
    payload = json.dumps({"url": raw_url}).encode("utf-8")
    req = urllib.request.Request(
        api_url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": UA},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                encrypted_link = data.get("encrypted_link")
                if encrypted_link and encrypted_link.startswith(
                    "happ://crypt5/"
                ):
                    print("[✓] Ссылка Happ успешно создана.")
                    return encrypted_link
                else:
                    print(f"[!] API Happ вернул неожиданный ответ: {data}")
                    return None
            else:
                print(f"[!] Ошибка API Happ: HTTP {response.status}")
                return None
    except Exception as e:
        print(f"[!] Ошибка при запросе к API Happ: {e}")
        return None


# ============================================================
# main
# ============================================================


def main():
    force = FORCE_REBUILD or ("--force" in sys.argv)

    if not SOURCES.exists():
        print(f"[!] Нет {SOURCES}", file=sys.stderr)
        return 1

    urls = [
        l.strip()
        for l in SOURCES.read_text(encoding="utf-8").splitlines()
        if l.strip() and not l.lstrip().startswith("#")
    ]
    if not urls:
        print("[!] sources.txt пустой", file=sys.stderr)
        return 0

    changed, new_state, cached = check_sources_changed(urls, force=force)
    save_state(new_state)

    # Сбор ссылок
    all_links = []
    for url in urls:
        try:
            raw = cached.get(url)
            if raw is None:
                print(f"[+] Загрузка: {url}")
                raw = fetch(url)
            decoded = decode_subscription(raw)
            for line in decoded.splitlines():
                line = line.strip()
                if "://" in line and not line.startswith("#"):
                    all_links.append(line)
        except Exception as e:
            print(f"[!] Ошибка {url}: {e}", file=sys.stderr)

    print(f"[=] Всего строк: {len(all_links)}")

    # Дедупликация
    seen = set()
    unique_links = []
    for link in all_links:
        t, h, p = parse_link(link)
        key = (t, h, p) if (t and h) else ("__raw__", link, "")
        if key in seen:
            continue
        seen.add(key)
        unique_links.append(link)
    all_links = unique_links
    print(f"[=] После дедупликации: {len(all_links)}")

    # Проверка работоспособности
    if CHECK_ENABLED:
        all_links = check_configs(all_links)
    else:
        print("[i] Проверка отключена, используются все конфиги")

    if not all_links:
        print(
            "[!] После проверки не осталось рабочих конфигов. merged.txt не обновляется."
        )
        current_time = datetime.now().strftime("%d.%m.%Y %H:%M")
        raw_url = "https://raw.githubusercontent.com/A-N-D-R-404/V-Merge.github.io/refs/heads/main/output/merged.txt"
        encrypted = encrypt_happ_link(raw_url) or raw_url
        OUT_HAPP.write_text(
            json.dumps(
                {
                    "encrypted_link": encrypted,
                    "updated_at": current_time,
                    "config_count": 0,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        return 0

    # Геолокация (только для рабочих)
    hosts = [h for _, h, _ in (parse_link(l) for l in all_links) if h]
    geo = load_geo()
    print(f"[=] Записей в кэше до: {len(geo)}")
    geo = update_geo_cache(hosts, geo)
    save_geo(geo)
    print(f"[=] Записей в кэше после: {len(geo)}")

    # Переименование с флагами
    renamed = []
    counter = {}
    for link in all_links:
        _, h, _ = parse_link(link)
        cc = geo.get(h.lower(), "XX") if h else "XX"
        counter[cc] = counter.get(cc, 0) + 1
        tag = f"{flag(cc)} {cc} #{counter[cc]}"
        renamed.append(rename_link(link, tag))

    current_time = datetime.now().strftime("%d.%m.%Y %H:%M")

    metadata_header = (
        "#profile-title: V-Merge 🚀\n"
        f"#announce: Обновлено: {current_time} | Конфигов: {len(renamed)} | Автообновление\n"
        "#profile-web-page-url: https://a-n-d-r-404.github.io/V-Merge.github.io/\n"
        "#support-url: https://t.me/V_Merge_VPN\n"
        "#profile-update-interval: 1\n"
    )

    text = metadata_header + "\n".join(renamed)
    if renamed:
        text += "\n"

    OUT_PLAIN.parent.mkdir(parents=True, exist_ok=True)
    OUT_PLAIN.write_text(text, encoding="utf-8")
    OUT_B64.write_text(
        base64.b64encode(text.encode("utf-8")).decode(), encoding="utf-8"
    )
    print(f"[✓] {OUT_PLAIN} ({len(renamed)} шт.)")
    print(f"[✓] {OUT_B64}")

    # Happ API
    print("[i] Запрос к API Happ для шифрования ссылки...")
    raw_merged_url = "https://raw.githubusercontent.com/A-N-D-R-404/V-Merge.github.io/refs/heads/main/output/merged.txt"
    encrypted_link = encrypt_happ_link(raw_merged_url)
    if not encrypted_link:
        print("[!] API Happ не ответил. Использую резервную ссылку (fallback).")
        encrypted_link = raw_merged_url

    happ_data = {
        "encrypted_link": encrypted_link,
        "updated_at": current_time,
        "config_count": len(renamed),
    }
    OUT_HAPP.write_text(
        json.dumps(happ_data, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"[✓] {OUT_HAPP} (ссылка: {encrypted_link[:30]}...)")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        process_manager.stop_all()
