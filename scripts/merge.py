#!/usr/bin/env python3
"""
V-Merge: объединённый скрипт сбора, проверки и публикации VPN-конфигов.
Заменяет merge.py + cl.py. Не создаёт новых файлов в репозитории.

Поток:
1. Читает источники из scripts/sources.txt (динамически).
2. Скачивает и дедуплицирует конфиги.
3. Отсеивает ранее известные нерабочие конфиги (dead_cache.json).
4. Проверяет работоспособность каждого конфига через Xray/Hysteria (с ограничением 500 рабочих).
5. Определяет страну для рабочих конфигов (ip-api.com).
6. Переименовывает с флагами и сохраняет в output/merged.txt.
7. Обновляет output/happ_link.txt через API Happ.
"""
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
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from json import JSONEncoder
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
import requests
import yaml
from requests import RequestException
from retrying import retry

# ============================================================
# Пути
# ============================================================
ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "scripts" / "sources.txt"
GEO_CACHE = ROOT / "scripts" / "geo_cache.json"
DEAD_CACHE = ROOT / "scripts" / "dead_cache.json"  # 🛑 Файл кэша нерабочих конфигов
STATE_FILE = ROOT / "scripts" / "sources_state.json"
CONF_PATH = ROOT / "scripts" / "config.json"
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
TH_MAX_WORKER = 10  # 🚀 10 одновременных проверок
MAX_WORKING_LIMIT = 500  # 🎯 Лимит рабочих конфигов
CHECK_TIMEOUT = 18  # секунд на HTTP-запрос через прокси
PROXY_TCP_TIMEOUT = 2.5  # секунд на TCP-подключение к локальному прокси
XRAY_STARTUP_TIMEOUT = 8.0  # максимум секунд на открытие локального порта Xray
DEAD_CACHE_MAX_FAILS = 3  # сколько раз подряд нода должна провалить проверку для попадания в кэш
DEAD_CACHE_TTL_DAYS = 30  # срок жизни записей в dead_cache в днях
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
    if len(code) == 2 and code.isalpha():
        return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)
    return "🏴"


# ============================================================
# Управление кэшем нерабочих конфигов
# ============================================================


def get_config_hash(link: str) -> str:
    """Генерирует чистый идентификатор конфига без тегов для кэша."""
    base_link = link.split("#", 1)[0].strip()
    return hashlib.md5(base_link.encode("utf-8")).hexdigest()


def _normalize_dead_entry(raw_entry: Any, now_ts: int) -> Optional[Dict[str, int]]:
    if isinstance(raw_entry, dict):
        fails = int(raw_entry.get("fails", 0))
        last_check = int(raw_entry.get("last_check", now_ts))
    elif isinstance(raw_entry, (int, float)):
        fails = int(raw_entry)
        last_check = now_ts
    else:
        return None
    if fails <= 0:
        return None
    return {"fails": fails, "last_check": last_check}


def load_dead_cache() -> Dict[str, Dict[str, int]]:
    """Загружает кэш неудач {hash: {"fails": N, "last_check": ts}} и чистит просроченные записи."""
    if not DEAD_CACHE.exists():
        return {}
    now_ts = int(time.time())
    ttl_seconds = DEAD_CACHE_TTL_DAYS * 86400
    try:
        data = json.loads(DEAD_CACHE.read_text(encoding="utf-8"))
        result: Dict[str, Dict[str, int]] = {}
        removed_expired = 0

        if isinstance(data, dict):
            for k, v in data.items():
                entry = _normalize_dead_entry(v, now_ts)
                if not entry:
                    continue
                if now_ts - entry["last_check"] > ttl_seconds:
                    removed_expired += 1
                    continue
                result[str(k)] = entry
        elif isinstance(data, list):
            for h in data:
                result[str(h)] = {
                    "fails": DEAD_CACHE_MAX_FAILS,
                    "last_check": now_ts,
                }

        if removed_expired > 0:
            print(
                f"[i] Удалено устаревших записей из {DEAD_CACHE.name} (> {DEAD_CACHE_TTL_DAYS} дн.): {removed_expired}"
            )
        return result
    except Exception as e:
        print(f"[!] Ошибка чтения dead_cache.json: {e}", file=sys.stderr)
        return {}


def save_dead_cache(dead_map: Dict[str, Dict[str, int]]):
    """Гарантированно создает папку и сохраняет счётчик нерабочих конфигов с меткой времени."""
    try:
        DEAD_CACHE.parent.mkdir(parents=True, exist_ok=True)
        now_ts = int(time.time())
        cleaned: Dict[str, Dict[str, int]] = {}
        for k, v in dead_map.items():
            entry = _normalize_dead_entry(v, now_ts)
            if entry:
                cleaned[str(k)] = entry

        DEAD_CACHE.write_text(
            json.dumps(cleaned, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        blocked_count = sum(
            1
            for item in cleaned.values()
            if item.get("fails", 0) >= DEAD_CACHE_MAX_FAILS
        )
        print(
            f"[✓] Кэш неудач сохранен в {DEAD_CACHE.name} ({len(cleaned)} записей, заблокировано: {blocked_count})"
        )
    except Exception as e:
        print(f"[!] Ошибка сохранения {DEAD_CACHE.name}: {e}", file=sys.stderr)


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
            return f"{int(yy):04d}-{int(mm):02d}-{int(dd):02d} {hh:02d}:{mi:02d}"
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


def _get_real_ip() -> Optional[str]:
    """Получает внешний IP раннера (без прокси) для сверки выхода через ноду."""
    endpoints = [
        ("https://api.ipify.org?format=json", lambda r: r.json().get("ip", "")),
        ("https://ifconfig.me/ip", lambda r: r.text.strip()),
        ("https://icanhazip.com", lambda r: r.text.strip()),
        ("https://api.myip.com", lambda r: r.json().get("ip", "")),
    ]
    for url, extractor in endpoints:
        for _ in range(2):
            try:
                r = requests.get(url, timeout=8)
                if r.status_code == 200:
                    ip = str(extractor(r)).strip()
                    if ip and (ip.count(".") == 3 or ":" in ip):
                        return ip
            except Exception:
                time.sleep(0.3)
    return None


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


def _extract_host_port_from_uri(uri: str) -> tuple[str, int]:
    """Извлекает address и port из URI с поддержкой IPv6 ([2001:db8::1]:443)."""
    parsed = urllib.parse.urlparse(uri)
    if parsed.hostname and parsed.port:
        return parsed.hostname.strip("[]"), int(parsed.port)
    if "@" in uri:
        after = uri.split("@", 1)[1]
        host_port = after.split("/", 1)[0].split("?", 1)[0].strip()
        if host_port.startswith("["):
            end_bracket = host_port.find("]")
            if end_bracket != -1:
                host = host_port[1:end_bracket]
                rest = host_port[end_bracket + 1 :]
                if rest.startswith(":") and rest[1:].isdigit():
                    return host, int(rest[1:])
        elif ":" in host_port:
            h, p = host_port.rsplit(":", 1)
            if p.isdigit():
                return h.strip(), int(p)
    return "", 0


def parse_config_params(config: str) -> ConfigParams:
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
    addr, port = _extract_host_port_from_uri(main_config)

    if protocol in ("vless", "trojan"):
        user_info = ""
        if "@" in main_config:
            prefix = main_config.split("@", 1)[0]
            user_info = prefix.split("://", 1)[1] if "://" in prefix else prefix
        common.update(
            {
                "id": user_info if protocol == "vless" else "",
                "address": addr,
                "port": port,
            }
        )
    elif protocol == "wireguard":
        secret_key = ""
        if "@" in main_config:
            prefix = main_config.split("@", 1)[0]
            secret_key = prefix.split("://", 1)[1] if "://" in prefix else prefix
        common.update(
            {
                "wg_secret_key": secret_key,
                "address": addr,
                "port": port,
            }
        )
    elif protocol in ("hy2", "hysteria2"):
        pwd = ""
        if "@" in main_config:
            prefix = main_config.split("@", 1)[0]
            pwd = prefix.split("://", 1)[1] if "://" in prefix else prefix
        common.update(
            {
                "ss_password": pwd,
                "address": addr,
                "port": port,
            }
        )
    else:
        common.update(
            {
                "address": addr,
                "port": port,
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
            address=str(vm.get("add", "")).strip("[]"),
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
        pwd = ""
        if "@" in main_config:
            prefix = main_config.split("@", 1)[0]
            pwd = prefix.split("://", 1)[1] if "://" in prefix else prefix
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
                server_clean = server.split("?", 1)[0]
                parsed_addr, parsed_port = _extract_host_port_from_uri(
                    f"ss://{server_clean}"
                )
                if parsed_addr:
                    address = parsed_addr
                if parsed_port:
                    port = parsed_port
            else:
                dec = base64.b64decode(
                    main_part + "=" * (-len(main_part) % 4)
                ).decode()
                if "@" in dec:
                    auth, server = dec.split("@", 1)
                    if ":" in auth:
                        method, password = auth.split(":", 1)
                    server_clean = server.split("?", 1)[0]
                    parsed_addr, parsed_port = _extract_host_port_from_uri(
                        f"ss://{server_clean}"
                    )
                    if parsed_addr:
                        address = parsed_addr
                    if parsed_port:
                        port = parsed_port
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
    TLS = "tls"
    REALITY = "reality"

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


def start_xray(conf_path: Path, idx: int, err_log_path: Optional[Path] = None) -> subprocess.Popen:
    if not XRAY_BIN.exists():
        raise FileNotFoundError(f"Xray не найден: {XRAY_BIN}")
    stderr_target = (
        open(err_log_path, "wb") if err_log_path is not None else subprocess.DEVNULL
    )
    try:
        proc = subprocess.Popen(
            [str(XRAY_BIN), "run", "-c", str(conf_path)],
            stdout=subprocess.DEVNULL,
            stderr=stderr_target,
        )
    finally:
        if stderr_target is not subprocess.DEVNULL:
            stderr_target.close()
    process_manager.add_process(f"xray_{idx}", proc.pid)
    return proc


def start_hy2(yaml_path: Path, idx: int, err_log_path: Optional[Path] = None) -> subprocess.Popen:
    if not HY2_BIN.exists():
        raise FileNotFoundError(f"Hysteria не найден: {HY2_BIN}")
    stderr_target = (
        open(err_log_path, "wb") if err_log_path is not None else subprocess.DEVNULL
    )
    try:
        proc = subprocess.Popen(
            [str(HY2_BIN), "client", "-c", str(yaml_path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=stderr_target,
        )
    finally:
        if stderr_target is not subprocess.DEVNULL:
            stderr_target.close()
    process_manager.add_process(f"hysteria_{idx}", proc.pid)
    return proc


def _read_stderr_tail(err_log_path: Optional[Path], max_chars: int = 300) -> str:
    if not err_log_path or not err_log_path.exists():
        return ""
    try:
        content = err_log_path.read_text(encoding="utf-8", errors="ignore").strip()
        if not content:
            return ""
        return content[-max_chars:].replace("\n", " | ")
    except Exception:
        return ""


def build_hy2_yaml(params: ConfigParams, local_port: int) -> dict:
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


def _wait_for_port(
    host: str, port: int, timeout: float, proc: Optional[subprocess.Popen] = None
) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc is not None and proc.poll() is not None:
            return False
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def _verify_proxy_response(
    resp: requests.Response,
    real_ip: Optional[str] = None,
    proxy_url: Optional[str] = None,
) -> bool:
    """
    Проверяет, что ответ валиден и не похож на прямой обход прокси.
    Если real_ip неизвестен, делает дополнительный запрос к generate_204
    через тот же прокси, чтобы подтвердить, что прокси реально работает.
    """
    if resp.status_code not in (200, 204):
        return False
    body = (resp.text or "").strip()
    if resp.status_code == 200 and not body:
        return False
    if body:
        try:
            data = resp.json()
            if isinstance(data, dict) and "ip" in data:
                proxy_ip = str(data.get("ip", "")).strip()
                if not proxy_ip:
                    return False
                if real_ip and proxy_ip == real_ip:
                    # IP совпал с реальным — прокси не сработал
                    return False
                if not real_ip:
                    # Не можем сверить IP — делаем fallback-проверку через 204
                    if proxy_url:
                        try:
                            test = requests.get(
                                "http://cp.cloudflare.com/generate_204",
                                proxies={"http": proxy_url, "https": proxy_url},
                                timeout=8,
                                headers={"Connection": "close"},
                            )
                            return test.status_code == 204
                        except Exception:
                            return False
                    return False
        except ValueError:
            pass
    return True


def check_one_config(
    link: str, idx: int, total: int, real_ip: Optional[str] = None
) -> str:
    """
    Возвращает:
    - "ok": рабочий конфиг
    - "dead": нода недоступна / провалила сетевую проверку
    - "error": ошибка парсинга или запуска локального процесса (не должна «залипать» в dead_cache)
    """
    print(f"[{idx + 1}/{total}] 🔍 Проверяется узел: {link[:50]}...")

    if not CHECK_ENABLED or not TEST_URL:
        print(f"[{idx + 1}/{total}] ⚠️ Проверка отключена или нет TEST_URL")
        return "ok"

    params: Optional[ConfigParams] = None
    local_port = (idx % 50) + 2
    xray_conf_path = XRAY_TMP_DIR / f"check_{idx}.json"
    hy2_yaml_path = HY2_TMP_DIR / f"check_{idx}.yaml"
    xray_err_path = XRAY_TMP_DIR / f"check_{idx}.err.log"
    hy2_err_path = HY2_TMP_DIR / f"check_{idx}_hy2.err.log"

    try:
        try:
            params = parse_config_params(link)
            if not params.address or not params.port:
                print(
                    f"[{idx + 1}/{total}] ❌ Пропуск: не удалось извлечь address/port"
                )
                return "error"
        except Exception as e:
            print(f"[{idx + 1}/{total}] ❌ Ошибка парсинга конфига: {e}")
            return "error"

        hy2_proc: Optional[subprocess.Popen] = None
        if params.protocol in ("hy2", "hysteria2"):
            hy2_yaml = build_hy2_yaml(params, local_port)
            with open(hy2_yaml_path, "w") as f:
                yaml.dump(hy2_yaml, f)
            hy2_proc = start_hy2(hy2_yaml_path, idx, hy2_err_path)
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
        xray_proc = start_xray(xray_conf_path, idx, xray_err_path)

        local_host = f"127.0.0.{local_port}"
        http_port = _get_http_port()
        port_ready = _wait_for_port(
            local_host, http_port, XRAY_STARTUP_TIMEOUT, proc=xray_proc
        )

        if not port_ready or xray_proc.poll() is not None:
            err_tail = _read_stderr_tail(xray_err_path) or _read_stderr_tail(
                hy2_err_path
            )
            extra = f" ({err_tail})" if err_tail else ""
            print(
                f"[{idx + 1}/{total}] ❌ Локальный порт {local_host}:{http_port} не поднялся{extra}"
            )
            return "dead"

        try:
            with socket.create_connection(
                (local_host, http_port), timeout=PROXY_TCP_TIMEOUT
            ):
                pass
        except OSError:
            print(f"[{idx + 1}/{total}] ❌ Таймаут TCP к локальному прокси")
            return "dead"

        proxy_url = f"http://{local_host}:{http_port}"
        proxies = {
            "http": proxy_url,
            "https": proxy_url,
        }
        try:
            r = requests.get(
                TEST_URL,
                proxies=proxies,
                timeout=CHECK_TIMEOUT,
                headers={"Connection": "close"},
            )
            ok = _verify_proxy_response(
                r, real_ip=real_ip, proxy_url=proxy_url
            )
        except Exception:
            ok = False

        if ok:
            print(f"[{idx + 1}/{total}] ✅ Успешно рабочий узел")
            return "ok"
        else:
            err_tail = _read_stderr_tail(xray_err_path) or _read_stderr_tail(
                hy2_err_path
            )
            extra = f" | log: {err_tail}" if err_tail else ""
            print(
                f"[{idx + 1}/{total}] ❌ Недоступен / Ошибка соединения{extra}"
            )
            return "dead"

    except Exception as e:
        print(f"[{idx + 1}/{total}] ❌ Ошибка проверки: {e}")
        return "error"
    finally:
        for p in (xray_conf_path, hy2_yaml_path, xray_err_path, hy2_err_path):
            try:
                p.unlink()
            except Exception:
                pass
        try:
            if params and params.protocol in ("hy2", "hysteria2"):
                process_manager.stop_process(f"hysteria_{idx}")
            process_manager.stop_process(f"xray_{idx}")
        except Exception:
            pass


def check_configs(links: List[str]) -> List[str]:
    """Проверяет список конфигов с отсечением нерабочих и строгим прерыванием по лимиту 500."""
    if not CHECK_ENABLED:
        print("[i] Проверка отключена (CHECK_ENABLED=False)")
        return links

    dead_cache = load_dead_cache()
    filtered_links = []
    skipped_count = 0

    # 1. Отсеиваем конфиги, набравшие порог неудач в чёрном списке
    for link in links:
        cfg_hash = get_config_hash(link)
        fails = dead_cache.get(cfg_hash, {}).get("fails", 0)
        if fails >= DEAD_CACHE_MAX_FAILS:
            skipped_count += 1
        else:
            filtered_links.append(link)

    print(
        f"[=] Всего строк: {len(links)} | В черном списке (пропущено): {skipped_count} | Осталось к проверке: {len(filtered_links)}"
    )

    total = len(filtered_links)
    if total == 0:
        save_dead_cache(dead_cache)
        return []

    real_ip = _get_real_ip()
    if real_ip:
        print(f"[i] Внешний IP раннера для сверки прокси: {real_ip}")
    else:
        print(
            "[!] Не удалось определить внешний IP раннера (при проверке IP будет использован fallback через generate_204)"
        )

    print(
        f"\n🚀 Запуск проверки {total} конфигураций (цель: {MAX_WORKING_LIMIT} рабочих) в {TH_MAX_WORKER} потоков...\n"
    )

    working = []
    stop_event = threading.Event()
    now_ts = int(time.time())

    try:
        with ThreadPoolExecutor(max_workers=TH_MAX_WORKER) as executor:
            futures = {}
            for i, link in enumerate(filtered_links):
                if stop_event.is_set():
                    break
                fut = executor.submit(check_one_config, link, i, total, real_ip)
                futures[fut] = link

            for fut in as_completed(futures):
                link = futures[fut]
                if stop_event.is_set():
                    break
                try:
                    status = fut.result()
                except Exception as e:
                    print(f"[!] Ошибка future: {e}")
                    status = "error"

                cfg_hash = get_config_hash(link)

                if status == "ok":
                    dead_cache.pop(cfg_hash, None)
                    working.append(link)
                    print(
                        f"🎯 Набрано рабочих конфигов: {len(working)}/{MAX_WORKING_LIMIT}"
                    )

                    if len(working) >= MAX_WORKING_LIMIT:
                        print(
                            f"\n🛑 Лимит в {MAX_WORKING_LIMIT} рабочих конфигов достигнут! Экстренно останавливаем проверку."
                        )
                        stop_event.set()
                        for f in futures:
                            f.cancel()
                        break
                elif status == "dead":
                    prev_fails = dead_cache.get(cfg_hash, {}).get("fails", 0)
                    dead_cache[cfg_hash] = {
                        "fails": prev_fails + 1,
                        "last_check": now_ts,
                    }
                else:
                    # "error": ошибка парсинга/запуска — счётчик не увеличиваем
                    pass
    finally:
        save_dead_cache(dead_cache)

    blocked_total = sum(
        1
        for item in dead_cache.values()
        if item.get("fails", 0) >= DEAD_CACHE_MAX_FAILS
    )
    print(
        f"\n🎉 Проверка завершена! Рабочих конфигов: {len(working)} | Записей в черном списке: {blocked_total}"
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
