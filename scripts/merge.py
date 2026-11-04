#!/usr/bin/env python3
import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "scripts" / "sources.txt"
GEO_CACHE = ROOT / "scripts" / "geo_cache.json"
STATE_FILE = ROOT / "scripts" / "sources_state.json"
OUT_PLAIN = ROOT / "output" / "merged.txt"
OUT_B64 = ROOT / "output" / "merged.base64.txt"
OUT_HAPP = ROOT / "output" / "happ_link.txt"

UA = "Mozilla/5.0 (compatible; V-Merge-Bot/1.0)"

GEO_ENABLED = True
MAX_NEW = 200
DELAY_BETWEEN = 1.5
RENAME_ENABLED = True
FORCE_REBUILD = False

FLAGS = {
    "RU": "🇷🇺", "US": "🇺🇸", "DE": "🇩🇪", "NL": "🇳🇱", "FR": "🇫🇷",
    "GB": "🇬🇧", "FI": "🇫🇮", "SE": "🇸🇪", "TR": "🇹🇷", "JP": "🇯🇵",
    "KR": "🇰🇷", "SG": "🇸🇬", "CA": "🇨🇦", "PL": "🇵🇱", "UA": "🇺🇦",
    "KZ": "🇰🇿", "CN": "🇨🇳", "HK": "🇭🇰", "IN": "🇮🇳", "BR": "🇧🇷",
    "IR": "🇮🇷", "AE": "🇦🇪", "IT": "🇮🇹", "ES": "🇪🇸", "CH": "🇨🇭",
    "AT": "🇦🇹", "CZ": "🇨🇿", "RO": "🇷🇴", "MD": "🇲🇩", "LV": "🇱🇻",
    "LT": "🇱🇹", "EE": "🇪🇪", "AM": "🇦🇲", "GE": "🇬🇪", "AZ": "🇦🇿",
    "IL": "🇮🇱", "AU": "🇦🇺", "NZ": "🇳🇿", "MX": "🇲🇽", "AR": "🇦🇷",
    "BG": "🇧🇬", "RS": "🇷🇸", "HR": "🇭🇷", "SK": "🇸🇰", "SI": "🇸🇮",
    "TH": "🇹🇭", "VN": "🇻🇳", "MY": "🇲🇾", "ID": "🇮🇩", "PH": "🇵🇭",
    "NO": "🇳🇴", "DK": "🇩🇰", "BE": "🇧🇪", "IE": "🇮🇪", "PT": "🇵🇹",
    "GR": "🇬🇷", "HU": "🇭🇺", "AL": "🇦🇱", "IM": "🇮🇲",
}


def flag(cc):
    return FLAGS.get(cc, "🏴")


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
                h = hashlib.md5(raw.encode("utf-8", errors="ignore")).hexdigest()[:12]
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
            b64 = link[len("vmess://"):]
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
            b64 = link[len("vmess://"):]
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


def send_telegram_notification(message):
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")

    if not token or not chat_id:
        print("[i] Telegram секреты не найдены, пропускаем отправку уведомления.")
        return

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown"
    }).encode("utf-8")

    try:
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=10):
            print("[✓] Уведомление в Telegram успешно отправлено!")
    except Exception as e:
        print(f"[!] Ошибка при отправке уведомления в Telegram: {e}", file=sys.stderr)


def encrypt_happ_link(raw_url):
    api_url = "https://crypto.happ.su/api-v2.php"
    
    payload = json.dumps({"url": raw_url}).encode("utf-8")
    
    req = urllib.request.Request(
        api_url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": UA
        },
        method="POST"
    )
    
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            if response.status == 200:
                response_data = json.loads(response.read().decode("utf-8"))
                encrypted_link = response_data.get("encrypted_link")
                if encrypted_link and encrypted_link.startswith("happ://crypt5/"):
                    print("[✓] Ссылка Happ успешно создана.")
                    return encrypted_link
                else:
                    print(f"[!] API Happ вернул неожиданный ответ: {response_data}")
                    return None
            else:
                print(f"[!] Ошибка API Happ: HTTP {response.status}")
                return None
    except Exception as e:
        print(f"[!] Ошибка при запросе к API Happ: {e}")
        return None


def main():
    force = FORCE_REBUILD or ("--force" in sys.argv)

    if not SOURCES.exists():
        print("[!] Нет scripts/sources.txt", file=sys.stderr)
        return 1

    urls = [
        l.strip() for l in SOURCES.read_text(encoding="utf-8").splitlines()
        if l.strip() and not l.lstrip().startswith("#")
    ]
    if not urls:
        print("[!] sources.txt пустой", file=sys.stderr)
        return 0

    changed, new_state, cached = check_sources_changed(urls, force=force)
    save_state(new_state)

    if not changed:
        print("[✓] Источники не изменились. Пересборка не требуется.")
        if not OUT_PLAIN.exists():
            print("[i] output/merged.txt отсутствует — собираю принудительно")
        else:
            return 0

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

    hosts = [h for _, h, _ in (parse_link(l) for l in all_links) if h]
    geo = load_geo()
    print(f"[=] Записей в кэше до: {len(geo)}")
    geo = update_geo_cache(hosts, geo)
    save_geo(geo)
    print(f"[=] Записей в кэше после: {len(geo)}")

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
        "#profile-web-page-url: https://alexanderru44.github.io/V-Merge.github.io/\n"
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

    print("[i] Запрос к API Happ для шифрования ссылки...")
   raw_merged_url = "https://raw.githubusercontent.com/A-N-D-R-404/V-Merge.github.io/refs/heads/main/output/merged.txt"
    
    encrypted_link = encrypt_happ_link(raw_merged_url)
    
    if encrypted_link:
        # Сохраняем данные для бота: ссылка | время | количество
        happ_data = f"{encrypted_link}|{current_time}|{len(renamed)}"
        OUT_HAPP.write_text(happ_data, encoding="utf-8")
        print(f"[✓] {OUT_HAPP}")
    else:
        print("[!] Не удалось создать ссылку Happ.")

    send_telegram_notification(
        f"🚀 *V-Merge успешно обновлен!*\n\n"
        f"📅 Время: `{current_time}`\n"
        f"🔗 Активных конфигураций: `{len(renamed)}`"
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
