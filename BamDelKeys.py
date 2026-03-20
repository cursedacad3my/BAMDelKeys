import sys
import ctypes
import ctypes.wintypes
import struct
import winreg
import os
import hashlib
import math
import glob
from datetime import datetime, timezone

from colorama import init as colorama_init
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.status import Status

colorama_init(wrap=False)
console = Console(record=True)

BAM_PATHS = [
    r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
    r"SYSTEM\CurrentControlSet\Services\bam\UserSettings",
    r"SYSTEM\ControlSet001\Services\bam\State\UserSettings",
    r"SYSTEM\ControlSet001\Services\bam\UserSettings",
    r"SYSTEM\ControlSet002\Services\bam\State\UserSettings",
    r"SYSTEM\ControlSet002\Services\bam\UserSettings",
]

SUSPECT_KEYWORDS = [
    "vape", "client", "inject", "reach", "clicker", "cheat",
    "hitbox", "internal", "external", "ghost", "bypass", "crack",
    "keygen", "loader", "injector", "aimbot", "triggerbot", "esp",
    "wallhack", "spinbot", "bhop", "autoclick", "macro"
]

SUSPICIOUS_FOLDERS = [
    r"\appdata\local\temp",
    r"\windows\fonts",
    r"\$recycle.bin",
    r"\programdata\temp",
    r"\users\public"
]

MINECRAFT_STRINGS = [b"Lnet/minecraft/", b"org/lwjgl/", b"clicker", b"net.minecraft"]

KNOWN_CHEAT_HASHES: dict[str, str] = {
    # "md5_hash_here": "CheatName v1.0",
}

WINDOWS_EPOCH_OFFSET = 116_444_736_000_000_000
VOLUME_MAP: dict = {}
YARA_RULES = None


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def filetime_to_dt(raw: bytes) -> str | None:
    if len(raw) < 8:
        return None
    ft = struct.unpack("<Q", raw[:8])[0]
    if ft == 0:
        return None
    try:
        unix_us = (ft - WINDOWS_EPOCH_OFFSET) // 10
        return datetime.fromtimestamp(unix_us / 1_000_000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
    except (OSError, OverflowError, ValueError):
        return None


def filetime_to_datetime(raw: bytes) -> datetime | None:
    if len(raw) < 8:
        return None
    ft = struct.unpack("<Q", raw[:8])[0]
    if ft == 0:
        return None
    try:
        unix_us = (ft - WINDOWS_EPOCH_OFFSET) // 10
        return datetime.fromtimestamp(unix_us / 1_000_000, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None


def get_volume_map() -> dict:
    result = {}
    try:
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            buf = ctypes.create_unicode_buffer(512)
            if ctypes.windll.kernel32.QueryDosDeviceW(letter + ":", buf, 512):
                result[buf.value.lower()] = letter + ":\\"
    except Exception:
        pass
    return result


def device_path_to_drive(path: str) -> str | None:
    global VOLUME_MAP
    if not VOLUME_MAP:
        VOLUME_MAP = get_volume_map()
    lower = path.lower()
    for device, drive in VOLUME_MAP.items():
        if lower.startswith(device):
            return drive + path[len(device):]
    return None


def resolve_path(path: str) -> tuple[str, bool]:
    if path.startswith("\\Device\\") or path.startswith(r"\Device\\"):
        converted = device_path_to_drive(path)
        if converted:
            return converted, False
        return path, True
    return path, False


def file_exists(path: str) -> bool:
    try:
        resolved, ghost = resolve_path(path)
        if ghost:
            return False
        return os.path.isfile(resolved)
    except Exception:
        return False


def is_blank_path(path: str) -> bool:
    stripped = path.strip()
    if not stripped:
        return True
    return all(ord(c) < 32 or ord(c) in (0x200B, 0x200C, 0x200D, 0xFEFF, 0x00A0) for c in stripped)


def is_suspect(path: str) -> bool:
    lower = path.lower()
    return any(kw in lower for kw in SUSPECT_KEYWORDS)


def is_suspicious_location(path: str) -> bool:
    lower = path.lower()
    return any(f in lower for f in SUSPICIOUS_FOLDERS)


def check_timestomp(path: str, bam_dt: datetime | None) -> bool:
    if not bam_dt or not os.path.exists(path):
        return False
    try:
        ctime = datetime.fromtimestamp(os.path.getctime(path), tz=timezone.utc)
        return bam_dt < ctime
    except Exception:
        return False


def win_verify_trust(path: str) -> str:
    try:
        WINTRUST_ACTION_GENERIC_VERIFY_V2 = "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}"

        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [
                ("cbStruct",       ctypes.wintypes.DWORD),
                ("pcwszFilePath",  ctypes.wintypes.LPCWSTR),
                ("hFile",          ctypes.wintypes.HANDLE),
                ("pgKnownSubject", ctypes.c_void_p),
            ]

        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", ctypes.c_ulong),
                ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort),
                ("Data4", ctypes.c_ubyte * 8),
            ]

        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [
                ("cbStruct",                ctypes.wintypes.DWORD),
                ("pPolicyCallbackData",     ctypes.c_void_p),
                ("pSIPClientData",          ctypes.c_void_p),
                ("dwUIChoice",              ctypes.wintypes.DWORD),
                ("fdwRevocationChecks",     ctypes.wintypes.DWORD),
                ("dwUnionChoice",           ctypes.wintypes.DWORD),
                ("pFile",                   ctypes.c_void_p),
                ("dwStateAction",           ctypes.wintypes.DWORD),
                ("hWVTStateData",           ctypes.wintypes.HANDLE),
                ("pwszURLReference",        ctypes.wintypes.LPWSTR),
                ("dwProvFlags",             ctypes.wintypes.DWORD),
                ("dwUIContext",             ctypes.wintypes.DWORD),
                ("pSignatureSettings",      ctypes.c_void_p),
            ]

        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = path
        file_info.hFile = None
        file_info.pgKnownSubject = None

        guid_parts = WINTRUST_ACTION_GENERIC_VERIFY_V2.strip("{}").split("-")
        guid = GUID()
        guid.Data1 = int(guid_parts[0], 16)
        guid.Data2 = int(guid_parts[1], 16)
        guid.Data3 = int(guid_parts[2], 16)
        data4 = bytes.fromhex(guid_parts[3] + guid_parts[4])
        for i, b in enumerate(data4):
            guid.Data4[i] = b

        trust_data = WINTRUST_DATA()
        trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        trust_data.dwUIChoice = 2
        trust_data.fdwRevocationChecks = 0
        trust_data.dwUnionChoice = 1
        trust_data.pFile = ctypes.cast(ctypes.pointer(file_info), ctypes.c_void_p)
        trust_data.dwStateAction = 0
        trust_data.dwProvFlags = 0x00000010

        result = ctypes.windll.wintrust.WinVerifyTrust(
            ctypes.wintypes.HANDLE(-1),
            ctypes.byref(guid),
            ctypes.byref(trust_data)
        )

        if result == 0:
            return "signed"
        else:
            return "unsigned"
    except Exception:
        return "unknown"


def check_signature(path: str) -> tuple[str, bool]:
    if not path or not os.path.exists(path):
        return "[dim]N/A[/dim]", False
    status = win_verify_trust(path)
    if status == "signed":
        return "[green]Signed[/green]", True
    # WinVerifyTrust не проверяет catalog-signed файлы (системные Windows).
    # Для них делаем быстрый фолбэк через PowerShell.
    if status == "unsigned":
        lower = path.lower()
        is_system = (
            r"\windows\\" in lower or
            r"\program files\windows" in lower or
            r"\programdata\microsoft\windows defender" in lower
        )
        if is_system:
            try:
                import subprocess
                cmd = f'(Get-AuthenticodeSignature -FilePath "{path}").Status'
                r = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", cmd],
                    capture_output=True, text=True, timeout=3,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                ps_status = r.stdout.strip()
                if ps_status == "Valid":
                    return "[green]Signed[/green]", True
            except Exception:
                pass
        return "[yellow]Unsigned[/yellow]", False
    return "[dim]Unknown[/dim]", False


def calc_hashes(path: str) -> tuple[str, str]:
    try:
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk)
                sha256.update(chunk)
        return md5.hexdigest(), sha256.hexdigest()
    except Exception:
        return "", ""


def calc_entropy(path: str) -> float:
    try:
        with open(path, "rb") as f:
            data = f.read(1_048_576)
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        length = len(data)
        entropy = 0.0
        for c in freq:
            if c:
                p = c / length
                entropy -= p * math.log2(p)
        return round(entropy, 3)
    except Exception:
        return 0.0


def scan_strings(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            data = f.read(2_097_152)
        return any(s in data for s in MINECRAFT_STRINGS)
    except Exception:
        return False


def _find_rules_dir() -> str | None:
    candidates = []
    if hasattr(sys, "_MEIPASS"):
        candidates.append(os.path.join(sys._MEIPASS, "rules"))
    exe_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    candidates.append(os.path.join(exe_dir, "rules"))
    candidates.append("rules")
    for path in candidates:
        if os.path.isdir(path):
            return path
    return None


def load_yara_rules() -> object | None:
    try:
        import yara_x
        rules_dir = _find_rules_dir()
        if not rules_dir:
            return None
        yar_files = glob.glob(os.path.join(rules_dir, "*.yar")) + \
                    glob.glob(os.path.join(rules_dir, "*.yara"))
        if not yar_files:
            return None
        compiler = yara_x.Compiler()
        loaded = 0
        for f in yar_files:
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    compiler.add_source(fh.read())
                loaded += 1
            except Exception as e:
                console.print(f"[yellow]⚠ YARA: ошибка в {os.path.basename(f)}: {e}[/yellow]")
        if loaded == 0:
            return None
        return compiler.build()
    except ImportError:
        return None
    except Exception as e:
        console.print(f"[yellow]⚠ YARA: {e}[/yellow]")
        return None


def yara_scan(path: str, rules) -> list[str]:
    if not rules or not os.path.exists(path):
        return []
    try:
        import yara_x
        scanner = yara_x.Scanner(rules)
        with open(path, "rb") as f:
            data = f.read(4_194_304)
        results = scanner.scan(data)
        return [m.identifier for m in results.matching_rules]
    except Exception:
        return []


def sort_priority(e: dict) -> tuple:
    verdict = e.get("verdict", "")
    is_critical  = "CRITICAL" in verdict
    is_suspect   = e.get("suspect", False)
    is_deleted   = e.get("deleted", False)
    ft           = e.get("filetime_raw", 0)
    return (not is_critical, not is_suspect, not is_deleted, -ft)


def pause_exit():
    console.print("\n[dim]Нажмите Enter для выхода...[/dim]")
    input()


def scan_bam() -> list[dict]:
    entries = []
    seen = set()
    found_any = False

    for candidate in BAM_PATHS:
        try:
            bam_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, candidate, access=winreg.KEY_READ)
        except PermissionError:
            console.print(Panel(
                "[bold red]⛔ Доступ к BAM\\UserSettings запрещён.\n"
                "Запустите скрипт от имени Администратора.[/bold red]",
                title="ACCESS DENIED", border_style="red"
            ))
            pause_exit()
            sys.exit(1)
        except FileNotFoundError:
            continue

        found_any = True
        sid_index = 0
        while True:
            try:
                sid_name = winreg.EnumKey(bam_key, sid_index)
            except OSError:
                break
            sid_index += 1

            try:
                sid_key = winreg.OpenKey(bam_key, sid_name, access=winreg.KEY_READ)
            except PermissionError:
                key = f"__denied__{sid_name}"
                if key not in seen:
                    seen.add(key)
                    entries.append({
                        "sid": sid_name, "program": "???", "path": f"[dim]{sid_name}[/dim]",
                        "last_run": "—", "status": "[bold red]⚠ Key Denied[/bold red]",
                        "trust": "—", "verdict": "[bold red]HIDDEN[/bold red]",
                        "raw_path": "", "deleted": False, "suspect": False,
                        "ghost": False, "filetime_raw": 0, "timestomp": False,
                        "unusual_loc": False, "md5": "", "sha256": "", "entropy": 0.0,
                    })
                continue

            val_index = 0
            while True:
                try:
                    val_name, val_data, _ = winreg.EnumValue(sid_key, val_index)
                except OSError:
                    break
                val_index += 1

                if not val_name.startswith("\\") and not val_name.startswith("/"):
                    continue
                if not isinstance(val_data, bytes):
                    continue

                dedup_key = f"{sid_name}|{val_name}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                ft_raw = struct.unpack("<Q", val_data[:8])[0] if len(val_data) >= 8 else 0
                timestamp    = filetime_to_dt(val_data)
                timestamp_dt = filetime_to_datetime(val_data)
                last_run     = timestamp if timestamp else "[dim]No timestamp[/dim]"

                resolved, is_ghost = resolve_path(val_name)
                exists      = file_exists(val_name)
                deleted     = not exists
                suspect     = is_suspect(val_name)
                blank       = is_blank_path(val_name)
                unusual_loc = is_suspicious_location(resolved)
                timestomp   = check_timestomp(resolved, timestamp_dt) if not is_ghost else False

                if is_ghost:
                    status_text = "[bold magenta]GHOST[/bold magenta]"
                elif exists:
                    status_text = "[green]EXIST[/green]"
                else:
                    status_text = "[red]DELETED[/red]"

                verdict_flags = []
                if blank:
                    verdict_flags.append("[bold red]BLANK PATH[/bold red]")
                    suspect = True
                elif is_ghost and suspect:
                    verdict_flags.append("[bold red]GHOST+SUSPECT[/bold red]")
                elif is_ghost:
                    verdict_flags.append("[bold magenta]GHOST DEVICE[/bold magenta]")
                elif suspect and deleted:
                    verdict_flags.append("[bold red]TRACE DETECTED[/bold red]")
                elif suspect:
                    verdict_flags.append("[bold red]SUSPECT[/bold red]")

                if timestomp:
                    verdict_flags.append("[bold red]TIMESTOMP[/bold red]")
                    suspect = True
                if unusual_loc and not is_ghost:
                    verdict_flags.append("[yellow]UNUSUAL LOC[/yellow]")
                    suspect = True
                if not verdict_flags:
                    verdict_flags.append("[green]CLEAN[/green]")

                entries.append({
                    "sid": sid_name,
                    "program": os.path.basename(resolved) if resolved else "Unknown",
                    "path": repr(val_name) if blank else resolved,
                    "last_run": last_run,
                    "status": status_text,
                    "trust": None,
                    "verdict": " + ".join(verdict_flags),
                    "raw_path": resolved,
                    "deleted": deleted,
                    "suspect": suspect,
                    "ghost": is_ghost,
                    "filetime_raw": ft_raw,
                    "timestomp": timestomp,
                    "unusual_loc": unusual_loc,
                    "md5": "", "sha256": "", "entropy": 0.0,
                })

            winreg.CloseKey(sid_key)
        winreg.CloseKey(bam_key)

    if not found_any:
        console.print("[yellow]⚠ BAM\\UserSettings не найден ни по одному из известных путей.[/yellow]")

    return entries


def main():
    if not is_admin():
        console.print(Panel(
            "[bold red]⛔  НЕДОСТАТОЧНО ПРАВ  ⛔\n\n"
            "Этот скрипт требует прав Администратора.\n"
            "Запустите CMD / PowerShell от имени Администратора\n"
            "и повторите запуск.",
            title="[bold red]ACCESS DENIED[/bold red]",
            border_style="red", expand=False
        ))
        pause_exit()
        sys.exit(1)

    ascii_art = (
        "██████╗  █████╗ ███╗   ███╗    ██████╗ ███████╗██╗      ██╗  ██╗███████╗██╗   ██╗███████╗\n"
        "██╔══██╗██╔══██╗████╗ ████║    ██╔══██╗██╔════╝██║      ██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔════╝\n"
        "██████╔╝███████║██╔████╔██║    ██║  ██║█████╗  ██║      █████╔╝ █████╗   ╚████╔╝ ███████╗\n"
        "██╔══██╗██╔══██║██║╚██╔╝██║    ██║  ██║██╔══╝  ██║      ██╔═██╗ ██╔══╝    ╚██╔╝  ╚════██║\n"
        "██████╔╝██║  ██║██║ ╚═╝ ██║    ██████╔╝███████╗███████╗ ██║  ██╗███████╗   ██║   ███████║\n"
        "╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝    ╚═════╝ ╚══════╝╚══════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝"
    )
    console.print(Panel(
        f"[bold cyan]{ascii_art}[/bold cyan]\n"
        "[dim cyan]               [ SS-EDITION ]  —  Background Activity Monitor Scanner[/dim cyan]",
        border_style="bright_blue", expand=True
    ))

    global YARA_RULES
    with Status("[bold cyan]Загрузка YARA правил...[/bold cyan]", console=console, spinner="dots"):
        YARA_RULES = load_yara_rules()
    if YARA_RULES:
        console.print("[green]✓ YARA правила загружены[/green]")
    else:
        console.print("[dim]  YARA: папка rules/ не найдена или yara-python не установлен[/dim]")

    entries = []
    with Status("[bold cyan]Сканирование реестра BAM...[/bold cyan]", console=console, spinner="dots"):
        entries = scan_bam()

    if not entries:
        console.print("[yellow]Записи BAM не найдены.[/yellow]")
        pause_exit()
        return

    with Status("[bold cyan]Глубокий анализ файлов...[/bold cyan]", console=console, spinner="bouncingBar"):
        for e in entries:
            path = e["raw_path"]
            exists = not e["deleted"] and not e["ghost"] and path and os.path.isfile(path)

            if not exists:
                e["trust"] = "[dim]N/A[/dim]"
                e["is_signed"] = False
                continue

            trust_str, is_signed = check_signature(path)
            e["trust"] = trust_str
            e["is_signed"] = is_signed

            md5, sha256 = calc_hashes(path)
            e["md5"]    = md5
            e["sha256"] = sha256

            if md5 and md5 in KNOWN_CHEAT_HASHES:
                cheat_name = KNOWN_CHEAT_HASHES[md5]
                e["verdict"] = f"[bold red on black]⚠ CRITICAL: {cheat_name}[/bold red on black]"
                e["suspect"] = True
                continue

            entropy = calc_entropy(path)
            e["entropy"] = entropy

            flags_to_add = []

            if entropy > 7.2 and not is_signed:
                flags_to_add.append("[bold red]PACKED/ENCRYPTED[/bold red]")
                e["suspect"] = True

            if not is_signed and scan_strings(path):
                flags_to_add.append("[bold red]MC-STRINGS[/bold red]")
                e["suspect"] = True

            if not is_signed and os.path.getsize(path) < 500_000:
                flags_to_add.append("[yellow]SMALL+UNSIGNED[/yellow]")
                e["suspect"] = True

            yara_hits = yara_scan(path, YARA_RULES)
            for rule in yara_hits:
                flags_to_add.append(f"[bold red]YARA:{rule}[/bold red]")
                e["suspect"] = True

            if flags_to_add:
                current = e["verdict"]
                if current == "[green]CLEAN[/green]":
                    e["verdict"] = " + ".join(flags_to_add)
                else:
                    e["verdict"] = current + " + " + " + ".join(flags_to_add)

    entries.sort(key=sort_priority)

    table = Table(
        title="[bold cyan]BAM Registry Scan Results[/bold cyan]",
        border_style="bright_blue",
        header_style="bold bright_cyan",
        show_lines=True,
        expand=True
    )
    table.add_column("#",              style="dim", width=4, justify="right")
    table.add_column("Program Name",   style="bold yellow", width=28, overflow="fold")
    table.add_column("Full Path",      style="dim white", min_width=35, overflow="fold")
    table.add_column("Last Run (UTC)", style="bright_white", width=17, justify="center")
    table.add_column("Status",         width=10, justify="center")
    table.add_column("Trust",          width=10, justify="center")
    table.add_column("Entropy",        width=7,  justify="center")
    table.add_column("Verdict",        width=32, overflow="fold", justify="center")

    for i, e in enumerate(entries, start=1):
        entropy_val = e.get("entropy", 0.0)
        entropy_str = (
            f"[bold red]{entropy_val}[/bold red]" if entropy_val > 7.2
            else f"[dim]{entropy_val}[/dim]" if entropy_val > 0
            else "[dim]—[/dim]"
        )
        table.add_row(
            str(i),
            e["program"],
            e["path"],
            e["last_run"],
            e["status"],
            e["trust"] or "—",
            entropy_str,
            e["verdict"],
        )

    console.print(table)

    total      = len(entries)
    suspects   = sum(1 for e in entries if e.get("suspect"))
    traces     = sum(1 for e in entries if e.get("suspect") and e.get("deleted"))
    ghosts     = sum(1 for e in entries if e.get("ghost"))
    criticals  = sum(1 for e in entries if "CRITICAL" in e.get("verdict", ""))
    timestomps = sum(1 for e in entries if e.get("timestomp"))
    unusual    = sum(1 for e in entries if e.get("unusual_loc"))
    packed     = sum(1 for e in entries if "PACKED" in e.get("verdict", ""))
    yara_hits  = sum(1 for e in entries if "YARA:" in e.get("verdict", ""))

    summary = (
        f"[white]Всего:[/white] [cyan]{total}[/cyan]   "
        f"[white]Подозрительных:[/white] [red]{suspects}[/red]   "
        f"[white]CRITICAL:[/white] [bold red]{criticals}[/bold red]   "
        f"[white]Следов:[/white] [bold red]{traces}[/bold red]   "
        f"[white]Ghost:[/white] [magenta]{ghosts}[/magenta]   "
        f"[white]Timestomp:[/white] [bold red]{timestomps}[/bold red]   "
        f"[white]Packed:[/white] [bold red]{packed}[/bold red]   "
        f"[white]YARA:[/white] [bold red]{yara_hits}[/bold red]   "
        f"[white]Unusual:[/white] [yellow]{unusual}[/yellow]"
    )
    console.print(Panel(summary, title="[bold cyan]Итог[/bold cyan]", border_style="bright_blue"))

    console.print("\n[dim cyan]Экспортировать отчёт в HTML? (y/n):[/dim cyan] ", end="")
    try:
        if input().strip().lower() == "y":
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            fname = f"SS_Report_{ts}.html"
            with open(fname, "w", encoding="utf-8") as f:
                f.write(console.export_html())
            console.print(f"[green]✓ Отчёт сохранён: {fname}[/green]")
    except Exception:
        pass

    pause_exit()


if __name__ == "__main__":
    main()
