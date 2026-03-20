import sys
import ctypes
import struct
import subprocess
import winreg
import os
from datetime import datetime, timezone

from colorama import init as colorama_init
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.status import Status

colorama_init()
console = Console()

BAM_PATHS = [
    r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
    r"SYSTEM\CurrentControlSet\Services\bam\UserSettings",
    r"SYSTEM\ControlSet001\Services\bam\State\UserSettings",
    r"SYSTEM\ControlSet001\Services\bam\UserSettings",
    r"SYSTEM\ControlSet002\Services\bam\State\UserSettings",
    r"SYSTEM\ControlSet002\Services\bam\UserSettings",
]
SUSPECT_KEYWORDS = [
    "vape", "client", "inject", "reach", "clicker",
    "cheat", "hitbox", "internal", "external"
]
WINDOWS_EPOCH_OFFSET = 116_444_736_000_000_000


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
        dt = datetime.fromtimestamp(unix_us / 1_000_000, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M")
    except (OSError, OverflowError, ValueError):
        return None


def check_signature(path: str) -> str:
    try:
        cmd = f'(Get-AuthenticodeSignature -FilePath "{path}").Status'
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, timeout=5
        )
        status = result.stdout.strip()
        if status == "Valid":
            return "[green]Signed[/green]"
        elif status in ("NotSigned", ""):
            return "[yellow]Unsigned[/yellow]"
        else:
            return f"[dim]{status}[/dim]"
    except Exception:
        return "[dim]Unknown[/dim]"


def is_suspect(path: str) -> bool:
    lower = path.lower()
    return any(kw in lower for kw in SUSPECT_KEYWORDS)


def is_ghost_device_path(path: str) -> bool:
    return path.startswith("\\Device\\HarddiskVolume") or path.startswith(r"\Device\HarddiskVolume")


def is_blank_path(path: str) -> bool:
    stripped = path.strip()
    if not stripped:
        return True
    invisible = all(
        (ord(c) < 32 or ord(c) in (0x200B, 0x200C, 0x200D, 0xFEFF, 0x00A0))
        for c in stripped
    )
    return invisible


def file_exists(path: str) -> bool:
    if is_ghost_device_path(path):
        return False
    return os.path.isfile(path)


def filetime_sort_key(entry: dict) -> int:
    return entry.get("filetime_raw", 0)


def pause_exit():
    console.print("\n[dim]Нажмите Enter для выхода...[/dim]")
    input()


def scan_bam() -> list[dict]:
    entries = []
    seen = set()
    found_any = False

    for candidate in BAM_PATHS:
        try:
            bam_key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, candidate,
                access=winreg.KEY_READ
            )
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
                        "sid": sid_name,
                        "path": f"[dim]{sid_name}[/dim]",
                        "last_run": "—",
                        "status": "[bold red]⚠ Key Denied/Hidden[/bold red]",
                        "trust": "—",
                        "verdict": "[bold red]⚠ HIDDEN[/bold red]",
                        "raw_path": "",
                        "deleted": False,
                        "suspect": False,
                        "ghost": False,
                        "filetime_raw": 0,
                    })
                continue

            val_index = 0
            while True:
                try:
                    val_name, val_data, val_type = winreg.EnumValue(sid_key, val_index)
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
                timestamp = filetime_to_dt(val_data)
                last_run = timestamp if timestamp else "[dim]No timestamp[/dim]"

                exists = file_exists(val_name)
                deleted = not exists
                suspect = is_suspect(val_name)
                ghost   = is_ghost_device_path(val_name)
                blank   = is_blank_path(val_name)

                if ghost:
                    status_text = "[bold magenta]GHOST[/bold magenta]"
                elif exists:
                    status_text = "[green]EXIST[/green]"
                else:
                    status_text = "[red]DELETED[/red]"

                if blank:
                    verdict = "[bold red]⚠ BLANK PATH[/bold red]"
                    suspect = True
                elif ghost and suspect:
                    verdict = "[bold red]⚠ GHOST+SUSPECT[/bold red]"
                elif ghost:
                    verdict = "[bold magenta]⚠ GHOST DEVICE[/bold magenta]"
                elif suspect and deleted:
                    verdict = "[bold red]⚠ TRACE DETECTED[/bold red]"
                elif suspect:
                    verdict = "[bold red][SUSPECT][/bold red]"
                else:
                    verdict = "[green][CLEAN][/green]"

                display_path = repr(val_name) if blank else val_name

                entries.append({
                    "sid": sid_name,
                    "path": display_path,
                    "last_run": last_run,
                    "status": status_text,
                    "trust": None,
                    "verdict": verdict,
                    "raw_path": val_name,
                    "deleted": deleted,
                    "suspect": suspect,
                    "ghost": ghost,
                    "filetime_raw": ft_raw,
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
            border_style="red",
            expand=False
        ))
        pause_exit()
        sys.exit(1)

    ascii_art = (
        "██████╗  █████╗ ███╗   ███╗    ██████╗ ███████╗██╗   ██╗███████╗ █████╗ ██╗     ███████╗██████╗ \n"
        "██╔══██╗██╔══██╗████╗ ████║    ██╔══██╗██╔════╝██║   ██║██╔════╝██╔══██╗██║     ██╔════╝██╔══██╗\n"
        "██████╔╝███████║██╔████╔██║    ██████╔╝█████╗  ██║   ██║█████╗  ███████║██║     █████╗  ██████╔╝\n"
        "██╔══██╗██╔══██║██║╚██╔╝██║    ██╔══██╗██╔══╝  ╚██╗ ██╔╝██╔══╝  ██╔══██║██║     ██╔══╝  ██╔══██╗\n"
        "██████╔╝██║  ██║██║ ╚═╝ ██║    ██║  ██║███████╗ ╚████╔╝ ███████╗██║  ██║███████╗███████╗██║  ██║\n"
        "╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝    ╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝"
    )

    console.print(Panel(
        f"[bold cyan]{ascii_art}[/bold cyan]\n"
        "[dim cyan]          [ SS-EDITION ]  —  Background Activity Monitor Scanner[/dim cyan]",
        border_style="bright_blue",
        expand=True
    ))

    entries = []
    with Status("[bold cyan]Сканирование реестра BAM...[/bold cyan]", console=console, spinner="dots"):
        entries = scan_bam()

    if not entries:
        console.print("[yellow]Записи BAM не найдены.[/yellow]")
        pause_exit()
        return

    entries.sort(key=filetime_sort_key, reverse=True)

    with Status("[bold cyan]Проверка цифровых подписей...[/bold cyan]", console=console, spinner="bouncingBar"):
        for e in entries:
            if e["trust"] is None:
                if e["deleted"] or not e["raw_path"]:
                    e["trust"] = "[dim]N/A[/dim]"
                else:
                    e["trust"] = check_signature(e["raw_path"])

    table = Table(
        title="[bold cyan]BAM Registry Scan Results[/bold cyan]",
        border_style="bright_blue",
        header_style="bold bright_cyan",
        show_lines=True,
        expand=True
    )

    table.add_column("#",               style="dim", width=4, justify="right")
    table.add_column("Executable Path", style="bold white", min_width=40, overflow="fold")
    table.add_column("SID",             style="dim cyan", width=20, overflow="fold")
    table.add_column("Last Run (UTC)",  style="bright_white", width=17, justify="center")
    table.add_column("Status",          width=10, justify="center")
    table.add_column("Trust",           width=10, justify="center")
    table.add_column("Verdict",         width=22, justify="center")

    for i, e in enumerate(entries, start=1):
        table.add_row(
            str(i),
            e["path"],
            e["sid"],
            e["last_run"],
            e["status"],
            e["trust"] or "—",
            e["verdict"],
        )

    console.print(table)

    total   = len(entries)
    suspects = sum(1 for e in entries if e.get("suspect"))
    traces  = sum(1 for e in entries if e.get("suspect") and e.get("deleted"))
    ghosts  = sum(1 for e in entries if e.get("ghost"))
    blanks  = sum(1 for e in entries if "BLANK PATH" in e["verdict"])
    denied  = sum(1 for e in entries if "HIDDEN" in e["verdict"])

    summary = (
        f"[white]Всего:[/white] [cyan]{total}[/cyan]   "
        f"[white]Подозрительных:[/white] [red]{suspects}[/red]   "
        f"[white]Следов:[/white] [bold red]{traces}[/bold red]   "
        f"[white]Ghost-устройств:[/white] [bold magenta]{ghosts}[/bold magenta]   "
        f"[white]Blank-путей:[/white] [bold red]{blanks}[/bold red]   "
        f"[white]Скрытых ключей:[/white] [bold red]{denied}[/bold red]"
    )

    console.print(Panel(summary, title="[bold cyan]Итог[/bold cyan]", border_style="bright_blue"))

    pause_exit()


if __name__ == "__main__":
    main()
