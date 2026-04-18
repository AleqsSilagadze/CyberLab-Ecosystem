#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║     GeoForum CyberLab — Blue Team SOC Monitor  v3.0                 ║
║     გაუშვი ცალკე ტერმინალში სანამ network.py-ს დაიწყებ:            ║
║         python server.py                                             ║
╚══════════════════════════════════════════════════════════════════════╝

ეს სერვერი:
  • UDP :9999 — network.py-ისგან იღებს forensic event-ებს real-time
  • აჩვენებს SOC dashboard-ს: alert feed, event stats, attack timeline
  • ინახავს სრულ audit log-ს  →  soc_audit.log
  • Analyst-ს აძლევს ბრძანებებს: status, alerts, timeline, export, clear
"""

import json
import socket
import threading
import time
import os
from datetime import datetime
from collections import Counter, deque
from rich.console    import Console
from rich.table      import Table
from rich.panel      import Panel
from rich.progress   import Progress, BarColumn, TextColumn, TaskProgressColumn
from rich.prompt     import Prompt
from rich.rule       import Rule
from rich            import box
from rich.layout     import Layout
from rich.live       import Live
from rich.text       import Text

# ══════════════════════════════════════════════════════════════════════
SOC_HOST   = "0.0.0.0"
SOC_PORT   = 9999
LOG_FILE   = "soc_audit.log"
MAX_EVENTS = 500     # ring buffer size
console    = Console()

# ══════════════════════════════════════════════════════════════════════
#  SEVERITY CONFIG
# ══════════════════════════════════════════════════════════════════════
SEV_COLOR = {
    "INFO": "bright_black",
    "WARN": "yellow",
    "HIGH": "bold red",
    "CRIT": "bold red reverse",
}

SEV_ICON = {
    "INFO": "ℹ",
    "WARN": "⚠",
    "HIGH": "🔴",
    "CRIT": "🚨",
}

EVENT_DESCRIPTIONS = {
    "SESSION_START":    ("Red Team session initialised",           "WARN"),
    "OSINT_SHODAN":     ("Passive OSINT — Shodan query",           "INFO"),
    "PORT_SCAN":        ("Active port scan detected",              "WARN"),
    "HONEYPOT_HIT":     ("⚠  HONEYPOT triggered — attacker burned","CRIT"),
    "EXPLOIT_SUCCESS":  ("Exploit landed — host compromised",      "HIGH"),
    "EXPLOIT_FAIL":     ("Exploit attempt failed (wrong module)",  "WARN"),
    "PIVOT_ROUTE":      ("Pivot route established (autoroute)",    "HIGH"),
    "SHELL_SPAWNED":    ("Interactive shell spawned on target",    "HIGH"),
    "CREDENTIAL_DUMP":  ("Credential dump (hashdump/SAM)",         "HIGH"),
    "FILE_READ":        ("Sensitive file accessed",                "HIGH"),
    "OBJECTIVE_DONE":   ("Attack objective completed",             "HIGH"),
    "ICS_DATA_EXFIL":   ("🚨 ICS/SCADA data exfiltration!",        "CRIT"),
    "FLAG_CAPTURED":    ("🏁 FLAG captured — full compromise!",     "CRIT"),
    "HUNTER_TRIGGERED": ("Hunter/IDS threshold breached",          "CRIT"),
}

# ══════════════════════════════════════════════════════════════════════
#  SOC STATE
# ══════════════════════════════════════════════════════════════════════
class SOCState:
    def __init__(self):
        self.events:      deque = deque(maxlen=MAX_EVENTS)
        self.lock                = threading.Lock()
        self.session_start       = None
        self.alert_score         = 0
        self.type_counts: Counter = Counter()
        self.sev_counts:  Counter = Counter()
        self.compromised_hosts   = []
        self.pivot_routes        = []
        self.objectives_done     = []
        self.flag_captured       = False
        self.last_event_time     = None

state = SOCState()

# ══════════════════════════════════════════════════════════════════════
#  AUDIT LOG WRITER
# ══════════════════════════════════════════════════════════════════════
def write_audit(event: dict):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")

# ══════════════════════════════════════════════════════════════════════
#  ALERT SCORE — each event type has a weight
# ══════════════════════════════════════════════════════════════════════
ALERT_WEIGHTS = {
    "SESSION_START":   2,
    "OSINT_SHODAN":    1,
    "PORT_SCAN":       5,
    "HONEYPOT_HIT":   50,
    "EXPLOIT_SUCCESS": 20,
    "EXPLOIT_FAIL":    8,
    "PIVOT_ROUTE":    15,
    "SHELL_SPAWNED":  15,
    "CREDENTIAL_DUMP": 20,
    "FILE_READ":       10,
    "OBJECTIVE_DONE":  10,
    "ICS_DATA_EXFIL":  30,
    "FLAG_CAPTURED":   50,
    "HUNTER_TRIGGERED": 0,
}

# ══════════════════════════════════════════════════════════════════════
#  UDP LISTENER THREAD
# ══════════════════════════════════════════════════════════════════════
def udp_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((SOC_HOST, SOC_PORT))
    except OSError as e:
        console.print(f"[red][SOC] Cannot bind UDP :{SOC_PORT} — {e}[/red]")
        return

    console.print(f"[green][SOC] UDP listener active on :{SOC_PORT}[/green]")

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            event = json.loads(data.decode("utf-8"))
            event["received_at"] = datetime.now().strftime("%H:%M:%S")

            with state.lock:
                state.events.appendleft(event)
                state.last_event_time = datetime.now()
                state.type_counts[event.get("type","?")] += 1
                sev = event.get("severity", "INFO")
                state.sev_counts[sev] += 1
                state.alert_score += ALERT_WEIGHTS.get(event.get("type",""), 3)
                state.alert_score  = min(state.alert_score, 100)

                etype = event.get("type","")
                if etype == "SESSION_START" and not state.session_start:
                    state.session_start = event.get("ts")
                if etype == "EXPLOIT_SUCCESS":
                    detail = event.get("detail","")
                    if detail and detail not in state.compromised_hosts:
                        state.compromised_hosts.append(detail)
                if etype == "PIVOT_ROUTE":
                    detail = event.get("detail","")
                    if detail and detail not in state.pivot_routes:
                        state.pivot_routes.append(detail)
                if etype == "OBJECTIVE_DONE":
                    state.objectives_done.append(event.get("detail",""))
                if etype == "FLAG_CAPTURED":
                    state.flag_captured = True

            write_audit(event)

        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════
#  RENDER HELPERS
# ══════════════════════════════════════════════════════════════════════
def _alert_bar(score: int) -> str:
    pct    = min(score, 100)
    filled = int(pct / 5)
    bar    = "█" * filled + "░" * (20 - filled)
    color  = "green" if pct < 30 else ("yellow" if pct < 60 else "bold red")
    return f"[{color}]THREAT [{bar}] {pct}%[/{color}]"


def render_status() -> Panel:
    with state.lock:
        score    = state.alert_score
        n_events = len(state.events)
        n_comp   = len(state.compromised_hosts)
        n_pivot  = len(state.pivot_routes)
        n_obj    = len(state.objectives_done)
        flag_str = "[bold red]⚑ FLAG CAPTURED[/bold red]" if state.flag_captured else "[green]secure[/green]"
        last_t   = state.last_event_time.strftime("%H:%M:%S") if state.last_event_time else "—"
        sess     = state.session_start or "—"

    lines = (
        f"  {_alert_bar(score)}\n\n"
        f"  [white]Session start     :[/white]  [cyan]{sess}[/cyan]\n"
        f"  [white]Last event        :[/white]  [cyan]{last_t}[/cyan]\n"
        f"  [white]Total events      :[/white]  {n_events}\n"
        f"  [white]Compromised hosts :[/white]  [bold red]{n_comp}[/bold red]\n"
        f"  [white]Pivot routes      :[/white]  [bold red]{n_pivot}[/bold red]\n"
        f"  [white]Objectives done   :[/white]  [bold red]{n_obj}[/bold red]\n"
        f"  [white]Flag              :[/white]  {flag_str}\n"
    )
    return Panel(lines, title="[ SOC STATUS ]", border_style="cyan")


def render_feed(n: int = 20) -> Panel:
    with state.lock:
        recent = list(state.events)[:n]

    t = Table(box=box.SIMPLE, show_header=True, header_style="bold white",
              expand=True, padding=(0,1))
    t.add_column("Time",     style="bright_black", width=10, no_wrap=True)
    t.add_column("Sev",      width=6,  no_wrap=True)
    t.add_column("Event",    style="cyan", width=22, no_wrap=True)
    t.add_column("Detail")

    for e in recent:
        sev   = e.get("severity", "INFO")
        sc    = SEV_COLOR.get(sev, "white")
        icon  = SEV_ICON.get(sev, "")
        sev_s = f"[{sc}]{icon}[/{sc}]"
        t.add_row(
            e.get("ts", "?"),
            sev_s,
            e.get("type","?"),
            e.get("detail",""),
        )

    return Panel(t, title="[ LIVE EVENT FEED ]", border_style="yellow")


def render_stats() -> Panel:
    with state.lock:
        tc = dict(state.type_counts.most_common(8))
        sc = dict(state.sev_counts)

    lines = "[bold cyan]Event Types (top 8):[/bold cyan]\n"
    for etype, cnt in tc.items():
        bar = "▓" * min(cnt * 2, 30)
        desc, _ = EVENT_DESCRIPTIONS.get(etype, (etype, "INFO"))
        lines += f"  {bar:<30} {cnt:>3}  [bright_black]{etype}[/bright_black]\n"

    lines += "\n[bold cyan]Severity Breakdown:[/bold cyan]\n"
    for sev in ("CRIT", "HIGH", "WARN", "INFO"):
        cnt   = sc.get(sev, 0)
        sc_   = SEV_COLOR.get(sev, "white")
        bar   = "▓" * min(cnt, 30)
        lines += f"  [{sc_}]{sev:4}[/{sc_}]  {bar:<30}  {cnt}\n"

    return Panel(lines, title="[ STATISTICS ]", border_style="magenta")


def render_timeline() -> Panel:
    with state.lock:
        all_events = list(reversed(list(state.events)))   # oldest first
        comp  = state.compromised_hosts[:]
        pivot = state.pivot_routes[:]
        obj   = state.objectives_done[:]

    milestones = [
        e for e in all_events
        if e.get("type","") in (
            "SESSION_START","EXPLOIT_SUCCESS","PIVOT_ROUTE",
            "CREDENTIAL_DUMP","ICS_DATA_EXFIL","FLAG_CAPTURED",
            "HONEYPOT_HIT","OBJECTIVE_DONE",
        )
    ]

    lines = ""
    for i, e in enumerate(milestones):
        etype  = e.get("type","?")
        _, sev = EVENT_DESCRIPTIONS.get(etype, (etype, "INFO"))
        sc     = SEV_COLOR.get(sev, "white")
        icon   = SEV_ICON.get(sev, "●")
        conn   = "│" if i < len(milestones)-1 else " "
        lines += f"  [{sc}]{icon}[/{sc}] [bright_black]{e.get('ts','?')}[/bright_black]  [{sc}]{etype}[/{sc}]\n"
        lines += f"  {conn}    [bright_black]{e.get('detail','')}[/bright_black]\n"

    if not lines:
        lines = "  [bright_black](waiting for events from network.py...)[/bright_black]\n"

    # Attack path summary
    lines += "\n[bold white]Compromised hosts:[/bold white]\n"
    if comp:
        for c in comp:
            lines += f"  [bold red]✗[/bold red]  {c}\n"
    else:
        lines += "  [green](none yet)[/green]\n"

    lines += "\n[bold white]Pivot routes:[/bold white]\n"
    if pivot:
        for p in pivot:
            lines += f"  [bold red]→[/bold red]  {p}\n"
    else:
        lines += "  [green](none yet)[/green]\n"

    return Panel(lines, title="[ ATTACK TIMELINE ]", border_style="red")


def render_forensic() -> Panel:
    """Show what the Blue Team can see and how to contain each finding."""
    with state.lock:
        types_seen = set(state.type_counts.keys())

    findings = []

    if "PORT_SCAN" in types_seen:
        findings.append((
            "Port Scan Detected",
            "nmap probes visible in firewall logs",
            "Block source IP at perimeter firewall; enable IPS signature for Nmap TCP SYN scan",
        ))
    if "EXPLOIT_SUCCESS" in types_seen:
        findings.append((
            "Host Compromised",
            "Meterpreter reverse shell — outbound TCP :4444",
            "Isolate host; capture RAM; check for persistence (crontab/registry RunKey); rotate credentials",
        ))
    if "PIVOT_ROUTE" in types_seen:
        findings.append((
            "Lateral Movement / Pivot",
            "Attacker added autoroute — internal segment reachable",
            "Check firewall rules between zones; disable unnecessary inter-zone routing; monitor for new connections",
        ))
    if "CREDENTIAL_DUMP" in types_seen:
        findings.append((
            "Credential Theft",
            "hashdump / NTLM hashes extracted from SAM",
            "Reset all domain passwords immediately; enable Protected Users SG; deploy Credential Guard",
        ))
    if "ICS_DATA_EXFIL" in types_seen:
        findings.append((
            "ICS Data Exfiltration",
            "Physical control codes accessed on SCADA HMI",
            "IMMEDIATE: isolate OT network; notify SCADA vendor; rotate emergency codes; review ICS-CERT AA20-205A",
        ))
    if "FLAG_CAPTURED" in types_seen:
        findings.append((
            "FULL CHAIN COMPROMISE",
            "DMZ → CORP → OT — root.txt read",
            "Declare critical incident; activate IR plan; preserve forensic images of all compromised hosts",
        ))

    if not findings:
        return Panel(
            "[bright_black]  (no actionable findings yet — waiting for events)[/bright_black]",
            title="[ FORENSIC FINDINGS & REMEDIATION ]", border_style="green",
        )

    t = Table(box=box.SIMPLE, header_style="bold red", expand=True)
    t.add_column("Finding",      style="bold red",   width=22)
    t.add_column("Evidence",     style="yellow",     width=30)
    t.add_column("Remediation",  style="green")

    for finding, evidence, remedy in findings:
        t.add_row(finding, evidence, remedy)

    return Panel(t, title="[ FORENSIC FINDINGS & REMEDIATION ]", border_style="green")


# ══════════════════════════════════════════════════════════════════════
#  COMMANDS (analyst CLI)
# ══════════════════════════════════════════════════════════════════════
def cmd_status():
    console.print(render_status())

def cmd_feed(n=30):
    console.print(render_feed(n))

def cmd_stats():
    console.print(render_stats())

def cmd_timeline():
    console.print(render_timeline())

def cmd_forensic():
    console.print(render_forensic())

def cmd_export():
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    out  = f"soc_report_{ts}.json"
    with state.lock:
        data = {
            "generated":          datetime.now().isoformat(),
            "alert_score":        state.alert_score,
            "session_start":      state.session_start,
            "flag_captured":      state.flag_captured,
            "compromised_hosts":  state.compromised_hosts,
            "pivot_routes":       state.pivot_routes,
            "objectives_done":    state.objectives_done,
            "type_counts":        dict(state.type_counts),
            "sev_counts":         dict(state.sev_counts),
            "events":             list(state.events),
        }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    console.print(f"[bold green][SOC] Report exported: [cyan]{out}[/cyan][/bold green]")

def cmd_clear():
    with state.lock:
        state.events.clear()
        state.type_counts.clear()
        state.sev_counts.clear()
        state.alert_score        = 0
        state.compromised_hosts  = []
        state.pivot_routes       = []
        state.objectives_done    = []
        state.flag_captured      = False
        state.session_start      = None
    console.print("[yellow][SOC] State cleared.[/yellow]")

def cmd_help():
    console.print(Panel(
        "[bold cyan]SOC ANALYST COMMANDS:[/bold cyan]\n\n"
        "  status      — Dashboard: alert score, session info, compromises\n"
        "  feed [n]    — Live event feed (default last 30)\n"
        "  stats       — Event type & severity breakdown\n"
        "  timeline    — Attack chain milestone timeline\n"
        "  forensic    — Findings + remediation recommendations\n"
        "  watch       — Auto-refresh dashboard every 3s (Ctrl+C to stop)\n"
        "  export      — Export full report to JSON\n"
        "  clear       — Reset all state (new session)\n"
        "  help        — This menu\n"
        "  exit        — Shutdown SOC server\n\n"
        "[bright_black]Audit log: soc_audit.log  |  UDP port: 9999[/bright_black]",
        title="[ SOC HELP ]", border_style="cyan",
    ))


def cmd_watch():
    """Auto-refresh dashboard every 3 seconds until Ctrl+C."""
    console.print("[bright_black](Ctrl+C to stop watch mode)[/bright_black]")
    try:
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            _banner()
            console.print(render_status())
            console.print(render_feed(15))
            console.print(render_forensic())
            time.sleep(3)
    except KeyboardInterrupt:
        console.print("\n[yellow]Watch stopped.[/yellow]")


# ══════════════════════════════════════════════════════════════════════
#  BANNER
# ══════════════════════════════════════════════════════════════════════
def _banner():
    art = (
        " ███████╗ ██████╗  ██████╗    ███╗   ███╗ ██████╗ ███╗  ██╗██╗████████╗\n"
        " ██╔════╝██╔═══██╗██╔════╝    ████╗ ████║██╔═══██╗████╗ ██║██║╚══██╔══╝\n"
        " ███████╗██║   ██║██║         ██╔████╔██║██║   ██║██╔██╗██║██║   ██║   \n"
        " ╚════██║██║   ██║██║         ██║╚██╔╝██║██║   ██║██║╚████║██║   ██║   \n"
        " ███████║╚██████╔╝╚██████╗    ██║ ╚═╝ ██║╚██████╔╝██║ ╚███║██║   ██║   \n"
        " ╚══════╝ ╚═════╝  ╚═════╝    ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚══╝╚═╝   ╚═╝  "
    )
    console.print(art, style="bold blue")
    console.print(
        f"  [ GeoForum CyberLab — Blue Team SOC  "
        f"| UDP :{SOC_PORT}  "
        f"| Log: {LOG_FILE}  "
        f"| {datetime.now().strftime('%Y-%m-%d %H:%M')} ]\n",
        style="bright_black",
    )
    console.print(
        "  [bright_black]Commands: status · feed · stats · timeline · forensic · "
        "watch · export · clear · help · exit[/bright_black]\n"
    )


# ══════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════
def main():
    # Start UDP listener in background
    t = threading.Thread(target=udp_listener, daemon=True)
    t.start()
    time.sleep(0.3)

    os.system('cls' if os.name == 'nt' else 'clear')
    _banner()
    console.print(Panel(
        "[white]Blue Team SOC სერვერი გაშვებულია.[/white]\n\n"
        "  1. ამ ტერმინალში რჩები — analyst interface\n"
        "  2. ახალ ტერმინალში გაუშვი: [bold cyan]python network.py[/bold cyan]  (Red Team)\n"
        "  3. ყოველი Red Team ნაბიჯი [bold yellow]real-time[/bold yellow]-ში ჩანს აქ\n\n"
        "  [bold]watch[/bold] — ავტო-განახლება  |  [bold]forensic[/bold] — შემოთავაზებები",
        title="[ SOC STARTUP ]", border_style="blue",
    ))

    CMDS = {
        "status":   cmd_status,
        "feed":     cmd_feed,
        "stats":    cmd_stats,
        "timeline": cmd_timeline,
        "forensic": cmd_forensic,
        "watch":    cmd_watch,
        "export":   cmd_export,
        "clear":    cmd_clear,
        "help":     cmd_help,
    }

    while True:
        try:
            raw = console.input(
                "[bold blue]┌──(soc-analyst㉿defender)-[~/soc][/bold blue]\n└─$ "
            ).strip()
            if not raw:
                continue

            parts = raw.split()
            cmd   = parts[0].lower()

            if cmd == "exit":
                console.print("[bold blue][SOC] Shutting down. Audit log saved to: "
                               f"[cyan]{LOG_FILE}[/cyan][/bold blue]")
                break
            elif cmd == "feed" and len(parts) > 1:
                try:
                    cmd_feed(int(parts[1]))
                except ValueError:
                    cmd_feed()
            elif cmd in CMDS:
                CMDS[cmd]()
            elif cmd == "help":
                cmd_help()
            else:
                console.print(f"[bright_black]-bash: {cmd}: command not found. type 'help'[/bright_black]")

        except KeyboardInterrupt:
            console.print("\n[yellow]Ctrl+C — type 'exit' to shutdown.[/yellow]")
        except Exception as e:
            import traceback
            console.print(f"[red][SOC Error] {e}[/red]")
            console.print(f"[bright_black]{traceback.format_exc()}[/bright_black]")


if __name__ == "__main__":
    main()