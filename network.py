BANNER_COLOR   = "bold green"
PROMPT_COLOR   = "bold green"
MSF_COLOR      = "bold red"
METERP_COLOR   = "bold underline red"
ZONE_DMZ_COLOR = "cyan"
ZONE_CORP_COLOR= "yellow"
ZONE_OT_COLOR  = "bold red"

import os, sys, time, json, random, socket, threading
from datetime import datetime
from rich.console  import Console
from rich.table    import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TaskProgressColumn
from rich.panel    import Panel
from rich.prompt   import Prompt
from rich.text     import Text
from rich          import box
from rich.rule     import Rule

console = Console()

SOC_HOST = "127.0.0.1"
SOC_PORT = 9999

def soc_event(event_type: str, detail: str, severity: str = "INFO"):
    """Send a forensic event to the Blue Team SOC server (non-blocking)."""
    try:
        payload = json.dumps({
            "ts":       datetime.now().strftime("%H:%M:%S"),
            "type":     event_type,
            "detail":   detail,
            "severity": severity,
        }).encode()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(payload, (SOC_HOST, SOC_PORT))
        sock.close()
    except Exception:
        pass

NMAP_FLAG_WEIGHTS = {
    "-sS":   {"noise": (2, 5),   "label": "SYN Stealth",       "opsec": "half-open scan — IDS ნაკლებად ხედავს"},
    "-sT":   {"noise": (6, 10),  "label": "TCP Connect",        "opsec": "სრული handshake — ლოგებში ჩნდება"},
    "-sU":   {"noise": (8, 14),  "label": "UDP Scan",           "opsec": "ნელი, ხმაურიანი — firewall ლოგი"},
    "-sV":   {"noise": (4, 8),   "label": "Version Detection",  "opsec": "banner grab — დამატებითი request-ები"},
    "-sN":   {"noise": (1, 3),   "label": "NULL Scan",          "opsec": "ძალიან stealth — ფარავს firewalled ports-ს"},
    "-sF":   {"noise": (1, 3),   "label": "FIN Scan",           "opsec": "stealth — Windows-ზე არ მუშაობს"},
    "-sX":   {"noise": (1, 3),   "label": "Xmas Scan",          "opsec": "stealth — Windows-ზე არ მუშაობს"},
    "-A":    {"noise": (15, 25), "label": "Aggressive",         "opsec": "-sV -O --script=default — ძალიან ხმაურიანი!"},
    "-O":    {"noise": (5, 8),   "label": "OS Detection",       "opsec": "TTL + TCP fingerprint probes"},
    "-p-":   {"noise": (8, 15),  "label": "All 65535 Ports",    "opsec": "firewall ლოგებში გარკვევით ჩანს"},
    "-T1":   {"noise": (-3, -3), "label": "Timing: Paranoid",   "opsec": "ძალიან ნელი — IDS rate-limit ვერ ჭრის"},
    "-T2":   {"noise": (-2, -2), "label": "Timing: Sneaky",     "opsec": "ნელი — IDS ნაკლებად ხედავს"},
    "-T3":   {"noise": (0, 0),   "label": "Timing: Normal",     "opsec": "სტანდარტული"},
    "-T4":   {"noise": (5, 8),   "label": "Timing: Aggressive", "opsec": "სწრაფი — IDS rate ატყდება"},
    "-T5":   {"noise": (10, 15), "label": "Timing: Insane",     "opsec": "ძალიან სწრაფი — instant IDS trigger"},
    "-n":    {"noise": (-2, -2), "label": "No DNS",             "opsec": "DNS lookup-ი IDS-ს „ბოძებს\" — გამოიყენე!"},
    "-Pn":   {"noise": (0, 0),   "label": "No Ping",            "opsec": "OPSEC+ — ping skip, ნაკლები ხმაური"},
    "--script": {"noise": (10, 20), "label": "NSE Scripts",     "opsec": "vuln scripts = exploit-მსგავსი ტრაფიკი"},
}

NSE_SCRIPT_OUTPUTS = {
    "smb-vuln-ms17-010": {
        "hosts": ["10.10.10.5"],
        "output": (
            "[bold red]  smb-vuln-ms17-010:[/bold red]\n"
            "[bold red]    VULNERABLE[/bold red]\n"
            "    State: VULNERABLE\n"
            "    IDs: CVE:CVE-2017-0144\n"
            "    Risk factor: HIGH\n"
            "    Description: Remote Code Execution vulnerability in SMBv1\n"
            "[bright_black]    → use exploit/windows/smb/ms17_010_eternalblue[/bright_black]"
        ),
    },
    "ldap-rootdse": {
        "hosts": ["10.10.10.5"],
        "output": (
            "[bold cyan]  ldap-rootdse:[/bold cyan]\n"
            "    namingContexts: DC=AMNESIA,DC=LOCAL\n"
            "    ldapServiceName: AMNESIA.LOCAL:corp-dc$@AMNESIA.LOCAL\n"
            "    dnsHostName: corp-dc.AMNESIA.LOCAL\n"
            "    domainFunctionality: 4 (Windows Server 2008 R2)\n"
            "[bright_black]    → domain confirmed: AMNESIA.LOCAL | DC: corp-dc[/bright_black]"
        ),
    },
    "http-title": {
        "hosts": ["192.168.10.5", "10.10.10.30", "172.16.5.10"],
        "output": (
            "[cyan]  http-title: Site title found[/cyan]\n"
            "[bright_black]    → check banner for application version[/bright_black]"
        ),
    },
    "modbus-discover": {
        "hosts": ["172.16.5.10", "172.16.5.20"],
        "output": (
            "[bold red]  modbus-discover:[/bold red]\n"
            "    Modbus TCP port 502 OPEN — no authentication required\n"
            "    Unit ID: 1  |  Device: Siemens S7 PLC\n"
            "[bold red]    ICS-CERT: CWE-306 — Missing Authentication for Critical Function[/bold red]\n"
            "[bright_black]    → modbus read_coils <ip> 0 10[/bright_black]"
        ),
    },
    "smb-enum-shares": {
        "hosts": ["10.10.10.15"],
        "output": (
            "[bold cyan]  smb-enum-shares:[/bold cyan]\n"
            "    \\\\corp-file\\IT_Tools   — READ ONLY\n"
            "    \\\\corp-file\\Finance    — READ, WRITE (!! no ACL !!) \n"
            "    \\\\corp-file\\HR_Confidential — READ (Domain Users)\n"
            "[bright_black]    → smbclient \\\\10.10.10.15\\Finance[/bright_black]"
        ),
    },
    "http-shellshock": {
        "hosts": ["192.168.10.5"],
        "output": (
            "[bright_black]  http-shellshock: not vulnerable (Ubuntu 20.04 — patched)[/bright_black]"
        ),
    },
    "vuln": {
        "hosts": ["192.168.10.5", "10.10.10.5"],
        "output": (
            "[bold red]  vulners:[/bold red]\n"
            "    CVE-2020-1938  9.8  Apache Tomcat AJP (Ghostcat)\n"
            "    CVE-2021-41773 7.5  Apache path traversal\n"
            "[bold yellow]  smb-vuln-ms17-010 (see above)[/bold yellow]\n"
            "[bright_black]    → combine with: nmap --script=smb-vuln-ms17-010[/bright_black]"
        ),
    },
}

HINTS = [
    "[ 1 ] shodan geoforum.ge → IP-ის პოვნა, შემდეგ nmap -sS 82.148.10.55",
    "[ 2 ] Tomcat/8080 → msfconsole → use exploit/multi/http/tomcat_mgr_upload → set HttpUsername tomcat → set HttpPassword tomcat → set RHOSTS 82.148.10.55 → run",
    "[ 3 ] meterpreter > shell → cat /etc/hosts  (CORP subnet ჩანს: 10.10.10.5)",
    "[ 4 ] autoroute -s 10.10.10.0/24 → background → MSF: use auxiliary/server/socks_proxy → set SRVPORT 1080 → run",
    "[ 5 ] proxychains nmap -sT 10.10.10.5  (SOCKS proxy-ს გავლით CORP სკანი)",
    "[ 6 ] ldap_hashdump: set USERNAME j.smith → set PASSWORD P@ssw0rd2026! → run",
    "[ 7 ] sessions -i 2 → kerberoast → hashcat -m 13100 spn_hashes.txt rockyou.txt  (TGS-REP!)",
    "[ 8 ] mimikatz lsadump::dcsync /domain:AMNESIA.LOCAL /user:svc_backup  → Backup@123  (+25% alert — ბოლოს!)",
    "[ 9 ] run autoroute -s 172.16.5.0/24 → db_nmap -p 80,102,502 172.16.5.10  (OT zone)",
    "[10 ] use exploit/windows/scada/step7_exec → set RHOSTS 172.16.5.10 → run",
    "[11 ] shell → modbus read_coils 172.16.5.20 0 10  (Modbus no_auth) → type root.txt",
    "[12 ] persistence → schtasks /create ... → WMI subscription (Hunter-ის გვერდის ავლა)",
    "[13 ] type root.txt  🏁",
]

FS = {
    "DMZ": {
        "/":                      ["var", "etc", "tmp", "home", "opt"],
        "/var":                   ["www", "log", "lib", "backups"],
        "/var/www":               ["html"],
        "/var/www/html":          ["index.html", "config.php.bak", ".env",
                                   "wp-config.php.old", "upload.php", ".git"],
        "/var/backups":           ["db_dump_2026-01.sql.gz", "config.tar.gz"],
        "/etc":                   ["passwd", "shadow", "hosts", "crontab",
                                   "ssh", "mysql", "sudoers"],
        "/tmp":                   ["sess_abc123", "f.sh", ".nix_pivot"],
        "/opt":                   ["tomcat9", "scripts"],
    },
    "CORP": {
        "C:\\":                         ["Users", "Windows", "Program Files", "inetpub", "Shares"],
        "C:\\Users":                    ["Administrator", "svc_backup", "j.smith", "svc_scada"],
        "C:\\Users\\Administrator":     ["Desktop", "Documents", "AppData"],
        "C:\\Users\\Administrator\\Desktop":
                                        ["root.txt", "AD_Passwords.txt",
                                         "network_diagram.png", "backup_keys.kdbx"],
        "C:\\Users\\Administrator\\Documents":
                                        ["sensitive_data.docx", "budget_2026.xlsx",
                                         "incident_response_plan.docx"],
        "C:\\Users\\svc_backup":        ["Desktop"],
        "C:\\Users\\svc_backup\\Desktop": ["ntds.dit.bak", "SYSTEM.hive"],
        "C:\\Shares":                   ["IT_Tools", "Finance", "HR_Confidential"],
        "C:\\inetpub\\wwwroot":         ["web.config", "login.aspx"],
    },
    "OT": {
        "C:\\":                             ["Siemens", "WinCC", "Users", "Windows", "Logs"],
        "C:\\WinCC":                        ["Config", "Data", "Logs", "Archive"],
        "C:\\WinCC\\Config":               ["SCADA_Config.xml", "PLC_Logic.bin",
                                            "hmi_settings.ini", "alarm_thresholds.csv"],
        "C:\\WinCC\\Logs":                 ["runtime.log", "alarm_2026.log"],
        "C:\\Siemens":                     ["STEP7", "S7ProSim", "NetPro"],
        "C:\\Logs":                        ["security_events.log", "vpn_access.log"],
        "C:\\Users\\Administrator\\Desktop": ["root.txt", "SCADA_backup.zip",
                                              "maintenance_log.txt", "emergency_codes.txt"],
    },
}

FILE_CONTENT = {
    "config.php.bak": (
        "[bold green]<?php[/bold green]\n"
        "[bright_black]// Database Configuration — DO NOT COMMIT![/bright_black]\n"
        "define('DB_HOST',    '[bold yellow]192.168.10.10[/bold yellow]');  [bright_black]// Internal DB IP[/bright_black]\n"
        "define('DB_USER',    '[bold yellow]admin[/bold yellow]');\n"
        "define('DB_PASS',    '[bold red]Sup3rS3cr3t![/bold red]');  [bright_black]// ← PLAIN TEXT CREDENTIALS![/bright_black]\n"
        "define('DB_NAME',    'geoforum_prod');\n"
        "define('ADMIN_HASH', '$2y$10$Xvf3mK9pQ2nL...');  [bright_black]// bcrypt[/bright_black]\n"
        "[bold green]?>[/bold green]\n\n"
        "[bright_black]// SECURITY FINDING: CWE-256 — Plaintext credential storage[/bright_black]"
    ),
    ".env": (
        "APP_ENV=production\n"
        "APP_KEY=base64:kJ9mP2xQ8rT...\n"
        "[bold red]DB_HOST=192.168.10.10[/bold red]\n"
        "[bold red]DB_PASSWORD=Sup3rS3cr3t![/bold red]\n"
        "MAIL_HOST=smtp.geoforum.ge\n"
        "[bold red]AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE[/bold red]\n"
        "[bold red]AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY[/bold red]\n\n"
        "[bright_black]// SECURITY FINDING: Secrets in .env — should use vault/secrets manager[/bright_black]"
    ),
    "passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "mysql:x:108:113:MySQL Server:/nonexistent:/bin/false\n"
        "svc_web:x:1001:1001:Web Service:/home/svc_web:/bin/bash\n"
        "deploy:x:1002:1002:Deploy Bot:/home/deploy:/bin/sh"
    ),
    "shadow": (
        "[bold red]Permission denied: requires root[/bold red]\n"
        "[bright_black]  → hashdump Meterpreter-ში, ან: sudo cat /etc/shadow[/bright_black]"
    ),
    "hosts": (
        "127.0.0.1       localhost\n"
        "[bold yellow]192.168.10.10   db-server db[/bold yellow]\n"
        "[bold yellow]192.168.10.20   dev-server dev[/bold yellow]\n"
        "[bold yellow]10.10.10.5      corp-dc AD AMNESIA[/bold yellow]   [bright_black]← შიდა CORP ქსელი![/bright_black]\n"
        "[bold yellow]10.10.10.15     corp-file[/bold yellow]\n"
        "[bold yellow]10.10.10.30     corp-mail[/bold yellow]\n"
        "[bright_black]# OT segment not visible from DMZ — must pivot via CORP[/bright_black]"
    ),
    "sudoers": (
        "[bright_black]# /etc/sudoers[/bright_black]\n"
        "root    ALL=(ALL:ALL) ALL\n"
        "[bold red]www-data ALL=(ALL) NOPASSWD: /usr/bin/python3[/bold red]   "
        "[bright_black]← Privilege Escalation vector! (GTFOBins)[/bright_black]"
    ),
    "crontab": (
        "[bright_black]# /etc/crontab[/bright_black]\n"
        "*/5 * * * *  root  /opt/scripts/backup.sh\n"
        "[bold red]*/1 * * * *  www-data  /tmp/f.sh[/bold red]   [bright_black]← Suspicious! writable by www-data[/bright_black]\n"
        "[bright_black]  → FINDING: Attacker-controlled cron — persistence vector (CWE-732)[/bright_black]"
    ),
    "AD_Passwords.txt": (
        "[bold red]⚠  CLEARTEXT PASSWORDS — HELPDESK EMERGENCY USE ONLY[/bold red]\n"
        "[bright_black]Created: 2026-01-15  |  Owner: j.smith (Helpdesk)[/bright_black]\n\n"
        "j.smith       :  P@ssw0rd2026!\n"
        "m.jones       :  Welcome1\n"
        "svc_backup    :  Backup$ecure99\n"
        "[bold red]svc_scada     :  Sc4da@Admin![/bold red]   [bright_black]← OT zone access![/bright_black]\n\n"
        "[bright_black]SECURITY FINDING: CWE-312 — Cleartext storage of sensitive information[/bright_black]"
    ),
    "root.txt": (
        "[bold green]╔══════════════════════════════════════════════════════╗[/bold green]\n"
        "[bold green]║   FLAG{SCADA_HMI_COMPROMISED_2026_GeoForumCyberLab} ║[/bold green]\n"
        "[bold green]╚══════════════════════════════════════════════════════╝[/bold green]\n\n"
        "[bright_black]Host: scada-hmi  |  Zone: OT  |  OS: Windows 7 Embedded[/bright_black]\n"
        "[bright_black]Chain: DMZ(RCE) → CORP(EternalBlue/DCSync) → OT(S7comm)[/bright_black]"
    ),
    "SCADA_Config.xml": (
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        "<SCADAConfig version='7.5'>\n"
        "  <Connection>\n"
        "    <PLC ip='[bold yellow]172.16.5.20[/bold yellow]' port='102' protocol='S7-400'/>\n"
        "    <Modbus ip='[bold yellow]172.16.5.20[/bold yellow]' port='502'/>\n"
        "  </Connection>\n"
        "  <Auth enabled='[bold red]false[/bold red]'/>   [bright_black]<!-- !! Authentication disabled !! -->[/bright_black]\n"
        "  <Emergency_Stop enabled='true' unlock_code='[bold red]1234[/bold red]'/>\n"
        "  <Remote_Access rdp='enabled' vnc='[bold red]enabled[/bold red]' vnc_pass='[bold red]scada123[/bold red]'/>\n"
        "</SCADAConfig>\n\n"
        "[bright_black]SECURITY FINDING: ICS-CERT AA20-205A — No authentication on critical ICS[/bright_black]"
    ),
    "maintenance_log.txt": (
        "2026-01-10: PLC firmware update skipped — production halt risk\n"
        "[bold red]2026-01-08: Auth DISABLED for maintenance window (NEVER RE-ENABLED)[/bold red]\n"
        "2025-12-01: OT segment connected to CORP for remote access\n"
        "[bold red]2025-11-20: Windows 7 EOL — no patches since 2020[/bold red]\n"
        "2025-10-05: IDS sensor on OT segment powered off for noise reduction\n\n"
        "[bright_black]FINDING: Multiple unmitigated ICS-CERT advisories outstanding[/bright_black]"
    ),
    "emergency_codes.txt": (
        "[bold red]⚠  RESTRICTED — OT EMERGENCY RESPONSE ONLY[/bold red]\n"
        "Turbine Emergency Shutdown  : [bold red]TURB-9912-HALT[/bold red]\n"
        "Coolant Override            : [bold red]COOL-7743-BYPASS[/bold red]\n"
        "Pressure Relief Manual      : code [bold red]5-5-1-9[/bold red] on HMI panel\n\n"
        "[bright_black]CRITICAL FINDING: Physical process codes stored on internet-accessible host[/bright_black]"
    ),
    "ntds.dit.bak": (
        "[bold red]Binary file: Active Directory database backup[/bold red]\n"
        "[bright_black]Size: 41.2 MB  |  Created: 2026-01-14[/bright_black]\n\n"
        "Extract hashes: [cyan]impacket-secretsdump -ntds ntds.dit.bak -system SYSTEM.hive LOCAL[/cyan]\n"
        "[bright_black]Then crack with: hashcat -m 1000 hashes.txt rockyou.txt[/bright_black]"
    ),
    "runtime.log": (
        "[bright_black]2026-04-07 08:01:12  INFO   WinCC Runtime started[/bright_black]\n"
        "[bright_black]2026-04-07 08:02:44  INFO   PLC 172.16.5.20 connected[/bright_black]\n"
        "[bold yellow]2026-04-07 09:14:55  WARN   Unusual Modbus read frequency detected[/bold yellow]\n"
        "[bold red]2026-04-07 09:15:01  ERROR  Unauthorised S7comm connection from 10.10.10.5[/bold red]\n"
        "[bright_black]2026-04-07 09:15:44  INFO   HMI operator panel: session timeout[/bright_black]"
    ),
    "web.config": (
        "[bright_black]<?xml version='1.0'?>[/bright_black]\n"
        "<configuration>\n"
        "  <connectionStrings>\n"
        "    <add name='MSSQL'\n"
        "         connectionString='[bold red]Server=corp-db;Database=HR;User=sa;Password=Sa$Admin2026![/bold red]'\n"
        "         providerName='System.Data.SqlClient'/>\n"
        "  </connectionStrings>\n"
        "  [bright_black]<!-- DEBUG mode enabled in production - CWE-94 -->[/bright_black]\n"
        "  <system.web><customErrors mode='[bold red]Off[/bold red]'/></system.web>\n"
        "</configuration>"
    ),
    "security_events.log": (
        "[bright_black]2026-04-07 09:10:01  EventID 4624  Logon: svc_scada  Type:3 (Network)[/bright_black]\n"
        "[bold yellow]2026-04-07 09:14:22  EventID 4625  Failed logon: unknown  Source: 10.10.10.5[/bold yellow]\n"
        "[bold red]2026-04-07 09:15:05  EventID 4662  Object access: Directory Service (DCSync indicator)[/bold red]\n"
        "[bold red]2026-04-07 09:15:44  EventID 7045  New service installed: WindowsUpdateSvc[/bold red]\n"
        "[bright_black]  FINDING: Multiple high-severity events — Blue Team should have triggered![/bright_black]"
    ),
    "alarm_2026.log": (
        "[bold red]2026-04-07 09:15:02  ALARM  Modbus write detected on coil 3 — unauthorised source[/bold red]\n"
        "[bold red]2026-04-07 09:15:10  ALARM  S7comm CPU STOP command received — PLC halted![/bold red]\n"
        "[bold yellow]2026-04-07 09:15:44  WARN   HMI disconnected from PLC unexpectedly[/bold yellow]\n"
        "[bright_black]  ICS-CERT: These events indicate active attack on OT infrastructure[/bright_black]"
    ),
}

class CyberLab:
    def __init__(self):
        self.alert_level      = 0
        self.scanned_hosts    = set()
        self.compromised      = {}
        self.active_session   = None
        self.msf_mode         = False
        self.msf_module       = None
        self.msf_options      = {
            "RHOSTS":  "",
            "RPORT":   "",
            "PAYLOAD": "linux/x64/meterpreter/reverse_tcp",
            "LHOST":   "10.0.2.15",
            "LPORT":   "4444",
        }
        self.known_routes     = ["82.148.10.55"]
        self.internal_map     = {"82.148.10.55": "192.168.10.5"}
        self.current_dir      = "/"
        self.start_time       = datetime.now()
        self.hint_index       = 0
        self.objectives_done  = []
        self.event_log        = []
        self.loot_files       = []
        self.persistence_done = []
        self.meta             = {}
        self.network          = {}
        self.ad_domain        = None
        self.shell_history    = []
        self.c2_server        = "203.0.113.10"

        self.module_map = {
            "rce":           "exploit/multi/http/tomcat_mgr_upload",
            "sql_injection": "exploit/multi/http/apache_sqli",
            "weak_creds":    "auxiliary/scanner/mysql/mysql_login",
            "brute_force":   "auxiliary/scanner/ssh/ssh_login",
            "eternalblue":   "exploit/windows/smb/ms17_010_eternalblue",
            "anon_share":    "auxiliary/scanner/smb/smb_enumshares",
            "anon_login":    "auxiliary/scanner/ftp/anonymous",
            "ldap_enum":     "auxiliary/gather/ldap_hashdump",
            "xss":           "exploit/unix/webapp/roundcube_rce",
            "s7_exploit":    "exploit/windows/scada/step7_exec",
            "default_creds": "exploit/windows/http/wincc_default_creds",
            "no_auth":       "auxiliary/scanner/scada/modbusclient",
            "socks_proxy":   "auxiliary/server/socks_proxy",
            "kerberoast":    "auxiliary/gather/get_user_spns",
            "psexec":        "exploit/windows/smb/psexec",
        }

    def log_event(self, event_type: str, detail: str, severity: str = "INFO"):
        entry = {
            "ts":       datetime.now().strftime("%H:%M:%S"),
            "type":     event_type,
            "detail":   detail,
            "severity": severity,
        }
        self.event_log.append(entry)
        soc_event(event_type, detail, severity)

    def cmd_eventlog(self):
        if not self.event_log:
            console.print("[bright_black](No events yet)[/bright_black]"); return
        t = Table(title="Red Team Event Log (local)", box=box.SIMPLE_HEAD,
                  header_style="bold white")
        t.add_column("Time",     style="bright_black", width=10)
        t.add_column("Severity", width=9)
        t.add_column("Type",     style="cyan", width=22)
        t.add_column("Detail")
        sev_colors = {
            "INFO": "white", "WARN": "yellow",
            "HIGH": "bold red", "CRIT": "bold red reverse"
        }
        for e in self.event_log[-30:]:
            sc = sev_colors.get(e["severity"], "white")
            t.add_row(e["ts"], f"[{sc}]{e['severity']}[/{sc}]", e["type"], e["detail"])
        console.print(t)

    def _alert_bar(self) -> str:
        pct    = min(self.alert_level, 100)
        thresh = self.meta.get("hunter_threshold", 50)
        filled = int(pct / 5)
        bar    = "█" * filled + "░" * (20 - filled)
        color  = "green" if pct < 30 else ("yellow" if pct < (thresh - 5) else "bold red")
        return (f"[{color}]ALERT [{bar}] {pct}%[/{color}]  "
                f"[bright_black]Hunter triggers @{thresh}%[/bright_black]")

    def check_hunter(self):
        threshold = self.meta.get("hunter_threshold", 50)
        if self.alert_level >= threshold:
            self.log_event("HUNTER_TRIGGERED", f"Alert={self.alert_level}%", "CRIT")
            console.print(Panel(
                "[bold red]🚨  IDS THRESHOLD BREACHED — BLUE TEAM RESPONDED!\n\n[/bold red]"
                "Blue Team-მა დაბლოკა შენი IP. ოპერაცია შეჩერდა.\n\n"
                "[yellow]OPSEC სქემა:\n"
                "  • nmap -sS -T2 -n    → ყველაზე stealth სკანი\n"
                "  • kerberoast (+8%)   >> DCSync (+25%) >> mimikatz LSASS (+20%)\n"
                "  • autoroute / SOCKS  → +0% (pivot alert-ს არ ზრდის)\n"
                "  • persistence        → scheduled task (+6%) << service (+12%)[/yellow]",
                title="[ ⛔ OPERATION BURNED ]", border_style="bold red",
            ))
            sys.exit(0)

    def _tick_alert_decay(self):
        decay = self.meta.get("alert_decay_per_tick", 0)
        if decay > 0:
            self.alert_level = max(0, self.alert_level - decay)

    def is_routable(self, target_ip):
        if target_ip in self.internal_map:
            target_ip = self.internal_map[target_ip]
        for route in self.known_routes:
            if "/" in route:
                base = route.rsplit(".", 1)[0]
                if target_ip.startswith(base):
                    return True
            elif target_ip == route:
                return True
        return False

    def _mark_obj(self, obj_key: str, log_detail: str):
        if obj_key not in self.objectives_done:
            self.objectives_done.append(obj_key)
            console.print(f"[bold green]  ✓ OBJECTIVE: {obj_key}[/bold green]")
            self.log_event("OBJECTIVE_DONE", log_detail, "HIGH")

    def _session_status(self) -> str:
        elapsed   = datetime.now() - self.start_time
        mins, secs = divmod(int(elapsed.total_seconds()), 60)
        sessions  = len(self.compromised)
        routes    = len([r for r in self.known_routes if "/" in r])
        loot      = len(self.loot_files)
        events    = len(self.event_log)
        hosts_str = "  ".join(
            f"[bold green]{self.network[ip]['hostname']}[/bold green]"
            for ip in self.compromised.values()
        ) if self.compromised else "[bright_black]none[/bright_black]"

        lines = [
            f"  [bright_black]Sessions: [white]{sessions}[/white]  "
            f"Pivot Routes: [white]{routes}[/white]  "
            f"Loot: [white]{loot}[/white] files  "
            f"Events: [white]{events}[/white]  "
            f"Elapsed: [white]{mins:02d}m {secs:02d}s[/white][/bright_black]",
            f"  [bright_black]Compromised: {hosts_str}[/bright_black]",
        ]
        return "\n".join(lines)

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def banner(self):
        self.clear_screen()
        art = r"""
   ▄████▄ ▓██   ██▓ ▄▄▄▄   ▓█████  ██▀███   ██▓    ▄▄▄       ▄▄▄▄
  ▒██▀ ▀█  ▒██  ██▒▓█████▄ ▓█   ▀ ▓██ ▒ ██▒▓██▒   ▒████▄    ▓█████▄
  ▒▓█    ▄  ▒██ ██░▒██▒ ▄██▒███   ▓██ ░▄█ ▒▒██░   ▒██  ▀█▄  ▒██▒ ▄██
  ▒▓▓▄ ▄██▒ ░ ▐██▓░▒██░█▀  ▒▓█  ▄ ▒██▀▀█▄  ▒██░   ░██▄▄▄▄██ ▒██░█▀
  ▒ ▓███▀ ░ ░ ██▒▓░░▓█  ▀█▓░▒████▒░██▓ ▒██▒░██████▒▓█   ▓██▒░▓█  ▀█▓
  ░ ░▒ ▒  ░  ██▒▒▒ ░▒▓███▀▒░░ ▒░ ░░ ▒▓ ░▒▓░░ ▒░▓  ░▒▒   ▓▒█░░▒▓███▀▒
    ░  ▒   ▓██ ░▒░ ▒░▒   ░  ░ ░  ░  ░▒ ░ ▒░░ ░ ▒  ░ ▒   ▒▒ ░▒░▒   ░
  ░        ▒ ▒ ░░   ░    ░    ░     ░░   ░   ░ ░    ░   ▒    ░    ░
  ░ ░      ░ ░      ░         ░  ░   ░         ░  ░     ░  ░ ░
  ░        ░ ░           ░
            CYBERLAB
"""
        console.print(art, style=BANNER_COLOR)
        console.print(
            "  [ OS: [cyan]Kali Linux 2026.1[/cyan]  USER: [bold red]anonimus[/bold red]"
            "  VPN: [green]tun0 ● Connected[/green]  IFACE: 10.0.2.15 ]\n"
            "  [ TARGET: [bold red]geoforum.ge[/bold red]"
            "  MODE: [bold red]HARD — Full Chain[/bold red]"
            f"  SESSION: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')} ]",
            style="bright_black",
        )
        console.print(f"\n  {self._alert_bar()}", highlight=False)
        console.print(Rule(style="bright_black"))
        console.print(self._session_status(), highlight=False)
        console.print(Rule(style="bright_black"))
        console.print(
            "  [bright_black]Commands: shodan · nmap · msfconsole · netmap · "
            "eventlog · ad · hashcat · hint · help · clear · exit[/bright_black]\n"
        )

    def load_scenario(self):
        self.clear_screen()
        console.print(Panel(
            "[bold red]CLASSIFIED MISSION BRIEFING — HARD MODE[/bold red]\n\n"
            "[white]სამიზნე:[/white]   [bold cyan]geoforum.ge[/bold cyan]\n"
            "[white]ჯაჭვი:[/white]    DMZ (RCE) → CORP (AD/EternalBlue) → OT (SCADA/S7)\n\n"
            "[bold yellow]OPSEC სავალდებულოა:[/bold yellow]\n"
            "  ⚠  IDS/Hunter აქტიურია. Alert ≥ 50% = ოპერაცია დასრულდა.\n"
            "  ⚠  Honeypot host-ი DMZ-ში! (192.168.10.99) — ნუ შეეხები!\n"
            "  ⚠  ყოველი ნაბიჯი Blue Team SOC-ს ეგზავნება — [bold]server.py[/bold]-ს გაუშვი.\n"
            "  💡 [bold]hint[/bold] = შემდეგი ნაბიჯი  |  [bold]eventlog[/bold] = შენი კვალი",
            title="[ OPERATIONAL DIRECTIVE ]", border_style="red",
        ))
        try:
            with open("Hard.json", "r", encoding="utf-8") as f:
                data = json.load(f)
            self.meta      = data.get("_meta", {})
            self.network   = data.get("network", {})
            self.ad_domain = data.get("ad_domain")
            self.c2_server = self.meta.get("c2_server", "203.0.113.10")
            self.known_routes.append("192.168.10.0/24")
            console.print(f"\n[bold green][+] სცენარი ჩაიტვირთა: {self.meta.get('name')}[/bold green]")
            console.print(f"[bright_black]    {self.meta.get('description')}[/bright_black]")
            self.log_event("SESSION_START", f"Red Team session started at {self.start_time}", "INFO")
            time.sleep(2)
        except Exception as e:
            console.print(f"[bold red][!] Hard.json ვერ ჩაიტვირთა: {e}[/bold red]")
            sys.exit(1)

    def cmd_netmap(self):
        console.print(Rule("[bold cyan]NETWORK MAP[/bold cyan]"))
        zones: dict[str, list] = {}
        for ip, node in self.network.items():
            zones.setdefault(node.get("zone", "?"), []).append((ip, node))

        zone_colors = {"DMZ": ZONE_DMZ_COLOR, "CORP": ZONE_CORP_COLOR, "OT": ZONE_OT_COLOR}
        zone_icons  = {"DMZ": "🌐", "CORP": "🏢", "OT": "⚙️ "}

        for zone, hosts in zones.items():
            color = zone_colors.get(zone, "white")
            console.print(f"\n  [{color}]{zone_icons.get(zone,'📡')}  ── {zone} ZONE ──[/{color}]")
            for ip, node in hosts:
                is_comp  = ip in self.compromised.values()
                is_scann = ip in self.scanned_hosts
                is_honey = node.get("is_honeypot", False)

                if is_honey:
                    status = ("[bold red]⚠  HONEYPOT[/bold red]"
                              if is_scann else "[bright_black]? (unknown)[/bright_black]")
                elif is_comp:
                    status = "[bold green]✓ COMPROMISED[/bold green]"
                elif is_scann:
                    status = "[yellow]◉ Scanned[/yellow]"
                else:
                    status = "[bright_black]○ Unknown[/bright_black]"

                reach   = "[green]✔[/green]" if self.is_routable(ip) else "[red]✘ no route[/red]"
                tree_ch = "└" if hosts[-1][0] == ip else "├"
                console.print(
                    f"    {tree_ch}── {ip:<16} [white]{node['hostname']:<18}[/white] "
                    f"{status}  {reach}", highlight=False
                )
                if is_scann and not is_honey:
                    ports_str = "  ".join(
                        f"[cyan]{p}[/cyan]/{info['service']}"
                        for p, info in node["ports"].items()
                    )
                    console.print(f"    │    ports: {ports_str}", highlight=False)
                if node.get("routes_to"):
                    for r in node["routes_to"]:
                        in_rt = any(r.split("/")[0].rsplit(".",1)[0] in kr for kr in self.known_routes) or r in self.known_routes
                        piv   = "[green]→ pivot ACTIVE[/green]" if in_rt else "[bright_black]→ pivot needed[/bright_black]"
                        console.print(f"    │    [bright_black]routes_to: {r}  {piv}[/bright_black]", highlight=False)

        if self.ad_domain:
            console.print(f"\n  [bold magenta]🔑  AD: {self.ad_domain['name']}  DC: {self.ad_domain['dc_ip']}[/bold magenta]")
        if self.loot_files:
            console.print(f"\n  [bold yellow]📦  Loot ({len(self.loot_files)} files): {', '.join(self.loot_files[-5:])}[/bold yellow]")
        if self.persistence_done:
            console.print(f"\n  [bold green]🔒  Persistence ({len(self.persistence_done)}): {', '.join(self.persistence_done)}[/bold green]")
        console.print()

    def cmd_ad(self):
        if not self.ad_domain:
            console.print("[red][-] AD domain not loaded.[/red]"); return
        console.print(Rule(f"[bold magenta]AD: {self.ad_domain['name']}[/bold magenta]"))

        t = Table(title="Domain Users", box=box.SIMPLE_HEAD, header_style="bold magenta")
        t.add_column("Username", style="cyan")
        t.add_column("Groups")
        t.add_column("SPN")
        t.add_column("Status")
        for u in self.ad_domain.get("users", []):
            spn     = u.get("spn") or "[bright_black]—[/bright_black]"
            enabled = "[green]enabled[/green]" if u["enabled"] else "[red]disabled[/red]"
            t.add_row(u["name"], ", ".join(u["groups"]), spn, enabled)
        console.print(t)

        console.print("\n[bold cyan]Attack Paths:[/bold cyan]")
        for ap in self.ad_domain.get("attack_paths", []):
            arrow_chain = " → ".join(ap["steps"])
            console.print(f"  [bold yellow]{ap['id']}[/bold yellow]: {arrow_chain}")
            console.print(f"  [bright_black]    {ap['description']}[/bright_black]\n")

    def cmd_shodan(self, query):
        self.log_event("OSINT_SHODAN", f"Query: {query}", "INFO")
        console.print(f"\n[bold yellow][*] Shodan query: [cyan]{query}[/cyan][/bold yellow]")
        with Progress(SpinnerColumn(), TextColumn("[bright_black]Contacting Shodan nodes..."),
                      transient=True) as p:
            p.add_task("", total=None); time.sleep(1.5)

        if "geoforum" in query.lower():
            t = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE_HEAD)
            t.add_column("IP Address",  style="bold cyan")
            t.add_column("Hostname")
            t.add_column("OS")
            t.add_column("Open Ports")
            t.add_column("Banners")
            t.add_row("82.148.10.55", "web-prod-gw", "Ubuntu 20.04",
                      "80, 443, 8080",
                      "[yellow]Apache/2.4.51 · Apache Tomcat/9.0.37[/yellow]")
            console.print(t)
            console.print(
                "[bright_black]  Shodan result: 1  |  Last indexed: 2026-04-07\n"
                "  CVE-2020-1938 (Tomcat AJP Ghostcat) detected on :8080\n"
                "  Shodan Tag: [bold red]vuln:CVE-2020-1938[/bold red][/bright_black]\n"
            )
            console.print("[bright_black]  → Passive recon. Kali-ს IP Shodan-ში არ ჩანს.[/bright_black]\n")
        else:
            console.print("[red][-] No results found.[/red]\n")

    def cmd_nmap(self, ip_arg, flags=""):
        target_ip = ip_arg

        if not self.is_routable(target_ip):
            console.print(f"[red]RTTM Host Unreachable. No route to {target_ip}.[/red]")
            console.print("[bright_black]  → autoroute pivot-ის შემდეგ სცადე.[/bright_black]\n")
            return

        internal_ip = self.internal_map.get(target_ip, target_ip)
        if internal_ip not in self.network:
            console.print(f"[red]Note: {target_ip} is down or filtering probes.[/red]\n")
            return

        node      = self.network[internal_ip]
        flag_list = flags.split() if flags else []

        if node.get("is_honeypot", False):
            self.alert_level += 50
            self.log_event("HONEYPOT_HIT", f"Scan of honeypot {target_ip}", "CRIT")
            console.print(Panel(
                "[bold red]⚠  HONEYPOT — IDS TRIGGERED![/bold red]\n\n"
                "ეს მასპინძელი ყალბი სამიზნეა — Blue Team-ის ხაფანგი.\n"
                "ნებისმიერი კავშირი SOC-ს სიგნალს უგზავნის!\n"
                f"[yellow]Alert +50% → სულ: {self.alert_level}%[/yellow]",
                border_style="red",
            ))
            self.check_hunter(); return

        scan_flags_found = []
        total_noise_lo   = 0
        total_noise_hi   = 0
        has_script       = False
        script_names     = []
        has_timing       = False
        has_A            = "-A" in flag_list

        effective_flags = list(flag_list)
        if has_A:
            for f in ["-sV", "-O", "--script=default"]:
                if f not in effective_flags:
                    effective_flags.append(f)

        scan_types = [f for f in effective_flags if f in ("-sS","-sT","-sU","-sN","-sF","-sX")]
        if not scan_types:
            effective_flags.insert(0, "-sS")

        for f in effective_flags:
            if f.startswith("--script"):
                has_script = True
                if "=" in f:
                    script_names = f.split("=", 1)[1].split(",")
            if f in NMAP_FLAG_WEIGHTS:
                w = NMAP_FLAG_WEIGHTS[f]
                lo, hi = w["noise"]
                total_noise_lo += lo
                total_noise_hi += hi
                scan_flags_found.append((f, w["label"], w["opsec"]))
                if f in ("-T1","-T2","-T3","-T4","-T5"):
                    has_timing = True

        if has_script and "--script" in NMAP_FLAG_WEIGHTS:
            w  = NMAP_FLAG_WEIGHTS["--script"]
            lo, hi = w["noise"]
            total_noise_lo += lo
            total_noise_hi += hi

        noise = random.randint(
            max(0, total_noise_lo),
            max(1, total_noise_hi)
        )
        self.alert_level += noise
        self.log_event("PORT_SCAN", f"nmap {target_ip} {flags or '-sS'}", "WARN")

        scan_speed = 0.8
        if "-T1" in effective_flags: scan_speed = 3.5
        elif "-T2" in effective_flags: scan_speed = 2.0
        elif "-T4" in effective_flags: scan_speed = 0.5
        elif "-T5" in effective_flags: scan_speed = 0.3
        if "-sV" in effective_flags:  scan_speed += 0.8
        if "-A" in flag_list:         scan_speed += 1.5
        if "-p-" in effective_flags:  scan_speed += 2.0

        with Progress(SpinnerColumn(), BarColumn(), TaskProgressColumn(),
                      TextColumn(f"[cyan]Scanning {target_ip}..."), transient=True) as p:
            task = p.add_task("", total=100)
            while not p.finished:
                p.update(task, advance=random.randint(8, 20))
                time.sleep(scan_speed / 20)

        self.scanned_hosts.add(internal_ip)

        if scan_flags_found:
            console.print(f"\n[bright_black]Starting Nmap 7.94SVN ( https://nmap.org ) at "
                          f"{datetime.now().strftime('%Y-%m-%d %H:%M')} EEST[/bright_black]")

        console.print(f"\n[bold green]Nmap scan report for {node['hostname']} ({target_ip})[/bold green]")
        console.print(f"[bright_black]Host: up ({random.randint(10,80)}ms latency)  "
                      f"OS: {node['os']}  Zone: {node['zone']}[/bright_black]\n")

        t = Table(box=box.SIMPLE, header_style="bold white")
        t.add_column("PORT",    style="cyan",   width=10)
        t.add_column("STATE",   style="green",  width=8)
        t.add_column("SERVICE", style="yellow", width=14)
        if "-sV" in effective_flags or has_A:
            t.add_column("VERSION", width=30)
            t.add_column("VULN",    width=22)
            for port, info in node["ports"].items():
                vuln_str = (f"[bold red]⚑ {info['vuln']}[/bold red]"
                            if info.get("vuln") else "[bright_black]—[/bright_black]")
                t.add_row(f"{port}/tcp", "open", info["service"], info["version"], vuln_str)
        else:
            for port, info in node["ports"].items():
                t.add_row(f"{port}/tcp", "open", info["service"])

        console.print(t)

        if "-O" in effective_flags or has_A:
            os_str = node["os"]
            if "Windows Server 2012" in os_str:
                cpe = "cpe:/o:microsoft:windows_server_2012:r2"
                guess = "Microsoft Windows Server 2012 R2 (96%)"
            elif "Windows 7" in os_str:
                cpe = "cpe:/o:microsoft:windows_7"
                guess = "Microsoft Windows 7 Embedded (94%)"
            elif "Ubuntu" in os_str:
                cpe = "cpe:/o:linux:linux_kernel"
                guess = "Linux 5.4 (Ubuntu) (98%)"
            elif "Debian" in os_str:
                cpe = "cpe:/o:linux:linux_kernel"
                guess = "Linux 4.19 (Debian) (96%)"
            elif "CentOS" in os_str:
                cpe = "cpe:/o:linux:linux_kernel"
                guess = "Linux 4.18 (CentOS 8) (95%)"
            elif "Siemens" in os_str:
                cpe = "cpe:/o:siemens:simatic"
                guess = "Siemens SIMATIC S7 (97%)"
            else:
                cpe = "cpe:/o:linux:linux_kernel"
                guess = f"{os_str} (90%)"
            console.print(f"[bright_black]OS CPE: {cpe}[/bright_black]")
            console.print(f"[bright_black]Aggressive OS guesses: {guess}[/bright_black]")

        if has_script:
            console.print()
            matched_any = False
            for script_name in (script_names if script_names else ["default"]):
                sn = script_name.strip()
                if sn in NSE_SCRIPT_OUTPUTS:
                    entry = NSE_SCRIPT_OUTPUTS[sn]
                    if internal_ip in entry["hosts"] or not entry["hosts"]:
                        console.print(f"[bright_black]PORT SCRIPT OUTPUT:[/bright_black]")
                        console.print(entry["output"])
                        matched_any = True
                elif sn == "default":
                    for k, v in NSE_SCRIPT_OUTPUTS.items():
                        if internal_ip in v["hosts"]:
                            console.print(v["output"])
                            matched_any = True
            if not matched_any:
                console.print(f"[bright_black]  NSE: {', '.join(script_names) or 'default'} — no output for this host.[/bright_black]")

        if node.get("routes_to"):
            console.print(f"[yellow]  ↳ Dual-homed! Internal routes: {', '.join(node['routes_to'])}[/yellow]")
            console.print("[bright_black]    → autoroute -s <subnet> pivot-ისთვის[/bright_black]")

        if scan_flags_found:
            console.print()
            opsec_t = Table(box=box.SIMPLE, header_style="bold white", show_header=False)
            opsec_t.add_column("Flag",  style="cyan",         width=12)
            opsec_t.add_column("Name",  style="white",        width=20)
            opsec_t.add_column("OPSEC", style="bright_black")
            for f, lbl, opsec in scan_flags_found:
                opsec_t.add_row(f, lbl, opsec)
            console.print(opsec_t)

        console.print(f"\n  {self._alert_bar()}  [bright_black](+{noise}% ამ სკანიდან)[/bright_black]\n")
        self.check_hunter()

    def show_msf_options(self):
        t = Table(title=f"Options ({self.msf_module or 'none'})",
                  header_style="bold magenta", box=box.SIMPLE_HEAD)
        t.add_column("Name"); t.add_column("Value"); t.add_column("Req"); t.add_column("Description")
        descs = {
            "RHOSTS":  "სამიზნე IP",
            "RPORT":   "სამიზნე პორტი (ცარიელი=auto)",
            "PAYLOAD": "Payload",
            "LHOST":   "ჩვენი IP (reverse connection)",
            "LPORT":   "ჩვენი listen port",
            "USERNAME":"მომხმარებელი (cred modules)",
            "PASSWORD":"პაროლი (cred modules)",
            "SMBUser": "SMB username (psexec/pth)",
            "SMBPass": "SMB password or NTLM hash (psexec/pth)",
        }
        for k, v in self.msf_options.items():
            if k.startswith("_"): continue
            req = "yes" if k in ("RHOSTS", "LHOST") else "no"
            t.add_row(k, v or "[bright_black](not set)[/bright_black]", req, descs.get(k, ""))
        console.print(t)

    def search_msf(self, term):
        t = Table(title=f"Modules matching '{term}'", header_style=BANNER_COLOR, box=box.SIMPLE_HEAD)
        t.add_column("#", width=4); t.add_column("Module Path"); t.add_column("Vuln Tag")
        idx = 0
        for vk, mp in self.module_map.items():
            if term.lower() in mp.lower() or term.lower() in vk.lower():
                t.add_row(str(idx), mp, f"[cyan]{vk}[/cyan]"); idx += 1
        if idx == 0:
            console.print(f"[red][-] No modules matched '{term}'.[/red]")
        else:
            console.print(t)
            console.print("[bright_black]  გამოყენება: use <module_name>[/bright_black]\n")

    def run_msf_exploit(self):
        rhost = self.msf_options.get("RHOSTS", "")
        if not rhost:
            console.print("[red][-] RHOSTS not set.[/red]\n"); return

        internal_ip = self.internal_map.get(rhost, rhost)

        cred_modules = {
            "exploit/multi/http/tomcat_mgr_upload": {
                "user_opt": "HttpUsername", "pass_opt": "HttpPassword",
                "default_user": "tomcat",   "default_pass": "tomcat",
                "hint": "Tomcat Manager requires HTTP auth. Try: set HttpUsername tomcat  /  set HttpPassword tomcat",
            },
            "auxiliary/gather/ldap_hashdump": {
                "user_opt": "USERNAME", "pass_opt": "PASSWORD",
                "default_user": None,   "default_pass": None,
                "hint": "ldap_hashdump requires valid AD credentials.\n"
                        "  set USERNAME j.smith\n  set PASSWORD P@ssw0rd2026!",
            },
            "exploit/windows/smb/psexec": {
                "user_opt": "SMBUser", "pass_opt": "SMBPass",
                "default_user": None,  "default_pass": None,
                "hint": "PsExec requires credentials or NTLM hash.\n"
                        "  set SMBUser Administrator\n"
                        "  set SMBPass aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c\n"
                        "  (Pass-the-Hash: LM:NT format)",
            },
        }
        if self.msf_module in cred_modules:
            cred_cfg  = cred_modules[self.msf_module]
            ukey, pkey = cred_cfg["user_opt"], cred_cfg["pass_opt"]
            username  = self.msf_options.get(ukey, "")
            password  = self.msf_options.get(pkey, "")
            if not username and cred_cfg["default_user"]:
                username = cred_cfg["default_user"]
                self.msf_options[ukey] = username
                console.print(f"[bright_black][*] Using default {ukey}={username}[/bright_black]")
            if not username or not password:
                console.print(f"[red][-] {self.msf_module} requires credentials.[/red]")
                console.print(f"[yellow]  → {cred_cfg['hint']}[/yellow]\n")
                return

        console.print(f"\n[*] Reverse TCP handler on {self.msf_options['LHOST']}:{self.msf_options['LPORT']}")
        console.print(f"[*] Executing {self.msf_module} against {rhost}...")

        with Progress(SpinnerColumn(), TextColumn("[yellow]Sending stage... "),
                      transient=True) as p:
            p.add_task("", total=None); time.sleep(random.uniform(1.5, 2.5))

        if not self.is_routable(internal_ip):
            console.print(f"[red][-] No route to {rhost}.[/red]")
            console.print("[bright_black]  → autoroute -s <subnet> pivot-ის შემდეგ სცადე.[/bright_black]\n"); return

        if internal_ip not in self.network:
            self.alert_level += 10
            console.print("[red][-] Host unreachable or down.[/red]\n")
            self.check_hunter(); return

        target_node   = self.network[internal_ip]
        valid_vulns   = [info.get("vuln") for info in target_node["ports"].values()]
        required_vuln = None
        for vk, mp in self.module_map.items():
            if mp == self.msf_module:
                required_vuln = vk; break

        has_edr = target_node.get("has_edr", False)
        if has_edr and required_vuln not in ("ldap_enum", "anon_share", "anon_login"):
            edr = target_node.get("edr_product", "EDR")
            console.print(f"[yellow][!] {edr} detected on target...[/yellow]")
            time.sleep(0.8)
            if required_vuln == "eternalblue":
                console.print("[bright_black]  → MS17-010 pre-dates EDR behavioral rules — proceeding...[/bright_black]")
            elif random.random() < 0.25:
                self.alert_level += 20
                self.log_event("AV_BLOCK", f"{edr} blocked {self.msf_module} payload", "CRIT")
                console.print(f"[bold red][-] {edr} killed the payload process![/bold red]")
                console.print("[yellow]  → Consider: set PAYLOAD windows/x64/meterpreter/reverse_https[/yellow]")
                console.print("[yellow]  → Or encode: set EnableStageEncoding true[/yellow]\n")
                self.check_hunter(); return

        if required_vuln in valid_vulns:
            session_id = len(self.compromised) + 1
            self.compromised[session_id] = internal_ip
            noise = random.randint(8, 16)
            self.alert_level += noise
            self.log_event("EXPLOIT_SUCCESS",
                           f"{self.msf_module} → {rhost} ({target_node['hostname']})", "HIGH")

            console.print(f"\n[bold green][+] Exploit successful![/bold green]")
            console.print(f"[bold green][+] Meterpreter session {session_id} opened "
                          f"({self.msf_options['LHOST']}:{self.msf_options['LPORT']} "
                          f"→ {rhost}:{random.randint(40000,65535)})[/bold green]")
            console.print(f"[bright_black]    {target_node['hostname']}  {target_node['os']}  "
                          f"Zone: {target_node['zone']}[/bright_black]")

            if required_vuln == "psexec":
                console.print(f"[bold red][!] OPSEC: PsExec ქმნის სერვისს — Event ID 7045 (Service Install)![/bold red]")
                console.print(f"[yellow]  → Stealthier: WMI exec / wmic /node:{rhost} process call create ...[/yellow]")

            console.print(f"\n  {self._alert_bar()}  [bright_black](+{noise}%)[/bright_black]\n")

            obj_map = {
                "192.168.10.5": "DMZ→CORP→OT სრული ჯაჭვი",
                "10.10.10.5":   "Domain Admin მოპოვება",
                "172.16.5.10":  "SCADA HMI-ზე წვდომა",
            }
            if internal_ip in obj_map:
                obj = obj_map[internal_ip]
                if obj not in self.objectives_done:
                    self.objectives_done.append(obj)
                    console.print(f"[bold green]  ✓ OBJECTIVE: {obj}[/bold green]\n")

            self.active_session = session_id
            self.msf_mode       = False
            self.check_hunter()
        else:
            self.alert_level += 15
            self.log_event("EXPLOIT_FAIL",
                           f"{self.msf_module} → {rhost} (wrong module/vuln)", "WARN")
            console.print("[red][-] Exploit failed — no session created.[/red]")
            console.print(f"[bright_black]  → {self.msf_module} ამ სამიზნეს არ შეეფერება.[/bright_black]")
            console.print(f"  {self._alert_bar()}\n")
            self.check_hunter()

    def handle_meterpreter(self, action, parts):
        target_ip  = self.compromised[self.active_session]
        node       = self.network[target_ip]
        is_win     = "Windows" in node["os"]
        raw        = " ".join(parts)

        if action == "sysinfo":
            console.print(f"Computer    : [cyan]{node['hostname']}[/cyan]")
            console.print(f"OS          : {node['os']}")
            console.print("Architecture: x64")
            console.print(f"Meterpreter : x64/{'windows' if is_win else 'linux'}")
            console.print(f"Zone        : [yellow]{node['zone']}[/yellow]")
            console.print(f"User        : [bold green]{'NT AUTHORITY\\SYSTEM' if is_win else 'root'}[/bold green]")

        elif action == "getuid":
            uid = "NT AUTHORITY\\SYSTEM" if is_win else "root"
            console.print(f"Server username: [bold green]{uid}[/bold green]")

        elif action == "autoroute" and len(parts) > 2 and parts[1] == "-s":
            subnet = parts[2]
            if subnet not in self.known_routes:
                self.known_routes.append(subnet)
                self.log_event("PIVOT_ROUTE", f"autoroute +{subnet} via session {self.active_session}", "HIGH")
                console.print(f"[bold green][+] Route added: {subnet} via session {self.active_session}[/bold green]")
                if "10.10" in subnet and "DMZ→CORP pivot" not in self.objectives_done:
                    self.objectives_done.append("DMZ→CORP pivot")
                    console.print("[bold green]  ✓ OBJECTIVE: DMZ→CORP Pivot active[/bold green]")
                if "172.16" in subnet:
                    console.print("[bold green]  ✓ OT subnet routable — SCADA ახლა სასწრაფოა![/bold green]")
                console.print(f"[bright_black]  ახლა შეგიძლია: nmap {subnet.replace('0/24','1')} / exploit[/bright_black]\n")
            else:
                console.print(f"[*] Route {subnet} already exists.")

        elif action in ("ifconfig", "ipconfig"):
            my_ip = target_ip
            console.print(f"eth0: inet [cyan]{my_ip}[/cyan]  netmask 255.255.255.0")
            if node.get("routes_to"):
                console.print(f"eth1: inet [yellow]{node['routes_to'][0].replace('0/24','1')}[/yellow]"
                               "  [bright_black]← internal NIC[/bright_black]")

        elif action == "shell":
            has_edr_s = node.get("has_edr", False)
            console.print("[*] Spawning shell...")
            time.sleep(0.3)
            if has_edr_s and is_win and random.random() < 0.3:
                self.alert_level += 15
                edr_s = node.get("edr_product", "Windows Defender")
                console.print(f"[bold red][-] {edr_s} terminated cmd.exe spawn — suspicious parent process.[/bold red]")
                console.print("[yellow]  → Try: migrate to explorer.exe first[/yellow]")
                console.print("[yellow]  → Or:  use post/multi/manage/shell_to_meterpreter[/yellow]\n")
                self.check_hunter()
            else:
                self.log_event("SHELL_SPAWNED", f"Interactive shell on {node['hostname']}", "HIGH")
                self.interactive_shell(node)

        elif action in ("background", "exit"):
            console.print(f"[*] Session {self.active_session} backgrounded.")
            self.active_session = None

        elif action == "sessions":
            if self.compromised:
                t = Table(box=box.SIMPLE, header_style="bold magenta")
                t.add_column("ID"); t.add_column("IP"); t.add_column("Hostname")
                t.add_column("OS"); t.add_column("Zone")
                for sid, ip in self.compromised.items():
                    n = self.network[ip]
                    t.add_row(str(sid), ip, n["hostname"], n["os"], n["zone"])
                console.print(t)
            else:
                console.print("[bright_black]No active sessions.[/bright_black]")

        elif action == "run" and len(parts) > 1:
            sub = parts[1].lower()
            if sub == "autoroute" and len(parts) > 3 and parts[2] == "-s":
                self.handle_meterpreter("autoroute", ["autoroute", "-s", parts[3]])
            elif sub == "post/windows/manage/persistence_exe":
                self._cmd_persistence_service(node, is_win)
            else:
                console.print(f"[bright_black][*] Running post module: {' '.join(parts[1:])}[/bright_black]")
                time.sleep(0.5)
                console.print("[bright_black](Module completed)[/bright_black]\n")

        elif action == "getsystem":
            has_edr = node.get("has_edr", False)
            edr     = node.get("edr_product", "EDR/AV")
            self.log_event("PRIVESC", f"getsystem on {node['hostname']}", "HIGH")
            with Progress(SpinnerColumn(), TextColumn("[yellow]Attempting privilege escalation..."),
                          transient=True) as p:
                p.add_task("", total=None); time.sleep(1.2)
            if has_edr and random.random() < 0.4:
                self.alert_level += 10
                console.print(f"[bold red][-] getsystem failed — {edr} blocked Named Pipe Impersonation.[/bold red]")
                console.print("[yellow]  → Alternatives:[/yellow]")
                console.print("[yellow]     PrintSpoofer:  upload PrintSpoofer64.exe → shell → .\\PrintSpoofer64.exe -i -c cmd[/yellow]")
                console.print("[yellow]     RoguePotato:   upload RoguePotato.exe → shell → .\\RoguePotato.exe ...[/yellow]")
                console.print("[yellow]     Token steal:   use post/windows/escalate/getsystem (technique 3)[/yellow]\n")
                self.check_hunter()
            else:
                technique = "Technique 1 (Named Pipe Impersonation)" if not has_edr else "Technique 3 (Token Duplication)"
                console.print(f"[bold green][+] getsystem — Got system via {technique}.[/bold green]")
                console.print("[bold green][+] NT AUTHORITY\\SYSTEM[/bold green]")
                console.print(f"[bright_black]  → Privesc Vector: SeImpersonatePrivilege[/bright_black]\n")

        elif action == "hashdump":
            if is_win:
                self.log_event("CREDENTIAL_DUMP", f"hashdump on {node['hostname']}", "HIGH")
                console.print("[bold yellow]Dumping SAM/NTDS hashes...[/bold yellow]")
                time.sleep(1)
                is_dc = node.get("hostname", "") == "corp-dc"
                if is_dc:
                    console.print("[bright_black]  [DC] SAM local accounts:[/bright_black]")
                    console.print("  Administrator(local):500:aad3b435b51404eeaad3b435b51404ee:"
                                  "[bold red]31d6cfe0d16ae931b73c59d7e0c089c0[/bold red]:::")
                    console.print("\n[yellow]  [!] DC domain hashes are in NTDS.dit, NOT SAM.[/yellow]")
                    console.print("[bright_black]  → Use: mimikatz lsadump::dcsync /domain:AMNESIA.LOCAL /user:Administrator[/bright_black]")
                    console.print("[bright_black]  → Or:  secretsdump.py AMNESIA.LOCAL/svc_backup:Backup@123@10.10.10.5[/bright_black]\n")
                else:
                    console.print("  Administrator:500:aad3b435b51404eeaad3b435b51404ee:"
                                  "[bold red]8846f7eaee8fb117ad06bdd830b7586c[/bold red]:::")
                    console.print("  j.smith:1001:aad3b435b51404eeaad3b435b51404ee:"
                                  "[bold red]7ce21f17c0aee7fb9ceba532d0546ad6[/bold red]:::")
                    console.print("  svc_scada:1003:aad3b435b51404eeaad3b435b51404ee:"
                                  "[bold red]e19ccf75ee54e06b06a5907af13cef42[/bold red]:::")
                    console.print("[bright_black]  → crack NTLM: hashcat -m 1000 ntlm.txt rockyou.txt[/bright_black]\n")
            else:
                console.print("[red][-] Windows-only. Linux-ზე: cat /etc/shadow (root-ად)[/red]")

        elif action == "mimikatz":
            if not is_win:
                console.print("[red][-] mimikatz Windows-only.[/red]"); return
            sub = parts[1] if len(parts) > 1 else ""
            self.log_event("MIMIKATZ", f"{sub} on {node['hostname']}", "CRIT")

            if "sekurlsa" in sub or "logonpasswords" in sub:
                with Progress(SpinnerColumn(), TextColumn("[yellow]sekurlsa::logonpasswords..."),
                              transient=True) as p:
                    p.add_task("", total=None); time.sleep(1.5)
                self.alert_level += 20
                console.print("[bold yellow]Authentication Id : 0 ; 123456 (00000000:0001e240)[/bold yellow]")
                console.print("Session           : Interactive from 1")
                console.print("UserName          : Administrator")
                console.print("Domain            : AMNESIA")
                console.print(f"  * Username : Administrator")
                console.print(f"  * [bold red]Password : Admin@2026![/bold red]")
                console.print(f"  * NTLM     : [bold red]8846f7eaee8fb117ad06bdd830b7586c[/bold red]\n")
                console.print("[bold red][!] Event ID 10 (LSASS Memory Read) — Blue Team WILL see this![/bold red]")
                console.print("[bright_black]  SECURITY FINDING: LSASS memory contains plaintext credentials (WDigest enabled)[/bright_black]\n")
                self.check_hunter()

            elif "dcsync" in sub or "lsadump" in sub:
                domain_arg = next((p for p in parts if "AMNESIA" in p.upper()), "AMNESIA.LOCAL")
                user_arg   = next((p.split(":")[-1] for p in parts if "/user:" in p.lower()), "Administrator")
                with Progress(SpinnerColumn(), TextColumn("[yellow]DCSync — pulling replication data..."),
                              transient=True) as p:
                    p.add_task("", total=None); time.sleep(2.0)
                self.alert_level += 25
                self.log_event("DCSYNC", f"lsadump::dcsync /domain:{domain_arg} /user:{user_arg}", "CRIT")
                console.print(f"[bold red][!] DCSync generates Windows Event 4662 — Blue Team WILL see this![/bold red]\n")
                console.print(f"[bold cyan]Object  : CN={user_arg},CN=Users,DC=AMNESIA,DC=LOCAL[/bold cyan]")
                console.print(f"[bold cyan]Object Security ID : S-1-5-21-...-500[/bold cyan]\n")
                hashes = {
                    "Administrator": ("8846f7eaee8fb117ad06bdd830b7586c", "Admin@2026!"),
                    "svc_backup":    ("a87f3a337d73085c45f9416be5787d86", "Backup@123"),
                    "svc_scada":     ("e19ccf75ee54e06b06a5907af13cef42", "Sc4da@Admin!"),
                    "krbtgt":        ("819af826bb148e603acbb79391b8955",  "[uncrackable — Golden Ticket possible]"),
                }
                h, p_txt = hashes.get(user_arg, ("<hash>", "<unknown>"))
                console.print(f"  Hash NTLM: [bold red]{h}[/bold red]")
                console.print(f"  [bright_black]crack: {p_txt}[/bright_black]")
                console.print(f"\n[bright_black]  save hashes.txt then: hashcat -m 1000 hashes.txt rockyou.txt[/bright_black]")
                console.print(f"  {self._alert_bar()}\n")
                self._mark_obj("DCSync — Domain Admin ჰეშები მოპოვებულია", f"DCSync /user:{user_arg}")
                self.check_hunter()
            else:
                console.print("[bright_black]mimikatz commands:[/bright_black]")
                console.print("  [cyan]mimikatz sekurlsa::logonpasswords[/cyan]          — LSASS dump  (+20% alert)")
                console.print("  [cyan]mimikatz lsadump::dcsync /domain:AMNESIA.LOCAL /user:Administrator[/cyan]  (+25%)")
                console.print("  [cyan]mimikatz lsadump::dcsync /domain:AMNESIA.LOCAL /user:krbtgt[/cyan]  — Golden Ticket\n")

        elif action == "kerberoast":
            self.log_event("KERBEROAST", f"TGS request on {node['hostname']}", "HIGH")
            with Progress(SpinnerColumn(), TextColumn("[yellow]Requesting TGS tickets for SPNs..."),
                          transient=True) as p:
                p.add_task("", total=None); time.sleep(1.8)
            self.alert_level += 8
            console.print("[bold green][+] SPN accounts found:[/bold green]")
            spn_users = [u for u in self.ad_domain.get("users", []) if u.get("spn")]
            for u in spn_users:
                console.print(f"  [cyan]{u['name']}[/cyan]  SPN: {u['spn']}")
                console.print(f"    $krb5tgs$23$*{u['name']}$AMNESIA.LOCAL${u['spn']}*"
                               f"$a3f2c1...4e7d [bright_black](TGS-REP hash)[/bright_black]")
            console.print(f"\n[bright_black]  Saved: spn_hashes.txt[/bright_black]")
            console.print(f"[bold yellow]  → crack: hashcat -m 13100 spn_hashes.txt rockyou.txt[/bold yellow]")
            console.print(f"[bright_black]         (mode 13100 = Kerberos TGS-REP, NOT 1000/NTLM)[/bright_black]")
            console.print(f"  {self._alert_bar()}\n")
            self.check_hunter()

        elif action == "asreproast":
            self.log_event("ASREP_ROAST", f"AS-REP roasting on {node['hostname']}", "HIGH")
            with Progress(SpinnerColumn(), TextColumn("[yellow]Checking accounts without preauth..."),
                          transient=True) as p:
                p.add_task("", total=None); time.sleep(1.5)
            self.alert_level += 5
            console.print("[bold green][+] AS-REP Roastable accounts (DONT_REQUIRE_PREAUTH):[/bold green]")
            console.print("  [cyan]m.jones[/cyan]  — Domain Users")
            console.print("    $krb5asrep$23$m.jones@AMNESIA.LOCAL:a8f3c2...9e4b  [bright_black](AS-REP hash)[/bright_black]")
            console.print(f"\n[bright_black]  Saved: asrep_hashes.txt[/bright_black]")
            console.print(f"[bold yellow]  → crack: hashcat -m 18200 asrep_hashes.txt rockyou.txt[/bold yellow]")
            console.print(f"[bright_black]         (mode 18200 = Kerberos AS-REP, different from TGS-REP!)[/bright_black]")
            console.print(f"  {self._alert_bar()}\n")
            self.check_hunter()

        elif action == "persistence":
            self._cmd_persistence_registry(node, is_win, parts)

        elif action == "upload" and len(parts) > 1:
            fname = parts[1]
            self.log_event("FILE_UPLOAD", f"upload {fname} → {node['hostname']}", "HIGH")
            self.alert_level += 3
            with Progress(SpinnerColumn(), BarColumn(), TaskProgressColumn(),
                          TextColumn(f"[cyan]Uploading {fname}..."), transient=True) as p:
                t = p.add_task("", total=100)
                while not p.finished:
                    p.update(t, advance=random.randint(20, 40)); time.sleep(0.1)
            dest = ("C:\\Windows\\Temp\\" if is_win else "/tmp/") + fname
            console.print(f"[bold green][+] {fname} → {dest}[/bold green]")
            console.print(f"[bright_black]  Alert +3%  |  OPSEC: Temp folder-ი EDR-ს მონიტორინგ ქვეშ![/bright_black]\n")
            self.check_hunter()

        elif action == "download" and len(parts) > 1:
            fname = parts[1]
            self.log_event("FILE_DOWNLOAD", f"download {fname} from {node['hostname']}", "HIGH")
            self.alert_level += 5
            with Progress(SpinnerColumn(), BarColumn(), TaskProgressColumn(),
                          TextColumn(f"[cyan]Downloading {fname}..."), transient=True) as p:
                t = p.add_task("", total=100)
                while not p.finished:
                    p.update(t, advance=random.randint(15, 35)); time.sleep(0.1)
            console.print(f"[bold green][+] {fname} → /home/anonimus/loot/{fname}[/bold green]")
            console.print(f"[bright_black]  Alert +5%  |  გამოყენება: hashcat / impacket / strings[/bright_black]\n")
            if fname not in self.loot_files:
                self.loot_files.append(fname)
            if fname in ("ntds.dit", "ntds.dit.bak", "SYSTEM.hive"):
                console.print(f"[bold yellow]  → impacket-secretsdump -ntds {fname} -system SYSTEM.hive LOCAL[/bold yellow]\n")
            self.check_hunter()

        elif action == "exfil":
            self._cmd_exfil(node, parts)

        elif action == "migrate" and len(parts) > 1:
            target_pid = parts[1]
            if not is_win:
                console.print("[red][-] migrate Windows-only command.[/red]"); return
            self.log_event("PROCESS_MIGRATE", f"migrate PID {target_pid} on {node['hostname']}", "HIGH")
            procs_win  = {
                "512":  "svchost.exe",
                "640":  "lsass.exe",
                "1204": "wincc.exe",
                "3344": "cmd.exe",
                "820":  "explorer.exe",
                "1508": "spoolsv.exe",
            }
            proc_name = procs_win.get(target_pid, f"PID:{target_pid}")
            with Progress(SpinnerColumn(), TextColumn(f"[yellow]Migrating to {proc_name}..."),
                          transient=True) as p:
                p.add_task("", total=None); time.sleep(1.0)
            if target_pid == "640":
                self.alert_level += 20
                console.print(f"[bold red][-] lsass.exe migration blocked — EDR detected PROCESS_ALL_ACCESS on LSASS![/bold red]")
                console.print("[yellow]  → OPSEC: explorer.exe (PID 820) ან svchost.exe (PID 512) გამოიყენე[/yellow]\n")
                self.check_hunter()
            else:
                self.alert_level += 4
                console.print(f"[bold green][+] Successfully migrated to {proc_name} (PID {target_pid})[/bold green]")
                console.print(f"[bright_black]  Meterpreter now inside {proc_name}  |  Alert +4%[/bright_black]\n")

        elif action == "help":
            self._meterpreter_help()

        else:
            console.print(f"[bright_black][-] Unknown meterpreter command: {action}[/bright_black]")
            console.print("[bright_black]  Type 'help' for available commands.[/bright_black]")

    def _cmd_persistence_registry(self, node, is_win, parts):
        """persistence [-X] [-i <seconds>] [-p <port>] [-r <lhost>]"""
        if not is_win:
            console.print("[red][-] persistence module is Windows-only.[/red]"); return
        lhost = self.msf_options.get("LHOST", "10.0.2.15")
        lport = self.msf_options.get("LPORT", "4444")
        for i, p in enumerate(parts):
            if p == "-r" and i+1 < len(parts): lhost = parts[i+1]
            if p == "-p" and i+1 < len(parts): lport = parts[i+1]

        self.log_event("PERSISTENCE_INSTALL", f"Registry Run Key on {node['hostname']}", "CRIT")
        self.alert_level += 8
        with Progress(SpinnerColumn(), TextColumn("[yellow]Installing persistence..."),
                      transient=True) as p:
            p.add_task("", total=None); time.sleep(1.2)
        console.print("[bold green][+] Running Persistence as: NT AUTHORITY\\SYSTEM[/bold green]")
        console.print(f"[bold green][+] Persistence installed to registry:[/bold green]")
        console.print(f"    HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        console.print(f"    Value: WindowsUpdate → C:\\Windows\\Temp\\update.exe")
        console.print(f"    Callback: {lhost}:{lport} every 60s\n")
        console.print(f"[bold red][!] OPSEC: Registry Run Key — Event ID 13 (Registry Value Set)[/bold red]")
        console.print(f"[yellow]  → Stealthier options:[/yellow]")
        console.print(f"[yellow]     Scheduled task:   schtasks /create ... (+6% vs +8%)[/yellow]")
        console.print(f"[yellow]     WMI subscription: wmic subscription (+4%, Hunter-ს ძნელად ხედავს)[/yellow]")
        console.print(f"[yellow]     Service install:  run post/windows/manage/persistence_exe (+12%)[/yellow]\n")
        console.print(f"  {self._alert_bar()}\n")
        key = "Registry Run Key"
        if key not in self.persistence_done:
            self.persistence_done.append(key)
        self._mark_obj("Persistence — Hunter-ის გვერდის ავლა", "Registry Run Key installed")
        self.check_hunter()

    def _cmd_persistence_service(self, node, is_win):
        """run post/windows/manage/persistence_exe — installs as Windows service"""
        if not is_win:
            console.print("[red][-] Service persistence is Windows-only.[/red]"); return
        self.log_event("PERSISTENCE_SERVICE", f"Service install on {node['hostname']}", "CRIT")
        self.alert_level += 12
        with Progress(SpinnerColumn(), TextColumn("[yellow]Creating persistent service..."),
                      transient=True) as p:
            p.add_task("", total=None); time.sleep(1.5)
        console.print("[bold green][+] post/windows/manage/persistence_exe completed[/bold green]")
        console.print("    Service name: WindowsUpdateSvc")
        console.print("    Binary path:  C:\\Windows\\System32\\svchost32.exe")
        console.print("    Start type:   Automatic (SYSTEM)\n")
        console.print(f"[bold red][!] OPSEC: Service install = Event ID 7045 — high visibility![/bold red]")
        console.print(f"[yellow]  → Blue Team SOC sees this immediately via server.py[/yellow]\n")
        console.print(f"  {self._alert_bar()}\n")
        key = "Windows Service (persistence_exe)"
        if key not in self.persistence_done:
            self.persistence_done.append(key)
        self._mark_obj("Persistence — Hunter-ის გვერდის ავლა", "Service persistence installed")
        self.check_hunter()

    def _cmd_exfil(self, node, parts):
        """exfil <filename> [--method https|dns]"""
        fname  = parts[1] if len(parts) > 1 else "data.zip"
        method = "https"
        for i, p in enumerate(parts):
            if p == "--method" and i+1 < len(parts): method = parts[i+1]

        if method == "dns":
            self.alert_level += 2
            self.log_event("EXFIL_DNS", f"DNS tunnel exfil: {fname} → {self.c2_server}", "CRIT")
            with Progress(SpinnerColumn(), BarColumn(), TaskProgressColumn(),
                          TextColumn("[cyan]DNS tunnel exfil..."), transient=True) as p:
                t = p.add_task("", total=100)
                while not p.finished:
                    p.update(t, advance=random.randint(5, 10)); time.sleep(0.15)
            console.print(f"[bold green][+] {fname} exfiltrated via DNS TXT queries[/bold green]")
            console.print(f"[bright_black]    C2: {self.c2_server}  |  Port: 53  |  Alert +2%[/bright_black]")
            console.print(f"[bright_black]    OPSEC: DNS = firewall bypass — port 53 almost always open[/bright_black]")
            console.print(f"[bright_black]    IDS: DNS tunneling hard to detect without DPI inspection[/bright_black]\n")
        else:
            self.alert_level += 3
            self.log_event("EXFIL_HTTPS", f"HTTPS exfil: {fname} → {self.c2_server}", "CRIT")
            with Progress(SpinnerColumn(), BarColumn(), TaskProgressColumn(),
                          TextColumn(f"[cyan]Uploading to C2 {self.c2_server}..."), transient=True) as p:
                t = p.add_task("", total=100)
                while not p.finished:
                    p.update(t, advance=random.randint(10, 20)); time.sleep(0.12)
            size = random.randint(8000, 150000)
            console.print(f"[bold green][+] {size:,} bytes exfiltrated → https://{self.c2_server}/upload[/bold green]")
            console.print(f"[bright_black]    OPSEC: HTTPS encrypted — IDS ვერ ხედავს payload-ს[/bright_black]")
            console.print(f"[bright_black]    Alert +3%  |  compare: direct download +5%[/bright_black]\n")

        if fname not in self.loot_files:
            self.loot_files.append(f"[C2]{fname}")
        self._mark_obj("Exfiltration Alert 40%-ის გარეშე", f"{method.upper()} exfil: {fname}")
        console.print(f"  {self._alert_bar()}\n")
        self.check_hunter()

    def interactive_shell(self, node):
        is_win    = "Windows" in node["os"]
        zone      = node["zone"]
        prompt_ch = ">" if is_win else "#"
        target_ip = self.compromised.get(self.active_session, "")

        default_dirs = {
            "CORP": ("C:\\Users\\Administrator\\Desktop" if is_win else "/"),
            "OT":   ("C:\\Users\\Administrator\\Desktop" if is_win else "/"),
            "DMZ":  ("/var/www/html" if not is_win else "C:\\"),
        }
        cwd = default_dirs.get(zone, "/")

        while True:
            try:
                raw = console.input(
                    f"[bold red]shell[/bold red] [white]{node['hostname']}[/white] "
                    f"[cyan]{cwd}[/cyan]{prompt_ch} "
                ).strip()
            except (KeyboardInterrupt, EOFError):
                break
            if not raw:
                continue
            self.shell_history.append(raw)
            if raw.lower() in ("exit", "quit"):
                console.print("[*] Exiting shell → back to meterpreter.")
                break

            parts = raw.split()
            cmd   = parts[0].lower()

            if cmd == "cd":
                target = parts[1] if len(parts) > 1 else ("C:\\" if is_win else "/")
                if target in ("..", "..\\", "../"):
                    sep = "\\" if is_win else "/"
                    cwd = cwd.rsplit(sep, 1)[0] or ("C:\\" if is_win else "/")
                elif target.startswith(("C:", "/")):
                    cwd = target
                else:
                    sep = "\\" if is_win else "/"
                    cwd = cwd.rstrip(sep) + sep + target

            elif cmd in ("ls", "dir"):
                fs_zone = FS.get(zone, FS["DMZ"])
                entries = fs_zone.get(cwd) or fs_zone.get(cwd.rstrip("/\\"))
                if entries:
                    for e in entries:
                        color = "cyan" if "." not in e else "white"
                        console.print(f"  [{color}]{e}[/{color}]")
                else:
                    console.print("[bright_black](empty directory)[/bright_black]")

            elif cmd in ("cat", "type") and len(parts) > 1:
                fname = parts[1]
                if fname in FILE_CONTENT:
                    self.log_event("FILE_READ", f"{node['hostname']}:{cwd}/{fname}", "HIGH")
                    console.print(Panel(
                        FILE_CONTENT[fname],
                        title=f"[white]► {fname}[/white]",
                        border_style="bright_black",
                    ))
                    if fname == "config.php.bak":
                        self._mark_obj("DB კრედიტების მოპოვება", "DB credentials found (config.php.bak)")
                    if fname == "root.txt":
                        self._mark_obj("SCADA HMI-ზე წვდომა", "root.txt read on SCADA HMI")
                        self.log_event("FLAG_CAPTURED", "root.txt read — mission complete!", "CRIT")
                        console.print(Rule("[bold green]🎉  MISSION COMPLETE — Full Chain Compromised!  🎉[/bold green]"))
                        self._victory_summary()
                    if fname == "emergency_codes.txt":
                        self.log_event("ICS_DATA_EXFIL",
                                       "Physical emergency codes accessed on scada-hmi", "CRIT")
                        self._mark_obj("Exfiltration Alert 40%-ის გარეშე", "ICS codes exfiltrated")
                else:
                    console.print(f"[red]{cmd}: {fname}: No such file or directory[/red]")

            elif cmd == "find" and len(parts) > 1:
                keyword  = parts[-1].lower()
                fs_zone  = FS.get(zone, FS["DMZ"])
                found    = []
                for path, entries in fs_zone.items():
                    for e in entries:
                        if keyword in e.lower():
                            sep = "\\" if is_win else "/"
                            found.append(f"{path}{sep}{e}")
                if found:
                    for f in found:
                        console.print(f"  [cyan]{f}[/cyan]")
                else:
                    console.print("[bright_black](nothing found)[/bright_black]")

            elif cmd == "whoami":
                console.print("[bold green]nt authority\\system[/bold green]"
                              if is_win else "[bold green]root[/bold green]")

            elif cmd == "id" and not is_win:
                console.print("uid=0(root) gid=0(root) groups=0(root)")

            elif cmd in ("ifconfig", "ipconfig"):
                console.print(f"{'eth0' if not is_win else 'Ethernet'}: [cyan]{target_ip}[/cyan]")

            elif cmd == "uname" and not is_win:
                console.print(f"Linux {node['hostname']} 5.15.0-1-amd64 #1 SMP")

            elif cmd == "systeminfo" and is_win:
                console.print(
                    f"Host Name:                 {node['hostname']}\n"
                    f"OS Name:                   {node['os']}\n"
                    f"OS Version:                6.1.7601 Service Pack 1 Build 7601\n"
                    f"Domain:                    AMNESIA.LOCAL\n"
                    f"Logon Server:              \\\\corp-dc\n"
                    f"Hotfix(s):                 [bold red]0 Hotfix(es) Installed.[/bold red]"
                )

            elif cmd == "net" and is_win and len(parts) > 1:
                sub = parts[1].lower()
                if sub == "user" and len(parts) > 2 and "/domain" in raw.lower():
                    uname = parts[2]
                    user_info = {
                        "Administrator": ("Domain Admins, Enterprise Admins", "Never"),
                        "j.smith":       ("Helpdesk, Domain Users",           "2027-01-15"),
                        "svc_backup":    ("Backup Operators, Domain Users",    "Never"),
                        "svc_scada":     ("SCADA_Operators, Domain Users",     "Never"),
                        "m.jones":       ("Domain Users",                      "2027-06-01"),
                    }
                    if uname in user_info:
                        grps, exp = user_info[uname]
                        console.print(f"User name                    {uname}")
                        console.print(f"Account active               Yes")
                        console.print(f"Password expires             {exp}")
                        console.print(f"Global Group memberships     {grps}")
                    else:
                        console.print(f"[red]The user name could not be found.[/red]")
                elif sub == "group" and "/domain" in raw.lower():
                    gname = parts[2] if len(parts) > 2 else ""
                    groups_info = {
                        "domain admins":   ["Administrator"],
                        "helpdesk":        ["j.smith"],
                        "backup operators":["svc_backup"],
                        "scada_operators": ["svc_scada"],
                        "domain users":    ["j.smith", "m.jones", "svc_web", "svc_backup", "svc_scada"],
                    }
                    key = gname.lower().strip('"')
                    members = groups_info.get(key, [])
                    if members:
                        console.print(f"Group name     {gname}")
                        console.print(f"Members\n")
                        for m in members:
                            console.print(f"  {m}")
                    else:
                        console.print(f"[bright_black]Group '{gname}' not found or empty.[/bright_black]")
                else:
                    console.print("[bright_black]net: user /domain <user>  |  group /domain <group>[/bright_black]")

            elif cmd == "reg" and is_win:
                if "run" in raw.lower():
                    if "WindowsUpdate" in "".join(self.persistence_done):
                        console.print("[bold red]HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run[/bold red]")
                        console.print("  WindowsUpdate    REG_SZ    C:\\Windows\\Temp\\update.exe")
                    else:
                        console.print("[bright_black]HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run[/bright_black]")
                        console.print("[bright_black]  (No entries)[/bright_black]")
                else:
                    console.print("[bright_black]reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run[/bright_black]")

            elif cmd == "netstat":
                if is_win:
                    console.print(f"  Proto  Local Address          Foreign Address        State")
                    console.print(f"  TCP    {target_ip}:445       10.0.2.15:51234       ESTABLISHED")
                    console.print(f"  TCP    {target_ip}:3389      10.0.2.15:4444        ESTABLISHED")
                    console.print(f"  [bold red]TCP    {target_ip}:49152    10.0.2.15:4444        ESTABLISHED[/bold red]  [bright_black]← Meterpreter![/bright_black]")
                    console.print(f"[bright_black]  OPSEC: Meterpreter connection visible in netstat — Blue Team can see PID[/bright_black]\n")
                else:
                    console.print(f"  tcp  0  0  {target_ip}:8080   10.0.2.15:4444   ESTABLISHED")
                    console.print(f"  [bold red]tcp  0  0  {target_ip}:45123  10.0.2.15:4444   ESTABLISHED[/bold red]  [bright_black]← shell[/bright_black]")

            elif cmd == "arp":
                console.print(f"  Interface: {target_ip}")
                console.print(f"  Internet Address      Physical Address      Type")
                if zone == "DMZ":
                    console.print(f"  [yellow]192.168.10.10[/yellow]         aa:bb:cc:01:02:03     dynamic  [bright_black](db-server)[/bright_black]")
                    console.print(f"  [yellow]192.168.10.20[/yellow]         aa:bb:cc:04:05:06     dynamic  [bright_black](dev-server)[/bright_black]")
                    console.print(f"  [yellow]10.10.10.5[/yellow]            aa:bb:cc:07:08:09     dynamic  [bright_black](corp-dc — dual-homed route)[/bright_black]")
                elif zone == "CORP":
                    console.print(f"  [yellow]10.10.10.15[/yellow]           aa:bb:cc:0a:0b:0c     dynamic  [bright_black](corp-file)[/bright_black]")
                    console.print(f"  [yellow]10.10.10.30[/yellow]           aa:bb:cc:0d:0e:0f     dynamic  [bright_black](corp-mail)[/bright_black]")
                    console.print(f"  [yellow]172.16.5.10[/yellow]           aa:bb:cc:10:11:12     dynamic  [bright_black](scada-hmi — OT route)[/bright_black]")
                elif zone == "OT":
                    console.print(f"  [yellow]172.16.5.20[/yellow]           aa:bb:cc:13:14:15     dynamic  [bright_black](plc-controller)[/bright_black]")

            elif cmd in ("ps", "tasklist"):
                procs = (
                    ["svchost.exe    PID:512   SYSTEM",
                     "lsass.exe      PID:640   SYSTEM",
                     "wincc.exe      PID:1204  SYSTEM",
                     "spoolsv.exe    PID:1508  SYSTEM",
                     "explorer.exe   PID:820   Administrator",
                     "cmd.exe        PID:3344  Administrator"]
                    if is_win else
                    ["apache2  PID:812   www-data",
                     "mysqld   PID:1024  mysql",
                     "sshd     PID:2204  root",
                     "sh       PID:4011  www-data"]
                )
                for p in procs:
                    console.print(f"  {p}")

            elif cmd == "history":
                for i, h in enumerate(self.shell_history[-20:], 1):
                    console.print(f"  {i:3}  {h}")

            elif cmd == "schtasks" and is_win:
                if "/create" in raw.lower():
                    task_name = "WinUpdate"
                    for i, p in enumerate(parts):
                        if p.lower() == "/tn" and i+1 < len(parts):
                            task_name = parts[i+1]
                    self.log_event("PERSISTENCE_SCHTASK", f"Scheduled task: {task_name} on {node['hostname']}", "CRIT")
                    self.alert_level += 6
                    console.print(f"[bold green]SUCCESS: The scheduled task \"{task_name}\" has been successfully created.[/bold green]")
                    console.print(f"[bright_black]  Task: {task_name}  |  Trigger: ONLOGON  |  Run As: SYSTEM[/bright_black]")
                    console.print(f"[yellow]  OPSEC: Event ID 4698 (Scheduled Task Created) — less visible than service[/yellow]")
                    console.print(f"  {self._alert_bar()}  [bright_black](+6%)[/bright_black]\n")
                    key = f"Scheduled Task ({task_name})"
                    if key not in self.persistence_done:
                        self.persistence_done.append(key)
                    self._mark_obj("Persistence — Hunter-ის გვერდის ავლა", f"Scheduled task: {task_name}")
                    self.check_hunter()
                elif "/query" in raw.lower():
                    if self.persistence_done:
                        console.print(f"[bold cyan]TaskName              Status     Next Run Time[/bold cyan]")
                        for p in self.persistence_done:
                            if "Scheduled Task" in p:
                                console.print(f"  {p:<30} Ready      On logon")
                    else:
                        console.print("[bright_black](No custom scheduled tasks)[/bright_black]")
                else:
                    console.print("[bright_black]schtasks /create /tn <name> /tr <cmd> /sc onlogon /ru SYSTEM[/bright_black]")
                    console.print("[bright_black]schtasks /query[/bright_black]")

            elif cmd == "wmic" and is_win:
                if "process call create" in raw.lower():
                    target_node_wmi = parts[2] if len(parts) > 2 else ""
                    self.log_event("WMI_EXEC", f"WMI process create on {target_node_wmi}", "HIGH")
                    self.alert_level += 8
                    console.print(f"[bold green][+] WMI process created on {target_node_wmi}[/bold green]")
                    console.print(f"[bright_black]  Executing via Win32_Process::Create (Event ID 4688)[/bright_black]")
                    console.print(f"[yellow]  OPSEC: WMI exec (+8%) stealthier than PsExec (+15%)[/yellow]")
                    console.print(f"[yellow]  → Stealthiest: WMI event subscription (+4%)[/yellow]\n")
                    self.check_hunter()
                elif "subscription" in raw.lower() or "eventfilter" in raw.lower():
                    self.log_event("PERSISTENCE_WMI", f"WMI subscription on {node['hostname']}", "CRIT")
                    self.alert_level += 4
                    console.print("[bold green][+] WMI permanent event subscription created[/bold green]")
                    console.print("    EventFilter:     __EventFilter (ProcessCreation)")
                    console.print("    EventConsumer:   CommandLineEventConsumer → update.exe")
                    console.print("    Binding:         __FilterToConsumerBinding\n")
                    console.print(f"[yellow]  OPSEC: WMI subscription (+4%) = stealthiest persistence[/yellow]")
                    console.print(f"[yellow]  Hunter ამ ვექტორს ნელ-ნელა ხედავს (behavioral detection only)[/yellow]\n")
                    console.print(f"  {self._alert_bar()}  [bright_black](+4%)[/bright_black]\n")
                    key = "WMI Subscription (stealthiest)"
                    if key not in self.persistence_done:
                        self.persistence_done.append(key)
                    self._mark_obj("Persistence — Hunter-ის გვერდის ავლა", "WMI event subscription")
                    self.check_hunter()
                else:
                    console.print("[bright_black]wmic /node:<ip> /user:<u> /password:<p> process call create \"cmd.exe\"[/bright_black]")
                    console.print("[bright_black]wmic eventfilter ...  (WMI persistence)[/bright_black]")

            elif cmd == "curl" and not is_win:
                if "-X POST" in raw or "--data" in raw or "-F" in raw:
                    self.log_event("EXFIL_CURL", f"curl POST to C2: {self.c2_server}", "CRIT")
                    self.alert_level += 3
                    target_url = next((p for p in parts if p.startswith("http")), f"https://{self.c2_server}/upload")
                    file_arg   = ""
                    for i, p in enumerate(parts):
                        if p == "-F" and i+1 < len(parts):
                            file_arg = parts[i+1]
                    console.print(f"[bright_black]*   Trying {target_url}...[/bright_black]")
                    time.sleep(0.5)
                    console.print(f"[bright_black]> POST /upload HTTP/1.1[/bright_black]")
                    size = random.randint(5000, 80000)
                    console.print(f"[bold green]< HTTP/1.1 200 OK[/bold green]")
                    console.print(f"[bold green][+] {size:,} bytes exfiltrated → {target_url}[/bold green]")
                    console.print(f"[bright_black]  OPSEC: HTTPS encrypted — IDS ვერ ხედავს payload-ს  |  Alert +3%[/bright_black]\n")
                    self._mark_obj("Exfiltration Alert 40%-ის გარეშე", f"curl HTTPS exfil to {self.c2_server}")
                    self.check_hunter()
                else:
                    target_url = parts[1] if len(parts) > 1 else ""
                    console.print(f"[bright_black]curl {target_url}[/bright_black]")
                    console.print("[bright_black]HTTP/1.1 200 OK[/bright_black]\n")

            elif cmd == "modbus" and zone == "OT":
                self._shell_modbus(parts, raw)

            elif cmd == "s7client" and zone == "OT":
                self._shell_s7client(parts, raw)

            elif cmd == "iodine" and not is_win:
                self.log_event("EXFIL_DNS_TUNNEL", f"iodine DNS tunnel established", "CRIT")
                self.alert_level += 2
                tunnel_domain = parts[-1] if len(parts) > 1 else "tunnel.geoforum.ge"
                console.print(f"[*] Connecting to {tunnel_domain}...")
                time.sleep(0.8)
                console.print(f"[bold green][+] Connection established — DNS tunnel active[/bold green]")
                console.print(f"[bright_black]    Interface: dns0  MTU: 1130  Server: {self.c2_server}[/bright_black]")
                console.print(f"[bright_black]    OPSEC: DNS tunnel via port 53 — firewall bypass, very hard to detect[/bright_black]")
                console.print(f"    {self._alert_bar()}  [bright_black](+2%)[/bright_black]\n")
                self.check_hunter()

            else:
                console.print(f"[bright_black]{cmd}: command not found (or not simulated)[/bright_black]")
                if zone == "OT" and cmd not in ("cd", "ls", "dir", "cat", "type", "find", "whoami"):
                    console.print(f"[bright_black]  OT commands: modbus · s7client · dir · type · cd[/bright_black]")

    def _shell_modbus(self, parts, raw):
        sub        = parts[1] if len(parts) > 1 else ""
        target_plc = parts[2] if len(parts) > 2 else "172.16.5.20"
        self.log_event("ICS_MODBUS", f"modbus {sub} {target_plc}", "CRIT")
        self.alert_level += 5
        if sub == "read_coils":
            start = parts[3] if len(parts) > 3 else "0"
            count = parts[4] if len(parts) > 4 else "10"
            console.print(f"[*] Modbus Read Coils — {target_plc}:{502} addr={start} count={count}")
            time.sleep(0.5)
            coils = ["ON" if random.random() > 0.4 else "OFF" for _ in range(int(count))]
            for i, c in enumerate(coils):
                color = "green" if c == "ON" else "bright_black"
                console.print(f"  Coil[{int(start)+i:03d}]: [{color}]{c}[/{color}]")
            console.print(f"[bright_black]  ICS FINDING: Modbus TCP has no authentication — any host can read/write coils (CWE-306)[/bright_black]\n")
        elif sub == "write_coil":
            addr  = parts[3] if len(parts) > 3 else "0"
            value = parts[4] if len(parts) > 4 else "1"
            console.print(f"[bold red][!] Writing Coil[{addr}] = {value} on {target_plc}[/bold red]")
            time.sleep(0.6)
            console.print(f"[bold red][+] Coil[{addr}] forced to {'ON' if value=='1' else 'OFF'} — physical output changed! (SIMULATION)[/bold red]")
            console.print(f"[bold red]    ⚠  სიმულაცია: რეალობაში ეს ფიზიკურ პროცესს შეცვლიდა![/bold red]\n")
            self._mark_obj("SCADA HMI-ზე წვდომა", "Modbus coil write — OT physical access confirmed")
        elif sub == "read_registers":
            console.print(f"[*] Modbus Read Holding Registers — {target_plc}")
            time.sleep(0.5)
            labels = ["Temp_Sensor_1", "Pressure_Main", "Flow_Rate", "Valve_Pos", "RPM_Turbine"]
            for i in range(5):
                val = random.randint(0, 32767)
                console.print(f"  HR[{i:03d}]: {val:>6}   [bright_black]({labels[i]})[/bright_black]")
            console.print(f"[bright_black]  Process values readable without authentication.[/bright_black]\n")
        else:
            console.print("[cyan]modbus commands: read_coils <ip> <start> <count> · write_coil <ip> <addr> <0|1> · read_registers <ip>[/cyan]")
        self.check_hunter()

    def _shell_s7client(self, parts, raw):
        target_plc = parts[1] if len(parts) > 1 else "172.16.5.20"
        action_arg = parts[2] if len(parts) > 2 else ""
        self.log_event("ICS_S7COMM", f"s7client {target_plc} {action_arg}", "CRIT")
        self.alert_level += 10
        if "--stop-cpu" in raw or "stop" in action_arg:
            console.print(f"[bold red][!] S7comm CPU STOP command → {target_plc}[/bold red]")
            time.sleep(1.0)
            console.print(f"[bold red][+] S7-400 CPU halted — PLC in STOP mode! (SIMULATION)[/bold red]")
            console.print(f"[bold red]    ⚠  სიმულაცია: რეალობაში ეს ინდუსტრიულ პროცესს გაჩერებდა![/bold red]")
            console.print(f"[bold red]    ⚠  OPSEC: S7comm CPU STOP = OT alarm + immediate Blue Team response![/bold red]\n")
            self._mark_obj("SCADA HMI-ზე წვდომა", "S7comm CPU STOP — OT full control confirmed")
        elif "--start-cpu" in raw or "start" in action_arg:
            console.print(f"[*] S7comm CPU START command → {target_plc}")
            time.sleep(0.8)
            console.print(f"[bold green][+] S7-400 CPU transitioned STOP → RUN mode[/bold green]")
            console.print(f"[yellow]  ⚠  Verify PLC logic integrity before restart in real environments![/yellow]\n")
        elif "--get-info" in raw or "info" in action_arg:
            console.print(f"[*] S7comm SZL read → {target_plc}")
            time.sleep(0.5)
            console.print("  Module: Siemens S7-400  Order: 6ES7 412-2XK07-0AB0")
            console.print("  Firmware: V5.6.4  Serial: S Q-C3V00123")
            console.print("  CPU State: RUN  Memory: 256KB  Protection: [bold red]NONE[/bold red]")
            console.print(f"[bright_black]  ICS FINDING: S7comm allows unauthenticated CPU info disclosure[/bright_black]\n")
        elif "--read-db" in raw:
            db_num = parts[3] if len(parts) > 3 else "1"
            console.print(f"[*] Reading Data Block DB{db_num} from {target_plc}")
            time.sleep(0.6)
            for i in range(4):
                console.print(f"  DB{db_num}.DBD{i*4}: {random.randint(0, 65535)}")
            console.print(f"[bright_black]  S7comm: unauthenticated DB read (CWE-306)[/bright_black]\n")
        else:
            console.print("[cyan]s7client <ip> --get-info · --stop-cpu · --start-cpu · --read-db <db#>[/cyan]")
        self.check_hunter()

    def cmd_proxychains(self, parts):
        if not self.msf_options.get("_socks_active"):
            console.print("[red][-] SOCKS proxy not running.[/red]")
            console.print("[yellow]  → MSF: use auxiliary/server/socks_proxy → set SRVPORT 1080 → run[/yellow]\n")
            return
        if len(parts) < 2:
            console.print("[bright_black]Usage: proxychains <nmap|curl|...> [args][/bright_black]"); return

        tool  = parts[1].lower()
        args  = parts[2:] if len(parts) > 2 else []
        port  = self.msf_options["_socks_active"]
        console.print(f"[bright_black][proxychains] Dynamic chain  127.0.0.1:{port}  OK[/bright_black]")

        if tool == "nmap":
            if not args:
                console.print("[red][-] proxychains nmap requires a target.[/red]"); return
            target_arg = args[-1]
            flags      = " ".join(args[:-1]) if len(args) > 1 else "-sT"
            if "-sS" in flags:
                console.print("[yellow][!] proxychains does not support SYN scan (-sS). Switching to -sT (TCP Connect).[/yellow]")
                console.print("[bright_black]    OPSEC: -sT through SOCKS is slower but required — proxy cannot forward raw packets.[/bright_black]")
                flags = flags.replace("-sS", "-sT")
            console.print(f"[bright_black][proxychains] Proxifying nmap {flags} {target_arg}[/bright_black]")
            self.cmd_nmap(target_arg, flags)
        elif tool == "curl":
            target_arg = args[0] if args else ""
            console.print(f"[bright_black][proxychains] curl {target_arg}[/bright_black]")
            console.print("[bright_black]HTTP/1.1 200 OK  (routed via SOCKS5)[/bright_black]\n")
        else:
            console.print(f"[bright_black][proxychains] Running: {tool} {' '.join(args)}[/bright_black]")
            console.print(f"[bright_black](simulation: {tool} proxied successfully)[/bright_black]\n")

    def cmd_hashcat(self, parts):
        mode     = "1000"
        hashfile = "hashes.txt"
        wordlist = "rockyou.txt"
        i = 1
        while i < len(parts):
            if parts[i] == "-m" and i + 1 < len(parts):
                mode = parts[i + 1]; i += 2
            elif parts[i].endswith((".txt", ".hash", ".kirbi", ".ntlm")) and hashfile == "hashes.txt":
                hashfile = parts[i]; i += 1
            elif parts[i] not in ("hashcat",) and not parts[i].startswith("-") and wordlist == "rockyou.txt":
                wordlist = parts[i]; i += 1
            else:
                i += 1

        MODE_INFO = {
            "1000":  ("NTLM",           "MD4(NT hash)         — from hashdump / DCSync / secretsdump"),
            "13100": ("Kerberos TGS-REP","$krb5tgs$23$*...   — from kerberoast (SPN accounts)"),
            "18200": ("Kerberos AS-REP", "$krb5asrep$23$...  — from asreproast (no preauth accounts)"),
            "5600":  ("NetNTLMv2",       "NTLMv2 challenge    — from Responder / relay captures"),
            "3200":  ("bcrypt",          "$2y$10$...          — from web app config files (very slow)"),
        }
        mode_name, mode_desc = MODE_INFO.get(mode, (f"Mode {mode}", ""))

        self.log_event("HASH_CRACK", f"hashcat -m {mode} {hashfile} {wordlist}", "HIGH")
        console.print(f"\n[bold red]hashcat[/bold red] [yellow](v6.2.6)[/yellow]  starting...")
        console.print(f"[bright_black]  Mode    : {mode} ({mode_name}) — {mode_desc}[/bright_black]")
        console.print(f"[bright_black]  Input   : {hashfile}[/bright_black]")
        console.print(f"[bright_black]  Wordlist: {wordlist}[/bright_black]\n")

        if mode == "1000":
            if "spn" in hashfile or "tgs" in hashfile:
                console.print("[bold red][!] Wrong mode for TGS hashes! Use: hashcat -m 13100[/bold red]\n"); return
            with Progress(SpinnerColumn(), BarColumn(), TaskProgressColumn(),
                          TextColumn("[cyan]Cracking NTLM..."), transient=True) as prog:
                t = prog.add_task("", total=100)
                while not prog.finished:
                    prog.update(t, advance=random.randint(15, 30)); time.sleep(0.12)
            cracked = [
                ("8846f7eaee8fb117ad06bdd830b7586c", "Administrator", "Admin@2026!"),
                ("7ce21f17c0aee7fb9ceba532d0546ad6", "j.smith",       "P@ssw0rd2026!"),
                ("a87f3a337d73085c45f9416be5787d86", "svc_backup",    "Backup@123"),
                ("e19ccf75ee54e06b06a5907af13cef42", "svc_scada",     "Sc4da@Admin!"),
            ]
            console.print("[bold green]Session complete![/bold green]\n")
            t2 = Table(title="Cracked NTLM Hashes", box=box.SIMPLE_HEAD, header_style="bold magenta")
            t2.add_column("Hash",     style="bright_black", width=34)
            t2.add_column("Username", style="cyan",         width=16)
            t2.add_column("Password", style="bold red",     width=20)
            for h, u, pw in cracked:
                t2.add_row(h, u, pw)
            console.print(t2)
            console.print("\n[bright_black]  Recovered: 4/4  |  Time: 00:00:07[/bright_black]")
            console.print("[bright_black]  svc_backup:Backup@123  → use for DCSync[/bright_black]")
            console.print("[bright_black]  svc_scada:Sc4da@Admin! → use for OT zone access[/bright_black]\n")
            self._mark_obj("Exfiltration Alert 40%-ის გარეშე", "NTLM hashes cracked offline")

        elif mode == "13100":
            if "ntlm" in hashfile or (hashfile == "hashes.txt" and "spn" not in hashfile):
                console.print("[yellow][!] Mode 13100 is for TGS-REP (Kerberoast). For NTLM use -m 1000.[/yellow]")
            with Progress(SpinnerColumn(), BarColumn(), TaskProgressColumn(),
                          TextColumn("[cyan]Cracking TGS-REP (Kerberoast)..."), transient=True) as prog:
                t = prog.add_task("", total=100)
                while not prog.finished:
                    prog.update(t, advance=random.randint(5, 15)); time.sleep(0.18)
            console.print("[bold green]Session complete![/bold green]\n")
            t2 = Table(title="Cracked TGS-REP (Kerberoast)", box=box.SIMPLE_HEAD, header_style="bold magenta")
            t2.add_column("Account",  style="cyan",     width=16)
            t2.add_column("SPN",      style="yellow",   width=30)
            t2.add_column("Password", style="bold red", width=20)
            t2.add_row("svc_backup", "MSSQLSvc/corp-db:1433", "Backup@123")
            t2.add_row("svc_scada",  "HOST/scada-hmi",        "Sc4da@Admin!")
            console.print(t2)
            console.print("\n[bright_black]  Recovered: 2/3  |  svc_web: NOT cracked (strong password)[/bright_black]")
            console.print("[bright_black]  → svc_backup cracked — use for DCSync PATH-2![/bright_black]\n")
            self._mark_obj("Exfiltration Alert 40%-ის გარეშე", "TGS-REP hashes cracked offline (-m 13100)")

        elif mode == "18200":
            with Progress(SpinnerColumn(), BarColumn(), TaskProgressColumn(),
                          TextColumn("[cyan]Cracking AS-REP (Kerberoast no-preauth)..."), transient=True) as prog:
                t = prog.add_task("", total=100)
                while not prog.finished:
                    prog.update(t, advance=random.randint(8, 18)); time.sleep(0.15)
            console.print("[bold green]Session complete![/bold green]\n")
            t2 = Table(title="Cracked AS-REP Hashes", box=box.SIMPLE_HEAD, header_style="bold magenta")
            t2.add_column("Account",  style="cyan",     width=16)
            t2.add_column("Password", style="bold red", width=20)
            t2.add_column("Note",     style="bright_black")
            t2.add_row("m.jones", "Welcome1", "Domain Users only — limited privs")
            console.print(t2)
            console.print("\n[bright_black]  Recovered: 1/1  |  Time: 00:00:03[/bright_black]")
            console.print("[bright_black]  m.jones:Welcome1 — can be used as domain foothold for further enum[/bright_black]\n")

        elif mode == "5600":
            with Progress(SpinnerColumn(), BarColumn(), TaskProgressColumn(),
                          TextColumn("[cyan]Cracking NetNTLMv2 (Responder capture)..."), transient=True) as prog:
                t = prog.add_task("", total=100)
                while not prog.finished:
                    prog.update(t, advance=random.randint(10, 25)); time.sleep(0.14)
            console.print("[bold green]Session complete![/bold green]\n")
            t2 = Table(title="Cracked NetNTLMv2 (Responder)", box=box.SIMPLE_HEAD, header_style="bold magenta")
            t2.add_column("Account",    style="cyan",     width=20)
            t2.add_column("Password",   style="bold red", width=20)
            t2.add_column("Source",     style="bright_black")
            t2.add_row("j.smith::AMNESIA", "P@ssw0rd2026!", "NTLMv2 relay capture")
            console.print(t2)
            console.print("\n[bright_black]  → NetNTLMv2 ≠ NTLM — cannot be used for Pass-the-Hash![/bright_black]")
            console.print("[bright_black]  → Use cracked plaintext password instead for auth[/bright_black]\n")

        elif mode == "3200":
            with Progress(SpinnerColumn(), BarColumn(), TaskProgressColumn(),
                          TextColumn("[cyan]Cracking bcrypt (slow)..."), transient=True) as prog:
                t = prog.add_task("", total=100)
                while not prog.finished:
                    prog.update(t, advance=random.randint(1, 4)); time.sleep(0.25)
            console.print("[bold yellow]Session complete — bcrypt is slow![/bold yellow]\n")
            console.print("[bright_black]  $2y$10$Xvf3mK9... : [/bright_black][bold red]admin123[/bold red]  (ADMIN_HASH from config.php.bak)")
            console.print("[bright_black]  Recovered: 1/1  |  Time: 00:02:44[/bright_black]\n")
        else:
            console.print(f"[yellow][!] Mode {mode} not simulated.[/yellow]")
            console.print("[bright_black]  Supported: -m 1000 (NTLM) · -m 13100 (TGS-REP) · -m 18200 (AS-REP) · -m 5600 (NetNTLMv2) · -m 3200 (bcrypt)[/bright_black]\n")

    def cmd_hint(self):
        idx = self.hint_index % len(HINTS)
        console.print(Panel(
            f"[bold yellow]{HINTS[idx]}[/bold yellow]\n\n"
            f"[bright_black]Hint {idx+1}/{len(HINTS)} — 'hint' ხელახლა შემდეგ ნაბიჯს გაჩვენებს.[/bright_black]",
            title="[ 💡 HINT ]", border_style="yellow",
        ))
        self.hint_index += 1

    def _meterpreter_help(self):
        console.print(Panel(
            "[bold green]METERPRETER:[/bold green]\n"
            "  sysinfo · getuid · getsystem · ifconfig · shell · background · exit\n"
            "  hashdump              — SAM dump (local only; DC needs DCSync)\n"
            "  upload <file>         — ფაილის ატვირთვა სამიზნეზე  (+3% alert)\n"
            "  download <file>       — ფაილის გადმოწერა  (+5% alert)\n"
            "  exfil <file> [--method https|dns]  — C2 exfiltration (+2-3% alert)\n"
            "  migrate <pid>         — process migration: 820=explorer (safe), 640=lsass (EDR blocks!)\n"
            "  mimikatz sekurlsa::logonpasswords   — LSASS dump  (+20% alert)\n"
            "  mimikatz lsadump::dcsync /domain:AMNESIA.LOCAL /user:<u>  (+25% alert)\n"
            "  kerberoast            — TGS tickets → hashcat -m 13100  (+8%)\n"
            "  asreproast            — AS-REP tickets → hashcat -m 18200  (+5%)\n"
            "  autoroute -s <subnet> — Pivot to new network segment  (+0%!)\n"
            "  run autoroute -s <subnet>  — same as above\n"
            "  run post/windows/manage/persistence_exe  — service persistence (+12%)\n"
            "  persistence [-X] [-r <lhost>]  — registry Run Key  (+8%)\n"
            "  sessions              — list/switch sessions\n",
            title="[ METERPRETER HELP ]", border_style="green",
        ))

    def cmd_help(self):
        console.print(Panel(
            "[bold cyan]KALI SHELL:[/bold cyan]\n"
            "  shodan <domain>                   — OSINT recon (passive, +0% alert)\n"
            "  nmap <ip> [flags]                 — Port scan (flags affect alert!)\n"
            "    -sS        SYN/stealth           +2–5%    (recommended)\n"
            "    -sT        TCP connect           +6–10%   (needed for proxychains)\n"
            "    -sU        UDP scan              +8–14%\n"
            "    -sV        Version detection     +4–8%    (no version without this)\n"
            "    -A         Aggressive (-sV-O-script) +15–25% (noisy!)\n"
            "    -O         OS detection          +5–8%\n"
            "    -p-        All 65535 ports       +8–15%\n"
            "    -T1/-T2    Slow/sneaky timing    -3/-2%   (IDS bypass)\n"
            "    -T4/-T5    Aggressive timing     +5/+10%  (loud!)\n"
            "    -n         No DNS lookup         -2%      (OPSEC+)\n"
            "    -Pn        Skip ping             +0%      (OPSEC+)\n"
            "    --script=<name>  NSE scripts     +10–20%  (vuln checks)\n\n"
            "  proxychains nmap -sT <ip>         — Scan via SOCKS (requires SOCKS proxy)\n"
            "  hashcat -m <mode> <hashfile>      — Crack hashes\n"
            "    -m 1000   NTLM          (hashdump / DCSync)\n"
            "    -m 13100  TGS-REP       (kerberoast)\n"
            "    -m 18200  AS-REP        (asreproast)\n"
            "    -m 5600   NetNTLMv2     (Responder capture)\n"
            "    -m 3200   bcrypt        (web configs — slow!)\n"
            "  msfconsole · netmap · ad · eventlog · hint · help · clear · exit\n\n"
            "[bold magenta]MSFCONSOLE:[/bold magenta]\n"
            "  use <module>  ·  set RHOSTS/USERNAME/PASSWORD/SMBUser/SMBPass/SRVPORT <val>\n"
            "  db_nmap [-p <ports>] <ip>         — Scan + save to MSF DB\n"
            "  run / exploit  ·  sessions [-i <id>]  ·  search <term>  ·  options  ·  exit\n\n"
            "[bold green]SHELL (inside meterpreter > shell):[/bold green]\n"
            "  cat/type · ls/dir · find · whoami · id · uname\n"
            "  systeminfo · net user/group /domain · reg query\n"
            "  netstat · arp · ps/tasklist · history\n"
            "  schtasks /create ...              — Scheduled task persistence (+6%)\n"
            "  wmic /node:<ip> process call ...  — WMI lateral movement (+8%)\n"
            "  wmic eventfilter ...              — WMI subscription persistence (+4%)\n"
            "  iodine -f -P <pass> <domain>      — DNS tunnel (+2%, OPSEC best)\n"
            "  curl -X POST -F ...               — HTTPS exfil (+3%)\n"
            "  modbus/s7client                   — OT zone commands\n\n"
            "[bold red]OPSEC ALERT BUDGET (50% threshold):[/bold red]\n"
            "  nmap -sS -T2 -n        +2–3%    ← stealthiest scan\n"
            "  autoroute / SOCKS      +0%      ← pivot is free!\n"
            "  kerberoast             +8%      ← prefer over DCSync\n"
            "  DCSync                 +25%     ← generates Event 4662 — do last!\n"
            "  mimikatz LSASS         +20%     ← visible to EDR\n"
            "  WMI persistence        +4%      ← stealthiest persistence\n"
            "  Honeypot 192.168.10.99 +50%     ← instant game over!",
            title="[ HELP ]", border_style="cyan",
        ))

    def _msf_db_nmap(self, parts):
        db_ip     = parts[-1]
        db_flags  = " ".join(parts[1:-1]) if len(parts) > 2 else "-sV"
        internal_ip = self.internal_map.get(db_ip, db_ip)
        if not self.is_routable(internal_ip):
            console.print(f"[red][-] No route to {db_ip}. autoroute pivot-ი გჭირდება.[/red]")
        elif internal_ip not in self.network:
            console.print(f"[red][-] Host {db_ip} unreachable.[/red]")
        else:
            node  = self.network[internal_ip]
            noise = random.randint(3, 7)
            self.alert_level += noise
            self.log_event("PORT_SCAN", f"db_nmap {db_ip} {db_flags}", "WARN")
            with Progress(SpinnerColumn(), TextColumn(f"[cyan]db_nmap {db_ip}..."),
                          transient=True) as p:
                p.add_task("", total=None); time.sleep(1.5)
            self.scanned_hosts.add(internal_ip)
            console.print(f"\n[bold green][*] db_nmap: {node['hostname']} ({db_ip})[/bold green]")
            console.print(f"[bright_black]OS: {node['os']} | Zone: {node['zone']}[/bright_black]")
            if node.get("has_edr"):
                console.print(f"[yellow][!] EDR: {node.get('edr_product','EDR')} detected[/yellow]")
            t = Table(box=box.SIMPLE, header_style="bold white")
            t.add_column("PORT",    style="cyan",   width=10)
            t.add_column("STATE",   style="green",  width=8)
            t.add_column("SERVICE", style="yellow", width=14)
            t.add_column("VERSION", width=30)
            t.add_column("VULN",    width=22)
            port_filter = None
            for i, part in enumerate(parts):
                if part == "-p" and i + 1 < len(parts):
                    port_filter = parts[i + 1].split(",")
            for port, info in node["ports"].items():
                if port_filter and port not in port_filter:
                    continue
                vuln_str = (f"[bold red]⚑ {info['vuln']}[/bold red]"
                            if info.get("vuln") else "[bright_black]—[/bright_black]")
                t.add_row(f"{port}/tcp", "open", info["service"], info["version"], vuln_str)
            console.print(t)
            console.print(f"[bright_black][*] Scan saved to MSF database.  Alert +{noise}%[/bright_black]\n")
            self.check_hunter()

    def _victory_summary(self):
        end_time    = datetime.now()
        elapsed     = end_time - self.start_time
        mins, secs  = divmod(int(elapsed.total_seconds()), 60)
        elapsed_str = f"{mins}m {secs}s"

        chain_hosts = []
        for ip in self.compromised.values():
            n = self.network[ip]
            chain_hosts.append(f"  • {ip:<16} {n['hostname']:<14} ({n['zone']})")

        loot_str = (", ".join(self.loot_files[:6]) + (f" +{len(self.loot_files)-6} more" if len(self.loot_files) > 6 else "")) if self.loot_files else "none"

        persist_str = "\n".join(f"  • {p}" for p in self.persistence_done) if self.persistence_done else "  (none installed)"

        thresh   = self.meta.get("hunter_threshold", 50)
        margin   = thresh - self.alert_level
        opsec_color = "green" if margin > 15 else ("yellow" if margin > 5 else "bold red")

        console.print(Panel(
            f"[bold cyan]Operator  :[/bold cyan] anonimus\n"
            f"[bold cyan]Target    :[/bold cyan] geoforum.ge — HARD MODE (DMZ → CORP → OT)\n"
            f"[bold cyan]Duration  :[/bold cyan] {elapsed_str}  |  {self.start_time.strftime('%Y-%m-%d %H:%M:%S')} → {end_time.strftime('%H:%M:%S')}\n\n"
            f"[bold white]ATTACK CHAIN ─────────────────────────────────────────[/bold white]\n"
            + "\n".join(chain_hosts) +
            f"\n  [yellow]→ Chain: DMZ (RCE) → CORP (AD/EternalBlue) → OT (S7comm)[/yellow]\n\n"
            f"[bold white]LOOT ─────────────────────────────────────────────────[/bold white]\n"
            f"  {loot_str}\n\n"
            f"[bold white]PERSISTENCE ──────────────────────────────────────────[/bold white]\n"
            f"{persist_str}\n\n"
            f"[bold white]OPSEC SCORE ──────────────────────────────────────────[/bold white]\n"
            f"  Peak Alert    : [{opsec_color}]{self.alert_level}%[/{opsec_color}]  (threshold: {thresh}%)\n"
            f"  Margin left   : [{opsec_color}]{margin}%[/{opsec_color}]\n"
            f"  Objectives    : {len(self.objectives_done)}/{len(self.meta.get('objectives',[]))}\n"
            f"  Hunter evaded : [bold green]✓[/bold green]\n\n"
            f"[cyan]Blue Team SOC timeline: check [bold]server.py[/bold] terminal[/cyan]",
            title="[ 🏆 MISSION REPORT ]", border_style="bold green",
        ))

    def run(self):
        self.load_scenario()
        self.banner()

        while True:
            try:
                self._tick_alert_decay()

                if self.msf_mode:
                    prompt = (f"[{MSF_COLOR}]msf6[/{MSF_COLOR}] "
                              f"[bold white]{self.msf_module or ''}[/bold white] > ")
                elif self.active_session:
                    t_ip   = self.compromised[self.active_session]
                    t_host = self.network[t_ip]["hostname"]
                    prompt = (f"[{METERP_COLOR}]meterpreter[/{METERP_COLOR}] "
                              f"[bright_black]({t_host})[/bright_black] > ")
                else:
                    prompt = f"[{PROMPT_COLOR}]┌──(anonimus㉿kali)-[~/workspace][/{PROMPT_COLOR}]\n└─$ "

                user_input = console.input(prompt).strip()
                if not user_input:
                    continue

                parts  = user_input.split()
                action = parts[0].lower()

                if action == "clear":
                    self.banner(); continue
                if action == "exit" and not self.msf_mode and not self.active_session:
                    console.print("\n[bold cyan]GeoForum CyberLab — სესია დასრულდა![/bold cyan]\n")
                    break
                if action == "help":
                    self.cmd_help(); continue

                if action == "msfconsole" and not self.msf_mode and not self.active_session:
                    self.msf_mode = True
                    console.print(f"\n[{MSF_COLOR}]       =[ metasploit v6.3.44-dev ][/{MSF_COLOR}]")
                    console.print("[bright_black]+ -- --=[ 2347 exploits - 1230 auxiliary - 427 post ][/bright_black]")
                    console.print("[bright_black]+ -- --=[ 607 payloads - 45 encoders                ][/bright_black]\n")
                    continue

                if self.active_session:
                    self.handle_meterpreter(action, parts); continue

                if self.msf_mode:
                    if action == "use" and len(parts) > 1:
                        self.msf_module = " ".join(parts[1:])
                        console.print(f"[*] Using: [bold cyan]{self.msf_module}[/bold cyan]")
                    elif action == "set" and len(parts) > 2:
                        k, v = parts[1].upper(), " ".join(parts[2:])
                        self.msf_options[k] = v
                        console.print(f"{k} => {v}")
                    elif action == "options":
                        self.show_msf_options()
                    elif action == "search" and len(parts) > 1:
                        self.search_msf(parts[1])
                    elif action in ("run", "exploit"):
                        if self.msf_module == "auxiliary/server/socks_proxy":
                            port = self.msf_options.get("SRVPORT", "1080")
                            ver  = self.msf_options.get("VERSION", "5")
                            console.print(f"[*] Starting SOCKS{ver} proxy on 0.0.0.0:{port}")
                            time.sleep(0.8)
                            console.print(f"[bold green][+] Auxiliary module running as background job 0.[/bold green]")
                            console.print(f"[bold green][+] SOCKS proxy listening on 127.0.0.1:{port}[/bold green]")
                            console.print(f"[bright_black]  → /etc/proxychains4.conf-ში: socks{ver} 127.0.0.1 {port}[/bright_black]")
                            console.print(f"[bright_black]  → შემდეგ: proxychains nmap -sT 10.10.10.5[/bright_black]\n")
                            self.msf_options["_socks_active"] = port
                        else:
                            self.run_msf_exploit()
                    elif action == "db_nmap":
                        self._msf_db_nmap(parts)
                    elif action == "exit":
                        self.msf_mode = False; self.msf_module = None
                        console.print("[*] Exiting msfconsole.")
                    elif action == "sessions":
                        if len(parts) > 2 and parts[1] == "-i":
                            try:
                                sid = int(parts[2])
                            except ValueError:
                                console.print(f"[red][-] Session ID რიცხვი უნდა იყოს.[/red]")
                                continue
                            if sid in self.compromised:
                                self.active_session = sid
                                self.msf_mode       = False
                                console.print(f"[*] Resumed session {sid} — "
                                              f"{self.network[self.compromised[sid]]['hostname']}")
                            else:
                                console.print(f"[red][-] Session {sid} not found.[/red]")
                        else:
                            if self.compromised:
                                t = Table(box=box.SIMPLE, header_style="bold magenta")
                                t.add_column("ID"); t.add_column("IP")
                                t.add_column("Hostname"); t.add_column("OS"); t.add_column("Zone")
                                for sid, ip in self.compromised.items():
                                    n = self.network[ip]
                                    t.add_row(str(sid), ip, n["hostname"], n["os"], n["zone"])
                                console.print(t)
                            else:
                                console.print("[bright_black]No sessions.[/bright_black]")
                    elif action == "help":
                        console.print("[cyan]msf> use · set · options · search · run · db_nmap · sessions · exit[/cyan]")
                    else:
                        console.print(f"[red]msf> Unknown: {action}[/red]")
                    continue

                if action == "shodan" and len(parts) > 1:
                    self.cmd_shodan(parts[1])
                elif action == "hashcat":
                    self.cmd_hashcat(parts)
                elif action == "proxychains":
                    self.cmd_proxychains(parts)
                elif action == "nmap" and len(parts) > 1:
                    ip_arg     = None
                    flags_list = []
                    skip_next  = False
                    for i, part in enumerate(parts[1:], 1):
                        if skip_next:
                            flags_list.append(part); skip_next = False; continue
                        if part.startswith("-"):
                            flags_list.append(part)
                            if part in ("-p", "-e", "--script", "--source-port"):
                                skip_next = True
                        else:
                            ip_arg = part
                    if ip_arg is None:
                        console.print("[red][-] nmap: target IP გჭირდება.[/red]")
                        console.print("[bright_black]  გამოყენება: nmap <ip> [-sS|-sV|-A|...][/bright_black]\n")
                    else:
                        self.cmd_nmap(ip_arg, " ".join(flags_list))
                elif action == "netmap":
                    self.cmd_netmap()
                elif action == "ad":
                    self.cmd_ad()
                elif action == "eventlog":
                    self.cmd_eventlog()
                elif action == "hint":
                    self.cmd_hint()
                else:
                    console.print(f"[bright_black]-bash: {action}: command not found[/bright_black]")

            except KeyboardInterrupt:
                console.print("\n[yellow][!] Ctrl+C — type 'exit' to quit.[/yellow]")
            except Exception as e:
                import traceback
                console.print(f"[red][!] Error: {e}[/red]")
                console.print(f"[bright_black]{traceback.format_exc()}[/bright_black]")

if __name__ == "__main__":
    CyberLab().run()
