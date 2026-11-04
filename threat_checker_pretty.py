import sys
import os
import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Initialize Rich console
console = Console()

# API key is read ONLY from the environment. Never hardcode a key here.
# Set it first, e.g.:  $env:ABUSEIPDB_API_KEY = "your-new-key"   (PowerShell)
API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

def check_ip_reputation(ip_address):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {'Accept': 'application/json', 'Key': API_KEY}
    params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}

    if not API_KEY:
        console.print("[bold red][!] ABUSEIPDB_API_KEY is not set. Set it as an environment variable and try again.[/]")
        return

    console.print(f"\n[bold cyan][*] Querying Threat Intelligence API for:[/] [yellow]{ip_address}[/]")

    try:
        response = requests.get(url, headers=headers, params=params)
        
        if response.status_code == 200:
            data = response.json()['data']
            score = data.get('abuseConfidenceScore', 0)

            # Determine Risk Badge and Color
            if score > 50:
                verdict = "[bold white on red] HIGH RISK [/] - Recommend Firewall Block"
                border_color = "red"
            elif score > 15:
                verdict = "[bold black on yellow] MEDIUM RISK [/] - Monitor Traffic"
                border_color = "yellow"
            else:
                verdict = "[bold black on green] CLEAN / LOW RISK [/] - Safe"
                border_color = "green"

            # Create a structured visual table
            table = Table(title="IP Details", show_header=False, expand=True)
            table.add_column("Property", style="bold cyan", width=20)
            table.add_column("Value", style="white")

            table.add_row("IP Address", str(data.get('ipAddress')))
            table.add_row("Abuse Score", f"{score}%")
            table.add_row("ISP", str(data.get('isp')))
            table.add_row("Domain", str(data.get('domain')))
            table.add_row("Country", str(data.get('countryCode')))
            table.add_row("Total Reports", str(data.get('totalReports')))

            # Render in a styled box/panel
            panel_content = Panel(table, title=f"Verdict: {verdict}", border_style=border_color)
            console.print(panel_content)

        else:
            console.print(f"[bold red][-] API Error {response.status_code}:[/] {response.text}")

    except Exception as e:
        console.print(f"[bold red][-] Connection failed:[/] {e}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "118.25.6.39"
    check_ip_reputation(target)
