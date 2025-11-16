#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WebCfScan - Advanced Web Intelligence & Vulnerability Scanner
Author: CyberFlow
Telegram: https://t.me/+EMAmFtc6PncxODM0
GitHub: https://github.com/tahaprogramming/taha
Version: 1.0.0
License: Apache
"""

import os
import sys
import time
import socket
import requests
import json 
import re
from datetime import datetime
from urllib.parse import urlparse, urljoin
import pyfiglet
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()
requests.packages.urllib3.disable_warnings()

def banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    font = pyfiglet.Figlet(font='slant')
    ascii_art = font.renderText("WebCfScan")
    
    console.print(f"[bold cyan]{ascii_art}")
    console.print(Panel(
        f"[bold white]Advanced Web Intelligence & Vulnerability Scanner[/]\n\n"
        f"[cyan]Author[/]      : [bold magenta]CyberFlow[/]\n"
        f"[cyan]Telegram[/]    : [bold blue]https://t.me/+EMAmFtc6PncxODM0[/]\n"
        f"[cyan]GitHub[/]      : [bold blue]https://github.com/tahaprogramming/taha[/]\n"
        f"[cyan]Version[/]     : [bold yellow]1.0.0[/]\n"
        f"[red]Use only on authorized targets • Ethical hacking only[/]\n"
        f"[dim]Tip: Run as root/sudo for accurate network path detection[/]",
        title="[bold magenta]WebCfScan v1.0[/]",
        border_style="bright_cyan",
        box=box.DOUBLE
    ))

def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return "Failed to resolve"

def get_subdomains(domain):
    subs = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15)
        if r.status_code == 200:
            for entry in r.json():
                name = entry['name_value'].strip().lower()
                if domain in name:
                    subs.add(name.split('@')[0])
    except:
        pass
    
    common = ["www", "mail", "ftp", "admin", "test", "dev", "api", "staging", "beta", "shop", "blog", "panel", "cpanel", "webmail", "ns1", "ns2"]
    for sub in common:
        try:
            socket.gethostbyname(f"{sub}.{domain}")
            subs.add(f"{sub}.{domain}")
        except:
            pass
    return list(subs) or ["No subdomains found"]

def get_real_network_path(ip, max_hops=8):
    hops = []
    is_root = os.getuid() == 0 if hasattr(os, 'getuid') else False
    
    for ttl in range(1, max_hops + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)  
            s.settimeout(2)
            start = time.time()
            s.connect((ip, 80))
            rtt = int((time.time() - start) * 1000)
            hops.append(f"Hop {ttl}: {ip} ({rtt}ms) [DIRECT CONNECT]")
            s.close()
            break
        except:
            s.close()
            pass
       
        if not is_root:
            hops.append(f"Hop {ttl}: * (requires sudo for ICMP)")
            continue

        try:
            icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            icmp.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl) 
            icmp.settimeout(2)
            start = time.time()
            icmp.sendto(b"", (ip, 0))
            _, addr = icmp.recvfrom(1024)
            rtt = int((time.time() - start) * 1000)
            hop_ip = addr[0] if addr else "unknown"
            hops.append(f"Hop {ttl}: {hop_ip} ({rtt}ms)")
            icmp.close()
            if hop_ip == ip:
                break
        except PermissionError:
            hops.append(f"Hop {ttl}: * (run as root for accurate path)")
            break
        except:
            hops.append(f"Hop {ttl}: * (timeout/blocked)")

    return hops[:6] if hops else ["Network path detection unavailable"]

def detect_tech_full(url):
    tech = {}
    try:
        headers = {"User-Agent": "Mozilla/5.0 (WebCfScan/1.0; +https://t.me/+EMAmFtc6PncxODM0)"}
        r = requests.get(url, timeout=20, headers=headers, verify=False, allow_redirects=True)
        h = {k.lower(): v for k, v in r.headers.items()}
        content = r.text.lower()
        raw_content = r.text

        if "server" in h:
            tech["Web Server"] = r.headers.get("Server", "Hidden")
        if "x-powered-by" in h:
            tech["Backend Engine"] = h["x-powered-by"]

        if any(x in str(h) for x in ["cloudflare", "cf-ray", "__cf_bm"]):
            tech["Protection"] = "Cloudflare"
        if "sucuri" in str(h):
            tech["Protection"] = "Sucuri"
        if "x-amz-cf-id" in h:
            tech["CDN"] = "AWS CloudFront"

        if re.search(r'wp-(content|includes|/wp-json)', content):
            tech["CMS"] = "WordPress"
            v = re.search(r'WordPress\s+([\d.]+)', raw_content, re.I) or re.search(r'generator["\']?\s*[:>]\s*["\']WordPress\s*([\d.]+)', raw_content, re.I)
            if v: tech["WordPress Version"] = v.group(1)

        if "joomla" in content:
            tech["CMS"] = "Joomla"
        if "laravel" in content or "laravel_session" in str(h):
            tech["Framework"] = "Laravel"
        if "react" in content:
            tech["Frontend Framework"] = "React"
        if "vue" in content or "__vue__" in content:
            tech["Frontend Framework"] = "Vue.js"
        if "_next" in content:
            tech["Frontend Framework"] = "Next.js"
        if "jquery" in content:
            tech["JS Library"] = "jQuery"
        if "bootstrap" in content:
            tech["CSS Framework"] = "Bootstrap"

        if len(tech) <= 2:
            tech["Development Type"] = "Custom / Hand-coded Website"

        return tech or {"Status": "Basic HTTP Server"}
    except:
        return {"Error": "Failed to fetch page"}

def full_scan(target):
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    domain = urlparse(target).netloc
    ip = get_ip(domain)
    
    results = {
        "target": target,
        "domain": domain,
        "ip": ip,
        "subdomains": get_subdomains(domain),
        "technologies": detect_tech_full(target),
        "network_path": get_real_network_path(ip) if ip not in ["Failed to resolve"] else ["IP resolution failed"],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    return results

def display_results(results):
    table = Table(title=f"[bold cyan]WebCfScan Results → {results['domain']}", box=box.DOUBLE, header_style="bold magenta")
    table.add_column("Category", style="cyan", width=22)
    table.add_column("Details", style="green")
    table.add_row("Target URL", results['target'])
    table.add_row("Domain", results['domain'])
    table.add_row("Main IP", f"[bold yellow]{results['ip']}[/]")
    table.add_row("Subdomains Found", f"[bold {'red' if len(results['subdomains']) > 8 else 'green'}]{len(results['subdomains'])}[/]")
    table.add_row("Technologies", f"{len(results['technologies'])} detected")
    table.add_row("Scan Time", results['timestamp'])
    console.print(table)
    
    console.print(Panel("[bold cyan]Subdomains Discovered[/]", border_style="bright_cyan"))
    for sub in results['subdomains'][:15]:
        console.print(f"   [green]•[/] [white]{sub}[/]")
    if len(results['subdomains']) > 15:
        console.print(f"   [dim]... and {len(results['subdomains'])-15} more[/]")

    console.print(Panel("[bold cyan]Technologies & Frameworks[/]", border_style="bright_cyan"))
    for k, v in results['technologies'].items():
        console.print(f"   [yellow]└─[/] [bold white]{k}[/]: [green]{v}[/]")

    console.print(Panel("[bold cyan]Network Path (Real Hop Discovery)[/]", border_style="bright_cyan"))
    for hop in results['network_path']:
        console.print(f"   [dim]{hop}[/]")

def save_report(results):
    if not os.path.exists("reports"):
        os.makedirs("reports")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_domain = results['domain'].replace('.', '_')
    filename = f"reports/WebCfScan_report_{timestamp}_{safe_domain}.txt"
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write("="*75 + "\n")
        f.write("                    WEBCFSCAN INTELLIGENCE REPORT\n")
        f.write("="*75 + "\n\n")
        f.write(f"Target        : {results['target']}\n")
        f.write(f"Domain        : {results['domain']}\n")
        f.write(f"Main IP       : {results['ip']}\n")
        f.write(f"Scanned At    : {results['timestamp']}\n")
        f.write(f"Scanner       : WebCfScan v1.0 by CyberFlow\n\n")
        f.write("SUBDOMAINS FOUND:\n")
        for s in results['subdomains']: f.write(f" • {s}\n")
        f.write("\nTECHNOLOGIES DETECTED:\n")
        for k, v in results['technologies'].items(): f.write(f" • {k}: {v}\n")
        f.write("\nREAL NETWORK PATH:\n")
        for hop in results['network_path']: f.write(f"   {hop}\n")
        f.write(f"\nTelegram: https://t.me/+EMAmFtc6PncxODM0\n")
        f.write(f"GitHub  : https://github.com/tahaprogramming/taha\n")
    
    console.print(f"\n[bold green][+] Report saved successfully → {filename}[/]")

def main():
    banner()
    console.print("[bold magenta]WebCfScan initialized. Ready for deep reconnaissance.[/]\n")
    
    target = console.input(f"[bold yellow][>] Enter target (domain or URL): [/]").strip()
    if not target:
        console.print("[red][!] Target is required![/]")
        sys.exit(1)
    
    console.print(f"\n[bold cyan]Launching WebCfScan against [white]{target}[/]...\n")
    
    with Progress(SpinnerColumn(), TextColumn("[bold cyan]Analyzing target intelligence..."), console=console) as progress:
        progress.add_task("", total=None)
        results = full_scan(target)
    
    display_results(results)
    
    save = console.input(f"\n[bold blue][?] Save full report to file? (y/n): [/]").lower().strip()
    if save in ["y", "yes"]:
        save_report(results)
    
    console.print(f"\n[bold magenta]WebCfScan mission completed. Stay in the shadows, CyberFlow.[/] [bold red]💀[/]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[bold red][!] Operation aborted by user.[/]")
        sys.exit(0)