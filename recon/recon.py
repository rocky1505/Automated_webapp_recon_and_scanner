import requests
import concurrent.futures
import socket
import json
import subprocess
import re
import os
import sys
from tqdm import tqdm
from rich.console import Console

console = Console()

# Global dictionary to store results
results = {
    "subdomains": set(),   # Using a set to ensure uniqueness
    "gobuster": {},
    "active_subdomains": set(),
    "redirected_links": {}  # Stores 301, 302 redirected links
}

### -------------------- CHECK ARGUMENTS -------------------- ###
if len(sys.argv) < 2:
    console.print("[red][❌] No target URL provided![/red]")
    sys.exit(1)

target_domain = sys.argv[1]

### -------------------- 1️⃣ SUBDOMAIN ENUMERATION -------------------- ###
def brute_force_subdomains(domain, wordlist = os.path.join(os.path.dirname(__file__), "sub_wordlist.txt"), threads=50, recursive=False, depth=0, visited=set(), root_domain=""):
    if depth >= 3:  # Stop recursion after Depth 2
        return

    if domain in visited:
        return  # Skip re-processing the same domain

    visited.add(domain)  # Mark as visited to avoid redundant expansion

    if depth == 0:
        root_domain = domain  # Store the root domain

    if not recursive:
        console.print("[cyan][*] Performing Initial Subdomain Enumeration...[/cyan]")
    else:
        console.print(f"[yellow][*] Performing Recursive Subdomain Enumeration (Depth {depth}) on {domain}...[/yellow]")

    results["subdomains"].add(domain)  # Ensure the main domain is always included

    def check_subdomains_batch(sub_list):
        """Perform batch DNS lookups for faster processing."""
        resolved = set()
        for sub in sub_list:
            url = f"{sub}.{domain}"
            if url == root_domain:  
                continue  # Avoid checking `www.amrita.edu` at Depth 2

            try:
                socket.gethostbyname(url)  # Batch lookup
                resolved.add(url)  # Store only valid subdomains
            except socket.gaierror:
                pass  # Ignore non-resolving subdomains
        return resolved

    try:
        with open(wordlist, "r") as file:
            subdomains = file.read().splitlines()

        batch_size = 100  # Process in batches of 100
        total_subdomains = len(subdomains)

        with tqdm(total=total_subdomains, desc=f"Depth {depth}: Enumerating {domain}", ncols=80) as progress:
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                future_to_batch = {
                    executor.submit(check_subdomains_batch, subdomains[i:i+batch_size]): i
                    for i in range(0, total_subdomains, batch_size)
                }

                for future in concurrent.futures.as_completed(future_to_batch):
                    results["subdomains"].update(future.result())
                    progress.update(batch_size)

    except FileNotFoundError:
        console.print("[red][!] Wordlist file not found.[/red]")

    # 🔥 Recursive subdomain brute-forcing, but **limit depth intelligently**
    if recursive and depth < 2:
        next_targets = list(results["subdomains"])[:10]  # Limit expansion to 10 new subdomains max
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            executor.map(lambda sub: brute_force_subdomains(sub, wordlist, threads, True, depth + 1, visited, root_domain), next_targets)

### -------------------- 2️⃣ ZONE TRANSFER CHECK -------------------- ###
def check_zone_transfer(domain):
    console.print("[cyan][*] Checking for Zone Transfers...[/cyan]")

    ns_lookup = subprocess.run(["host", "-t", "ns", domain], capture_output=True, text=True)
    nameservers = re.findall(r"nameserver\s+(\S+)", ns_lookup.stdout)

    for ns in nameservers:
        console.print(f"[yellow][*] Attempting Zone Transfer on {ns}[/yellow]")
        axfr_check = subprocess.run(["host", "-l", domain, ns], capture_output=True, text=True)

        if "Transfer failed" not in axfr_check.stderr:
            found_subdomains = re.findall(rf"(\S+)\.{domain}", axfr_check.stdout)
            results["subdomains"].update(found_subdomains)
            console.print(f"[bold green][✓] Zone Transfer Successful on {ns}[/bold green]")
        else:
            console.print(f"[red][!] Zone Transfer Failed on {ns}[/red]")

### -------------------- 3️⃣ DIRECTORY BRUTEFORCE WITH GOBUSTER -------------------- ###
def run_gobuster(wordlist = os.path.join(os.path.dirname(__file__), "dir_wordlist.txt"), threads=20):
    console.print("[cyan][*] Running Gobuster for Found Subdomains...[/cyan]")

    if not results["subdomains"]:
        console.print("[red][!] No subdomains found for Gobuster.[/red]")
        return

    def scan_subdomain(sub):
        try:
            command = ["gobuster", "dir", "-u", f"http://{sub}", "-w", wordlist, "-q"]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            directories = []
            redirected_links = []  

            for line in process.stdout:
                if line.strip():
                    cleaned_entry = re.sub(r'\u001b\[\d*K', '', line).strip()  

                    status_match = re.search(r"\(Status: (\d{3})\)", cleaned_entry)
                    redirect_match = re.search(r"\[--> (.*?)\]", cleaned_entry)  

                    if status_match:
                        status_code = status_match.group(1)
                        if status_code in {"200", "403", "301", "302"}:
                            directories.append({
                                "path": cleaned_entry.split(" (Status:")[0].strip(),
                                "status_code": status_code,
                                "redirect_url": redirect_match.group(1) if redirect_match else None
                            })

                        if status_code in {"301", "302"} and redirect_match:  
                            redirected_links.append(redirect_match.group(1))

            if directories:
                results["gobuster"][sub] = directories
                results["active_subdomains"].add(sub)  

            if redirected_links:
                results["redirected_links"][sub] = redirected_links

        except Exception as e:
            console.print(f"[red][!] Gobuster scan failed for {sub}: {e}[/red]")

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        list(tqdm(executor.map(scan_subdomain, results["subdomains"]), total=len(results["subdomains"]), desc="Scanning Directories", ncols=80))

### -------------------- 4️⃣ LIVE SUBDOMAIN CHECK WITH HTTPX -------------------- ###
def run_httpx():
    console.print("[cyan][*] Checking Live Subdomains with HTTPX...[/cyan]")

    if not results["subdomains"]:
        console.print("[red][!] No subdomains found to check.[/red]")
        return

    try:
        command = ["httpx", "-silent", "-title", "-tech-detect", "-status-code", "-json", "-u"] + list(results["subdomains"])
        result = subprocess.run(command, capture_output=True, text=True)

        if result.stdout:
            httpx_results = [json.loads(line) for line in result.stdout.strip().split("\n") if line.strip()]
            for entry in httpx_results:
                subdomain = entry.get("input")
                if subdomain:
                    results["active_subdomains"].add(subdomain)

    except Exception as e:
        console.print(f"[red][!] HTTPX scan failed: {e}[/red]")

### -------------------- 5️⃣ SAVE JSON OUTPUT -------------------- ###
def save_results():
    os.makedirs("recon", exist_ok=True)
    output_file = os.path.join("recon", "recon_results.json")

    final_results = {
        "subdomains": list(results["subdomains"]),
        "gobuster": results["gobuster"],
        "active_subdomains": list(results["active_subdomains"]),
        "redirected_links": results["redirected_links"]
    }

    with open(output_file, "w") as f:
        json.dump(final_results, f, indent=4)

    console.print(f"[bold green][✓] Results saved to {output_file}[/bold green]")

### -------------------- RUN RECON -------------------- ###
def run_recon(target):
    console.print(f"[bold cyan][*] Running reconnaissance on {target}...[/bold cyan]")

    brute_force_subdomains(target, recursive=True, depth=0)
    check_zone_transfer(target)
    run_gobuster()
    run_httpx()
    save_results()

    console.print("[bold green][✓] Reconnaissance completed! Results saved.[/bold green]")

if __name__ == "__main__":
    run_recon(target_domain)
