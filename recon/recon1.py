import os
import requests
import concurrent.futures
import dns.resolver
import socket
import whois
import json
import re
import subprocess
from tqdm import tqdm
from rich.console import Console

console = Console()

# Load subdomains from JSON file
def load_subdomains(json_file):
    try:
        with open(json_file, "r") as file:
            data = json.load(file)
            return data.get("subdomains", [])
    except Exception as e:
        console.print(f"[red][!] Error loading JSON: {e}[/red]")
        return []

# Initialize results dictionary
results = {}

def get_dns_info(subdomain):
    try:
        result = subprocess.run(["dig", subdomain, "ALL"], capture_output=True, text=True)
        return result.stdout.strip().split("\n") if result.returncode == 0 else ["Error: dig command failed"]
    except Exception as e:
        return [f"Error: {str(e)}"]

def get_whois_info(subdomain):
    try:
        result = subprocess.run(["whois", subdomain], capture_output=True, text=True, check=True)
        return result.stdout.strip().split("\n")
    except subprocess.CalledProcessError:
        return ["WHOIS lookup failed."]

def detect_technology(subdomain):
    url = f"http://{subdomain}"
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        return {
            "server": headers.get("Server", "Unknown"),
            "powered_by": headers.get("X-Powered-By", "Unknown")
        }
    except requests.exceptions.RequestException:
        return {"error": "Technology detection failed."}

def get_reverse_ip_lookup(subdomain):
    try:
        ip = socket.gethostbyname(subdomain)
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        return response.json().get("hostname", "No hostname found") if response.status_code == 200 else "Reverse IP lookup failed"
    except Exception:
        return "Reverse IP lookup failed"

def get_asn_info(subdomain):
    try:
        ip = socket.gethostbyname(subdomain)
        result = subprocess.run(["whois", ip], capture_output=True, text=True, check=True)
        return [line.strip() for line in result.stdout.split("\n") if "origin" in line.lower() or "asn" in line.lower()]
    except Exception:
        return ["ASN lookup failed."]

def run_nmap_scan(subdomain):
    try:
        result = subprocess.run(["nmap", "-Pn", "-F", "-sV", subdomain], capture_output=True, text=True)
        return [line.strip() for line in result.stdout.strip().split("\n") if "open" in line] or ["No open ports found."]
    except Exception:
        return ["Nmap scan failed."]

def run_wafw00f(subdomain):
    try:
        result = subprocess.run(["wafw00f", subdomain], capture_output=True, text=True)
        return "WAF Detected" if "WAF detected" in result.stdout else "No WAF Detected"
    except Exception:
        return "WAF detection failed."

def run_whatweb(subdomain):
    try:
        result = subprocess.run(["whatweb", subdomain], capture_output=True, text=True)
        return [line.strip() for line in result.stdout.strip().split("\n") if any(keyword in line for keyword in ["Apache", "nginx", "PHP", "WordPress", "jQuery", "ASP.NET"])] or ["No significant technologies detected."]
    except Exception:
        return ["WhatWeb scan failed."]

def clean_escape_sequences(text):
    if isinstance(text, str):
        ansi_escape = re.compile(r'\x1b\[[0-9;]*[mGKF]')
        return ansi_escape.sub('', text)
    return text

def save_results_to_txt():
    try:
        # Create 'recon/subrecon' folder if it doesn't exist
        if not os.path.exists('recon/recon/subrecon'):
            os.makedirs('recon/recon/subrecon')

        for subdomain, data in results.items():
            cleaned_data = {}
            for key, value in data.items():
                if isinstance(value, list):
                    cleaned_data[key] = [clean_escape_sequences(line) for line in value]
                else:
                    cleaned_data[key] = clean_escape_sequences(value)
            
            # Save results inside the 'recon/recon/subrecon' folder
            file_name = os.path.join('recon/recon/subrecon', f"{subdomain}_recon_results.json")
            with open(file_name, "w") as file:
                json.dump(cleaned_data, file, indent=4)
            console.print(f"[green][✔] Results saved to {file_name}[/green]")
    except Exception as e:
        console.print(f"[red][!] Error saving results: {e}[/red]")

def run_recon_on_subdomains(subdomains, threads=10):
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {}
        for subdomain in subdomains:
            console.print(f"\n[bold cyan][*] Scanning {subdomain}...[/bold cyan]\n")
            futures[subdomain] = {
                "dns": executor.submit(get_dns_info, subdomain),
                "whois": executor.submit(get_whois_info, subdomain),
                "technology": executor.submit(detect_technology, subdomain),
                "network": {
                    "reverse_ip": executor.submit(get_reverse_ip_lookup, subdomain),
                    "asn_info": executor.submit(get_asn_info, subdomain)
                },
                "nmap": executor.submit(run_nmap_scan, subdomain),
                "waf": executor.submit(run_wafw00f, subdomain),
                "whatweb": executor.submit(run_whatweb, subdomain)
            }
        
        for subdomain, tasks in futures.items():
            results[subdomain] = {key: task.result() if isinstance(task, concurrent.futures.Future) else {k: v.result() for k, v in task.items()} for key, task in tasks.items()}
    
    save_results_to_txt()

def main():
    subdomains = load_subdomains("recon/recon_results.json")
    if subdomains:
        run_recon_on_subdomains(subdomains)
    else:
        console.print("[red][!] No subdomains found in recon_results.json[/red]")

if __name__ == "__main__":
    main()
