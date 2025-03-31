import os
import json
import subprocess

def search_exploits(query):
    """Search for exploits using searchsploit."""
    try:
        result = subprocess.run(["searchsploit", query], capture_output=True, text=True)
        return result.stdout.strip() or "No Results"
    except Exception as e:
        return f"Error running searchsploit: {str(e)}"

def scan_vulnerabilities(base_path, output_file):
    """Scan each subdomain JSON file for vulnerabilities and store results."""
    subrecon_path = os.path.join(base_path, "recon", "subrecon")
    
    if not os.path.exists(subrecon_path):
        with open(output_file, "w") as log:
            log.write("❌ subrecon directory not found!\n")
        print("❌ subrecon directory not found!")
        return
    
    with open(output_file, "w") as log:
        log.write(f"🔍 Scanning directory: {subrecon_path}\n\n")

        for file in os.listdir(subrecon_path):
            json_path = os.path.join(subrecon_path, file)
            
            if file.endswith("_recon_results.json"):
                log.write(f"📄 Found JSON file: {file}\n")
                print(f"📄 Found JSON file: {file}")
                
                try:
                    with open(json_path, "r") as f:
                        data = json.load(f)
                except json.JSONDecodeError:
                    log.write(f"❌ Error: {file} is not valid JSON!\n\n")
                    print(f"❌ Error: {file} is not valid JSON!")
                    continue
                
                log.write(f"\n🔍 Scanning for vulnerabilities in: {file}\n")
                
                # Extract technologies
                technologies = data.get("technology", {})
                if not technologies:
                    log.write("❌ No 'technology' key found in JSON.\n")
                else:
                    log.write("📌 Discovered Services & Technologies:\n")
                    for tech, service in technologies.items():
                        log.write(f" - {tech}: {service}\n")
                        if service and service != "Unknown":
                            log.write(f"🔎 Searching exploits for: {service}\n")
                            exploits = search_exploits(service)
                            log.write(exploits + "\n")

                # Extract Nmap services
                nmap_results = data.get("nmap", [])
                if not nmap_results or "No open ports found." in nmap_results:
                    log.write("❌ No open ports/services found in Nmap scan.\n\n")
                else:
                    log.write("\n📌 Nmap Detected Services:\n")
                    for line in nmap_results:
                        log.write(f" - {line}\n")
                        service_name = line.split()[0] if len(line.split()) > 1 else None
                        if service_name and "open" in line:
                            log.write(f"🔎 Searching exploits for: {service_name}\n")
                            exploits = search_exploits(service_name)
                            log.write(exploits + "\n")

                log.write("\n" + "="*50 + "\n\n")  # Separator for better readability
                
if __name__ == "__main__":
    base_path = os.path.expanduser("../recon")  # Adjust path if needed
    output_file = "scan_results.log"  # File to store the results
    scan_vulnerabilities(base_path, output_file)
    print(f"✅ Scan completed. Results saved in {output_file}")
