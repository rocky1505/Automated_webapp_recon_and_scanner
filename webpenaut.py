import argparse
import subprocess

def run_script(script_name, url):
    """Runs a Python script as a subprocess with the provided URL argument."""
    print(f"\n[⚡] Running {script_name} with URL: {url}\n")

    process = subprocess.Popen(["python3", script_name, url], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()

    if stdout:
        print(stdout)
    if stderr:
        print(f"\n[⚠️] Error in {script_name}:\n{stderr}")

def main():
    parser = argparse.ArgumentParser(description="WebPenAut - Automated Web Reconnaissance")
    parser.add_argument("-r", choices=["recon"], default="recon", nargs="?", help="Specify the script to run (default: recon)")
    parser.add_argument("-u", required=True, help="Target URL or domain")

    args = parser.parse_args()

    if args.r == "recon":
        run_script("recon/recon.py", args.u)
        run_script("recon/recon1.py", args.u)

if __name__ == "__main__":
    main()
