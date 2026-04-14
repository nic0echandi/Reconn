import os
import sys
import subprocess
import datetime
import random
import time
import argparse
from collections import defaultdict

TARGET = None
OUTPUT_DIR = None
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

WORDLIST = os.path.join(SCRIPT_DIR, "wordlists/subdomains.txt")
RESOLVERS_FILE = os.path.join(SCRIPT_DIR, "resolvers.txt")
RESOLVERS_WARM = os.path.join(SCRIPT_DIR, "resolvers_warm.txt")
ENV_FILE = os.path.join(SCRIPT_DIR, ".env")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
]

def load_env():
    global WAF_DELAY, RATE_LIMIT, PROXY_LIST
    env_vars = {}
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    env_vars[key] = value.strip()
    WAF_DELAY = float(env_vars.get('RECON_WAF_DELAY', os.getenv('RECON_WAF_DELAY', '1')))
    RATE_LIMIT = int(env_vars.get('RECON_RATE_LIMIT', os.getenv('RECON_RATE_LIMIT', '100')))
    proxy_str = env_vars.get('RECON_PROXIES', os.getenv('RECON_PROXIES', ''))
    PROXY_LIST = [p.strip() for p in proxy_str.split(',') if p.strip()]

WAF_DELAY = 1.0
RATE_LIMIT = 100
PROXY_LIST = []

load_env()

def get_random_ua():
    return random.choice(USER_AGENTS)

def get_proxy_for_tool():
    if PROXY_LIST:
        return random.choice(PROXY_LIST)
    return None

def log_info(msg):
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] [INFO] {msg}")

def log_success(msg):
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] [SUCCESS] {msg}")

def log_warning(msg):
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] [WARNING] {msg}")

def log_error(msg):
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] [ERROR] {msg}")

def check_tool(name):
    try:
        subprocess.run([name, "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def check_all_tools():
    tools = ["subfinder", "shuffledns", "massdns", "httpx", "naabu", "nmap", "katana", "waybackurls", "gf", "nuclei", "amass", "assetfinder", "nuclei-waf"]
    missing = []
    for tool in tools:
        if not check_tool(tool):
            missing.append(tool)
    if missing:
        log_warning(f"Tools not found: {', '.join(missing)}")
        log_warning("Some features may not work. Install them for full functionality.")
    return len(missing) == 0

def setup_directories():
    dirs = ["subdomains", "passive", "active", "discovery", "scans", "vulns", "waf"]
    for d in dirs:
        os.makedirs(os.path.join(OUTPUT_DIR, d), exist_ok=True)

def get_output_path(category, filename):
    return os.path.join(OUTPUT_DIR, category, filename)

def run_command(command, output_file=None, retries=1, delay=0):
    for attempt in range(retries):
        try:
            if delay > 0:
                time.sleep(delay)
            log_info(f"Running: {' '.join(command)}")
            if output_file:
                with open(output_file, 'w') as f, open(os.devnull, 'w') as devnull:
                    subprocess.run(command, check=True, stdout=f, stderr=devnull, text=True, timeout=600)
            else:
                with open(os.devnull, 'w') as devnull:
                    subprocess.run(command, check=True, stdout=devnull, stderr=devnull, text=True, timeout=600)
            return True
        except subprocess.CalledProcessError as e:
            log_warning(f"Command failed (attempt {attempt + 1}/{retries}): {e}")
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
        except subprocess.TimeoutExpired:
            log_warning(f"Command timed out (attempt {attempt + 1}/{retries})")
        except FileNotFoundError as e:
            log_error(f"Tool not found: {e}")
            return False
    return False

def run_piped_commands(command1, command2, output_file=None, delay=0):
    if delay > 0:
        time.sleep(delay)
    try:
        log_info(f"Piping: {' '.join(command1)} | {' '.join(command2)}")
        proc1 = subprocess.Popen(command1, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if output_file:
            with open(output_file, 'w') as f:
                result = subprocess.run(command2, stdin=proc1.stdout, stdout=f, stderr=subprocess.PIPE, check=True, text=True, timeout=600)
        else:
            with open(os.devnull, 'w') as devnull:
                result = subprocess.run(command2, stdin=proc1.stdout, stdout=devnull, stderr=subprocess.PIPE, check=True, text=True, timeout=600)
        proc1.stdout.close()
        return True
    except subprocess.CalledProcessError as e:
        log_warning(f"Piped command failed: {e}")
        if e.stderr:
            log_warning(f"Tool error: {e.stderr.strip()}")
        return False
    except FileNotFoundError as e:
        log_error(f"Tool not found: {e}")
        return False
    except subprocess.TimeoutExpired:
        log_warning("Piped command timed out")
        return False

def merge_and_dedupe(input_files, output_file):
    unique = set()
    for fname in input_files:
        if os.path.exists(fname) and os.path.getsize(fname) > 0:
            with open(fname, 'r') as f:
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        unique.add(stripped)
    if unique:
        with open(output_file, 'w') as f:
            for item in sorted(unique):
                f.write(item + '\n')
        return True
    return False

def passive_enumeration():
    log_info("=== Phase 1: Passive Enumeration ===")
    subfinder_out = get_output_path("passive", "subfinder.txt")
    amass_out = get_output_path("passive", "amass.txt")
    assetfinder_out = get_output_path("passive", "assetfinder.txt")

    subfinder_ok = run_command(["subfinder", "-d", TARGET, "-o", subfinder_out, "-silent"])
    if not subfinder_ok:
        log_warning("subfinder failed")

    if check_tool("amass"):
        run_command(["amass", "enum", "-passive", "-d", TARGET, "-o", amass_out, "-silent"])

    if check_tool("assetfinder"):
        run_command(["assetfinder", "--subs-only", TARGET], assetfinder_out)

    all_passive = get_output_path("passive", "all_passive.txt")
    merge_and_dedupe([subfinder_out, amass_out, assetfinder_out], all_passive)

    log_success(f"Passive enumeration done: {all_passive}")
    return all_passive

def active_enumeration():
    log_info("=== Phase 2: Active Enumeration (Brute-force) ===")

    if not os.path.exists(RESOLVERS_FILE) or os.path.getsize(RESOLVERS_FILE) == 0:
        log_error(f"Resolvers file missing or empty: {RESOLVERS_FILE}")
        return None

    if not os.path.exists(WORDLIST) or os.path.getsize(WORDLIST) == 0:
        log_error(f"Wordlist missing or empty: {WORDLIST}")
        return None

    bruteforce_out = get_output_path("active", "bruteforce.txt")

    shuffledns_ok = run_command([
        "shuffledns", "-d", TARGET, "-w", WORDLIST, "-r", RESOLVERS_FILE,
        "-mode", "bruteforce", "-t", "500", "-o", bruteforce_out
    ])

    if not shuffledns_ok:
        log_warning("shuffledns failed, trying massdns direct brute-force")
        massdns_bruteforce = get_output_path("active", "massdns_bruteforce.txt")
        with open(WORDLIST, 'r') as f:
            subs = [line.strip() + "." + TARGET for line in f if line.strip()]
        with open(get_output_path("active", "temp_subs.txt"), 'w') as f:
            f.write('\n'.join(subs))
        run_piped_commands(
            ["cat", get_output_path("active", "temp_subs.txt")],
            ["massdns", "-r", RESOLVERS_FILE, "-t", "A", "-o", "S"],
            massdns_bruteforce
        )

    log_success("Active enumeration done")
    return bruteforce_out

def resolve_subdomains(all_subs_file):
    log_info("=== Phase 3: DNS Resolution ===")

    resolved_all = get_output_path("discovery", "resolved_all.txt")
    massdns_cmd = ["massdns", "-r", RESOLVERS_FILE, "-t", "A", "-o", "S"]

    if not run_piped_commands(["cat", all_subs_file], massdns_cmd, resolved_all):
        log_error("massdns resolution failed")
        return None, None

    resolved_domains = get_output_path("discovery", "resolved_domains.txt")
    resolved_ips = get_output_path("discovery", "resolved_ips.txt")

    try:
        subprocess.run(
            f"cat {resolved_all} | awk '{{print $1}}' | sed 's/\\.$//' > {resolved_domains}",
            shell=True, check=True, capture_output=True
        )
        subprocess.run(
            f"grep ' A ' {resolved_all} | awk '{{print $NF}}' > {resolved_ips}",
            shell=True, check=True, capture_output=True
        )
    except subprocess.CalledProcessError:
        log_warning("Error cleaning massdns output")

    for f in [resolved_ips, resolved_domains]:
        if not os.path.exists(f) or os.path.getsize(f) == 0:
            open(f, 'w').close()

    log_success(f"DNS resolution done: {len(open(resolved_ips).readlines()) if os.path.exists(resolved_ips) else 0} IPs")

    ips_count = len(open(resolved_ips).readlines()) if os.path.exists(resolved_ips) and os.path.getsize(resolved_ips) > 0 else 0
    log_info(f"Found {ips_count} unique IPs")
    return resolved_domains, resolved_ips

def check_active_services(resolved_domains):
    log_info("=== Phase 4: HTTP/HTTPS Service Detection ===")

    active_urls = get_output_path("discovery", "active_urls.txt")

    if not os.path.exists(resolved_domains) or os.path.getsize(resolved_domains) == 0:
        log_warning("No domains to check for HTTP/HTTPS")
        open(active_urls, 'w').close()
        return active_urls

    httpx_command = [
        "httpx",
        "-list", resolved_domains,
        "-silent",
        "-status-code",
        "-title",
        "-tech-detect",
        "-o", active_urls
    ]

    proxy = get_proxy_for_tool()
    if proxy:
        httpx_command.extend(["-proxy", proxy])
        log_info(f"Using proxy: {proxy}")

    run_piped_commands(["cat", resolved_domains], httpx_command, active_urls)

    if not os.path.exists(active_urls) or os.path.getsize(active_urls) == 0:
        log_warning("httpx found no active HTTP services")
        open(active_urls, 'w').close()

    log_success(f"HTTP/HTTPS detection done: {sum(1 for _ in open(active_urls))} active URLs" if os.path.exists(active_urls) and os.path.getsize(active_urls) > 0 else "No active URLs found")
    return active_urls

def port_scan(resolved_ips):
    log_info("=== Phase 5: Port Scanning ===")

    open_ports = get_output_path("discovery", "open_ports.txt")

    if not os.path.exists(resolved_ips) or os.path.getsize(resolved_ips) == 0:
        log_warning("No IPs to scan")
        open(open_ports, 'w').close()
        return open_ports

    proxy = get_proxy_for_tool()
    if proxy:
        naabu_command = ["naabu", "-list", resolved_ips, "-o", open_ports, "-c", "50", "-rate", str(RATE_LIMIT), "-proxy", proxy]
        log_info(f"Using proxy for naabu: {proxy}")
        naabu_ok = run_command(naabu_command)
    else:
        naabu_ok = run_command([
            "naabu",
            "-list", resolved_ips,
            "-o", open_ports,
            "-c", "50",
            "-rate", str(RATE_LIMIT)
        ])

    if not naabu_ok:
        log_warning("naabu scan failed, trying nmap fallback")
        nmap_out = get_output_path("discovery", "nmap_quick.txt")
        run_command(["nmap", "-T4", "-F", "-iL", resolved_ips, "-oG", nmap_out])

    log_success("Port scanning done")
    return open_ports

def service_version_detection(open_ports, resolved_ips):
    log_info("=== Phase 6: Service Version Detection ===")

    nmap_versions = get_output_path("scans", "nmap_versions.txt")

    if not os.path.exists(open_ports) or os.path.getsize(open_ports) == 0:
        log_warning("No ports to scan for versions")
        open(nmap_versions, 'w').close()
        return nmap_versions

    unique_ports = set()
    try:
        with open(open_ports, 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) == 2:
                    unique_ports.add(parts[1].strip())
    except Exception:
        pass

    if not unique_ports:
        log_warning("Could not extract ports from naabu output")
        open(nmap_versions, 'w').close()
        return nmap_versions

    port_list = ",".join(sorted(unique_ports))

    nmap_command = [
        "nmap",
        "-sV",
        "-sC",
        "-p", port_list,
        "-iL", resolved_ips,
        "-oN", nmap_versions,
        "--version-intensity", "5"
    ]

    log_info(f"Running Nmap version scan on {len(unique_ports)} ports")
    run_command(nmap_command)

    log_success("Service version detection done")
    return nmap_versions

def waf_detection(active_urls):
    log_info("=== Phase 7: WAF Detection ===")

    waf_log = get_output_path("waf", "waf_detected.txt")
    detected_wafs = set()

    if not os.path.exists(active_urls) or os.path.getsize(active_urls) == 0:
        log_warning("No URLs to check for WAF")
        open(waf_log, 'w').close()
        return waf_log

    try:
        result = subprocess.run(
            ["wafw00f", "-l"],
            capture_output=True,
            text=True
        )
        waf_list = result.stdout.strip().split('\n') if result.returncode == 0 else []
    except FileNotFoundError:
        log_warning("wafw00f not installed, using httpx built-in WAF detection")
        waf_list = []

    if waf_list:
        result = subprocess.run(
            ["wafw00f", "-i", active_urls],
            capture_output=True,
            text=True,
            timeout=300
        )
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if "is behind" in line.lower() or "detected" in line.lower():
                    detected_wafs.add(line.strip())

    httpx_waf_out = get_output_path("waf", "httpx_waf.txt")
    httpx_waf_command = [
        "httpx",
        "-list", active_urls,
        "-tls-probe",
        "-cname-probe",
        "-o", httpx_waf_out
    ]
    proxy = get_proxy_for_tool()
    if proxy:
        httpx_waf_command.extend(["-proxy", proxy])
        log_info(f"Using proxy for WAF detection: {proxy}")
    run_command(httpx_waf_command)

    with open(waf_log, 'w') as f:
        for waf in sorted(detected_wafs):
            f.write(waf + '\n')

    log_success(f"WAF detection done: {len(detected_wafs)} WAFs potentially detected")
    return waf_log

def url_crawling(active_urls):
    log_info("=== Phase 8: URL Crawling & Endpoint Discovery ===")

    discovered_endpoints = get_output_path("discovery", "discovered_endpoints.txt")
    wayback_data = get_output_path("discovery", "wayback_data.txt")

    if os.path.exists(active_urls) and os.path.getsize(active_urls) > 0:
        run_piped_commands(
            ["katana", "-list", active_urls, "-jc", "-silent", "-d", "5"],
            ["anew", discovered_endpoints],
            delay=WAF_DELAY
        )

    run_piped_commands(
        ["waybackurls", TARGET],
        ["anew", wayback_data],
        delay=WAF_DELAY
    )

    run_piped_commands(
        ["cat", wayback_data],
        ["unfurl", "--format", "key"],
        get_output_path("discovery", "params.txt")
    )

    if os.path.exists(discovered_endpoints) and os.path.getsize(discovered_endpoints) > 0:
        with open(discovered_endpoints, 'r') as f:
            endpoints = f.readlines()
        with open(wayback_data, 'a') as f:
            for ep in endpoints:
                if ep.strip() and ep.strip() not in open(wayback_data).read():
                    f.write(ep)

    log_success("URL crawling done")
    return discovered_endpoints

def vulnerability_filtering(discovered_endpoints):
    log_info("=== Phase 9: Vulnerability Pattern Filtering ===")

    xss_endpoints = get_output_path("vulns", "xss_endpoints.txt")
    rce_endpoints = get_output_path("vulns", "rce_endpoints.txt")
    ssti_endpoints = get_output_path("vulns", "ssti_endpoints.txt")
    sqli_endpoints = get_output_path("vulns", "sqli_endpoints.txt")
    ssrf_endpoints = get_output_path("vulns", "ssrf_endpoints.txt")
    lfi_endpoints = get_output_path("vulns", "lfi_endpoints.txt")
    redirect_endpoints = get_output_path("vulns", "redirect_endpoints.txt")
    crlf_endpoints = get_output_path("vulns", "crlf_endpoints.txt")

    if not os.path.exists(discovered_endpoints) or os.path.getsize(discovered_endpoints) == 0:
        log_warning("No endpoints to filter")
        for f in [xss_endpoints, rce_endpoints, ssti_endpoints, sqli_endpoints, ssrf_endpoints, lfi_endpoints, redirect_endpoints, crlf_endpoints]:
            open(f, 'w').close()
        return

    patterns = [
        ("xss", xss_endpoints),
        ("rce", rce_endpoints),
        ("ssti", ssti_endpoints),
        ("sqli", sqli_endpoints),
        ("ssrf", ssrf_endpoints),
        ("lfi", lfi_endpoints),
        ("redirect", redirect_endpoints),
        ("crlf", crlf_endpoints),
    ]

    for pattern, output in patterns:
        run_piped_commands(["cat", discovered_endpoints], ["gf", pattern], output, delay=WAF_DELAY)

    log_success("Vulnerability filtering done")

def nuclei_scan(active_urls):
    log_info("=== Phase 10: Nuclei Vulnerability Scanning ===")

    cves_scan = get_output_path("scans", "cves_scan.txt")
    exposure_scan = get_output_path("scans", "exposure_scan.txt")
    misconfig_scan = get_output_path("scans", "misconfig_scan.txt")
    panels_scan = get_output_path("scans", "panels_scan.txt")
    tokens_scan = get_output_path("scans", "tokens_scan.txt")
    vulnerabilities_scan = get_output_path("scans", "vulnerabilities_scan.txt")
    js_scan = get_output_path("scans", "js_scan.txt")
    dns_scan = get_output_path("scans", "dns_scan.txt")

    if not os.path.exists(active_urls) or os.path.getsize(active_urls) == 0:
        log_warning("No URLs for nuclei scanning")
        for f in [cves_scan, exposure_scan, misconfig_scan, panels_scan, tokens_scan, vulnerabilities_scan, js_scan, dns_scan]:
            open(f, 'w').close()
        return

    nuclei_base = [
        "nuclei",
        "-l", active_urls,
        "-c", "20",
        "-bulk-size", "25",
        "-rate-limit", str(RATE_LIMIT),
        "-timeout", "10"
    ]
    proxy = get_proxy_for_tool()
    if proxy:
        nuclei_base.extend(["-proxy", proxy])
        log_info(f"Using proxy for nuclei: {proxy}")

    log_info("Scanning for CVEs...")
    run_command(nuclei_base + ["-t", "cves/", "-o", cves_scan], delay=WAF_DELAY)

    log_info("Scanning for vulnerabilities...")
    run_command(nuclei_base + ["-t", "vulnerabilities/", "-o", vulnerabilities_scan], delay=WAF_DELAY)

    log_info("Scanning for exposures...")
    run_command(nuclei_base + ["-t", "exposure/", "-o", exposure_scan], delay=WAF_DELAY)

    log_info("Scanning for misconfigurations...")
    run_command(nuclei_base + ["-t", "security-misconfiguration/", "-o", misconfig_scan], delay=WAF_DELAY)

    log_info("Scanning for exposed panels...")
    run_command(nuclei_base + ["-t", "exposed-panel/", "-o", panels_scan], delay=WAF_DELAY)

    log_info("Scanning for exposed tokens...")
    run_command(nuclei_base + ["-t", "exposed-tokens/", "-o", tokens_scan], delay=WAF_DELAY)

    log_info("Scanning DNS templates...")
    run_command(nuclei_base + ["-t", "dns/", "-o", dns_scan], delay=WAF_DELAY)

    js_urls_file = get_output_path("discovery", "js_urls.txt")
    with open(js_urls_file, 'w') as f:
        for url in open(active_urls).readlines():
            if '.js' in url.lower():
                f.write(url)

    if os.path.exists(js_urls_file) and os.path.getsize(js_urls_file) > 0:
        log_info("Scanning JavaScript files...")
        run_command(nuclei_base + ["-l", js_urls_file, "-t", "javascript/", "-o", js_scan], delay=WAF_DELAY)

    log_success("Nuclei scanning done")

def subdomain_takeover_check(all_subs_file):
    log_info("=== Phase 11: Subdomain Takeover Detection ===")

    takeover_scan = get_output_path("vulns", "subdomain_takeover.txt")

    if not os.path.exists(all_subs_file) or os.path.getsize(all_subs_file) == 0:
        log_warning("No subdomains for takeover check")
        open(takeover_scan, 'w').close()
        return

    run_command([
        "nuclei",
        "-l", all_subs_file,
        "-t", "vulnerabilities/network/subdomain-takeover/",
        "-o", takeover_scan,
        "-c", "20"
    ], delay=WAF_DELAY)

    log_success("Subdomain takeover check done")

def network_recon(resolved_ips):
    log_info("=== Phase 12: Advanced Network Recon ===")

    network_scan = get_output_path("scans", "network_scan.txt")

    if not os.path.exists(resolved_ips) or os.path.getsize(resolved_ips) == 0:
        log_warning("No IPs for network recon")
        open(network_scan, 'w').close()
        return

    run_command([
        "nuclei",
        "-l", resolved_ips,
        "-t", "network/",
        "-o", network_scan,
        "-c", "20",
        "-rate-limit", str(RATE_LIMIT)
    ], delay=WAF_DELAY)

    log_success("Network recon done")

def generate_summary():
    log_info("=== Generating Summary ===")

    summary_file = get_output_path("discovery", "summary.txt")

    stats = {}
    categories = {
        "subdomains": ["all_subdomains.txt", "passive/all_passive.txt", "active/bruteforce.txt"],
        "discovery": ["resolved_domains.txt", "resolved_ips.txt", "active_urls.txt", "discovered_endpoints.txt"],
        "scans": ["open_ports.txt", "nmap_versions.txt"],
        "vulns": ["xss_endpoints.txt", "rce_endpoints.txt", "ssti_endpoints.txt", "sqli_endpoints.txt", "ssrf_endpoints.txt", "lfi_endpoints.txt", "subdomain_takeover.txt"],
        "scans_nuclei": ["cves_scan.txt", "exposure_scan.txt", "misconfig_scan.txt", "panels_scan.txt", "tokens_scan.txt", "vulnerabilities_scan.txt", "dns_scan.txt", "js_scan.txt"]
    }

    for cat, files in categories.items():
        cat_count = 0
        for f in files:
            fpath = get_output_path(cat if cat != "scans_nuclei" else "scans", f.split('/')[-1] if '/' in f else f)
            if os.path.exists(fpath) and os.path.getsize(fpath) > 0:
                with open(fpath, 'r') as fh:
                    cat_count += len([l for l in fh if l.strip()])
        stats[cat] = cat_count

    with open(summary_file, 'w') as f:
        f.write(f"Recon Summary for {TARGET}\n")
        f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Output: {OUTPUT_DIR}\n\n")
        f.write("Results Count:\n")
        for cat, count in stats.items():
            f.write(f"  {cat}: {count}\n")

    log_success(f"Summary saved to {summary_file}")
    log_success(f"All results in: {OUTPUT_DIR}")

def main():
    global TARGET, OUTPUT_DIR

    parser = argparse.ArgumentParser(description="Advanced Reconnaissance Script v3")
    parser.add_argument("target", help="Target domain (e.g., example.com)")
    parser.add_argument("-o", "--output", help="Custom output directory")
    parser.add_argument("--no-waf-delay", action="store_true", help="Disable WAF evasion delays")
    parser.add_argument("--rate-limit", type=int, default=RATE_LIMIT, help="Rate limit for requests")
    args = parser.parse_args()

    TARGET = args.target

    if args.output:
        OUTPUT_DIR = args.output
    else:
        OUTPUT_DIR = os.path.join(SCRIPT_DIR, f"{TARGET}-{datetime.date.today()}")

    log_info(f"Target: {TARGET}")
    log_info(f"Output: {OUTPUT_DIR}")
    log_info(f"WAF Delay: {WAF_DELAY}s")
    log_info(f"Rate Limit: {RATE_LIMIT}")
    if PROXY_LIST:
        log_info(f"Proxies: {len(PROXY_LIST)} configured")
    else:
        log_info("Proxies: None (direct connection)")

    check_all_tools()

    setup_directories()

    if not os.path.exists(RESOLVERS_FILE) or os.path.getsize(RESOLVERS_FILE) == 0:
        log_error(f"Critical: Resolvers file missing or empty: {RESOLVERS_FILE}")
        sys.exit(1)

    if not os.path.exists(WORDLIST) or os.path.getsize(WORDLIST) == 0:
        log_error(f"Critical: Wordlist missing or empty: {WORDLIST}")
        sys.exit(1)

    passive_file = passive_enumeration()
    bruteforce_file = active_enumeration()

    all_subs = get_output_path("subdomains", "all_subdomains.txt")
    merge_and_dedupe([passive_file, bruteforce_file], all_subs)

    resolved_domains, resolved_ips = resolve_subdomains(all_subs)

    active_urls = check_active_services(resolved_domains)

    open_ports = port_scan(resolved_ips)

    service_version_detection(open_ports, resolved_ips)

    waf_detection(active_urls)

    discovered_endpoints = url_crawling(active_urls)

    vulnerability_filtering(discovered_endpoints)

    nuclei_scan(active_urls)

    subdomain_takeover_check(all_subs)

    network_recon(resolved_ips)

    generate_summary()

    log_success("Reconnaissance completed successfully!")

if __name__ == "__main__":
    main()
