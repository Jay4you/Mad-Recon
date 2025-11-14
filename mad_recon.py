#!/usr/bin/env python3
"""
Madrecon - Full recon pipeline script

Usage examples:
    ./madrecon.py -u example.com
    ./madrecon.py -u example.com -H "X-HackerOne: game0va" -t 10
    ./madrecon.py -u example.com --only subfinder,wayback,httpx
    ./madrecon.py -u example.com --skip ffuf,gobuster
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import subprocess
import os
import sys
import shutil
import time

# --- Configure available tool names here (used for --only/--skip) ---
ALL_TOOLS = [
    "subfinder",
    "assetfinder",
    "amass",
    "httpx",
    "waybackurls",
    "gau",
    "katana",
    "nuclei",
    "naabu",
    "dnsx",
    "ffuf",
    "gobuster",
    "dalfox",
    "gf",
    "uro",
    "unfurl",
    "httprobe",
]

# Tools that accept headers via '-H' or '--header' flags
TOOLS_WITH_HEADERS = {"httpx", "nuclei", "dalfox", "katana", "ffuf", "gobuster"}

# Helper functions
def which(tool):
    return shutil.which(tool) is not None

def write_file(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content if content is not None else "")

def run_cmd(cmd, outpath=None):
    """
    Runs command (list) and writes stdout+stderr to outpath if provided.
    Returns tuple(stdout, stderr, returncode)
    """
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        if outpath:
            # write both stdout and stderr so we don't lose useful info
            with open(outpath, "w", encoding="utf-8") as f:
                if stdout:
                    f.write(stdout)
                if stderr:
                    f.write("\n--- STDERR ---\n")
                    f.write(stderr)
        return stdout, stderr, proc.returncode
    except Exception as e:
        if outpath:
            write_file(outpath, f"Error executing command {cmd}: {e}\n")
        return "", str(e), 1

def ensure_tool(tool, outdir):
    """Check presence of tool; if missing, create a missing file and return False"""
    if not which(tool):
        write_file(os.path.join(outdir, f"{tool}_missing.txt"),
                   f"Tool '{tool}' not found in PATH. Install it and re-run.\n")
        return False
    return True

def safe_join(outdir, name):
    """Return a safe file path for outputs"""
    return os.path.join(outdir, name)

# --- Module wrappers (each writes to its own file immediately) ---

def subfinder_module(domain, outdir):
    out = safe_join(outdir, f"subfinder_{domain}.txt")
    if not ensure_tool("subfinder", outdir):
        return
    cmd = ["subfinder", "-d", domain, "-silent"]
    run_cmd(cmd, out)

def assetfinder_module(domain, outdir):
    out = safe_join(outdir, f"assetfinder_{domain}.txt")
    if not ensure_tool("assetfinder", outdir):
        return
    cmd = ["assetfinder", "--subs-only", domain]
    run_cmd(cmd, out)

def amass_module(domain, outdir):
    out = safe_join(outdir, f"amass_{domain}.txt")
    if not ensure_tool("amass", outdir):
        return
    cmd = ["amass", "enum", "-passive", "-d", domain]
    run_cmd(cmd, out)

def wayback_module(domain, outdir):
    out = safe_join(outdir, f"wayback_{domain}.txt")
    if not ensure_tool("waybackurls", outdir):
        return
    cmd = ["waybackurls", domain]
    run_cmd(cmd, out)

def gau_module(domain, outdir):
    out = safe_join(outdir, f"gau_{domain}.txt")
    if not ensure_tool("gau", outdir):
        return
    cmd = ["gau", domain]
    run_cmd(cmd, out)

def katana_module(domain, outdir, headers):
    out = safe_join(outdir, f"katana_{domain}.txt")
    if not ensure_tool("katana", outdir):
        return
    cmd = ["katana", "-u", domain, "-silent", "-depth", "2"]
    # katana supports -H style headers (per earlier requirements)
    for h in headers:
        cmd.extend(["-H", h])
    run_cmd(cmd, out)

def httpx_module(input_file, outdir, headers):
    out = safe_join(outdir, f"httpx_live_{os.path.basename(input_file)}.txt")
    if not ensure_tool("httpx", outdir):
        return
    cmd = ["httpx", "-l", input_file, "-silent", "-status-code", "-title", "-follow-redirects"]
    for h in headers:
        cmd.extend(["-H", h])
    run_cmd(cmd, out)

def nuclei_module(input_file, outdir, headers):
    out = safe_join(outdir, f"nuclei_{os.path.basename(input_file)}.txt")
    if not ensure_tool("nuclei", outdir):
        return
    cmd = ["nuclei", "-l", input_file, "-silent"]
    for h in headers:
        cmd.extend(["-H", h])
    run_cmd(cmd, out)

def naabu_module(input_file, outdir):
    out = safe_join(outdir, f"naabu_{os.path.basename(input_file)}.txt")
    if not ensure_tool("naabu", outdir):
        return
    cmd = ["naabu", "-list", input_file, "-silent", "-top-100"]
    run_cmd(cmd, out)

def dnsx_module(input_file, outdir):
    out = safe_join(outdir, f"dnsx_{os.path.basename(input_file)}.txt")
    if not ensure_tool("dnsx", outdir):
        return
    cmd = ["dnsx", "-l", input_file, "-silent"]
    run_cmd(cmd, out)

def ffuf_module(wordlist, url_template, outdir, headers):
    out = safe_join(outdir, f"ffuf_{int(time.time())}.txt")
    if not ensure_tool("ffuf", outdir):
        return
    cmd = ["ffuf", "-w", wordlist, "-u", url_template, "-mc", "200,301,302", "-s"]
    for h in headers:
        cmd.extend(["-H", h])
    run_cmd(cmd, out)

def gobuster_module(wordlist, url, outdir, headers):
    out = safe_join(outdir, f"gobuster_{int(time.time())}.txt")
    if not ensure_tool("gobuster", outdir):
        return
    cmd = ["gobuster", "dir", "-w", wordlist, "-u", url, "-q"]
    for h in headers:
        cmd.extend(["-H", h])
    run_cmd(cmd, out)

def dalfox_module(input_file, outdir, headers):
    out = safe_join(outdir, f"dalfox_{os.path.basename(input_file)}.txt")
    if not ensure_tool("dalfox", outdir):
        return
    cmd = ["dalfox", "file", input_file, "-o", out, "-silent"]
    # dalfox accepts headers with '-H'
    for h in headers:
        cmd.extend(["-H", h])
    # dalfox writes to file itself with -o, but we still run via run_cmd so a wrapper file is created
    run_cmd(cmd, None)

def gf_module(input_file, outdir):
    # gf is usually used as filter; write multiple param files
    base = os.path.splitext(os.path.basename(input_file))[0]
    outputs = {}
    if not ensure_tool("gf", outdir):
        return
    # common gf patterns we want
    patterns = {"xss": f"{base}_gf_xss.txt", "sqli": f"{base}_gf_sqli.txt",
                "redirect": f"{base}_gf_redirect.txt", "ssrf": f"{base}_gf_ssrf.txt"}
    for pat, name in patterns.items():
        out = safe_join(outdir, name)
        cmd = ["bash", "-lc", f"cat {input_file} | gf {pat} || true"]
        stdout, stderr, rc = run_cmd(cmd, out)
        outputs[pat] = out
    return outputs

def uro_module(input_files, outdir):
    out = safe_join(outdir, f"uro_{int(time.time())}.txt")
    if not ensure_tool("uro", outdir):
        return
    # uro expects stdin - we'll cat all inputs into it
    cmd = ["bash", "-lc", f"cat {' '.join(input_files)} | uro || true"]
    run_cmd(cmd, out)

def unfurl_module(input_file, outdir):
    out = safe_join(outdir, f"unfurl_{os.path.basename(input_file)}.txt")
    if not ensure_tool("unfurl", outdir):
        return
    cmd = ["unfurl", "keys", "-i", input_file]
    run_cmd(cmd, out)

def httprobe_module(input_file, outdir):
    out = safe_join(outdir, f"httprobe_{os.path.basename(input_file)}.txt")
    if not ensure_tool("httprobe", outdir):
        return
    cmd = ["httprobe"]
    # httprobe reads from stdin
    cmd = ["bash", "-lc", f"cat {input_file} | httprobe -prefer-https || true"]
    run_cmd(cmd, out)

# --- Orchestration ---

def merge_unique(files, dest):
    """Merge multiple files into dest with unique sorted lines"""
    lines = set()
    for f in files:
        if os.path.exists(f):
            with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                for l in fh:
                    l = l.strip()
                    if l:
                        lines.add(l)
    with open(dest, "w", encoding="utf-8") as out:
        for l in sorted(lines):
            out.write(l + "\n")

def prepare_subdomains(outdir, domain):
    """Run subdomain enumeration tools in parallel and merge results"""
    tools = [subfinder_module, assetfinder_module, amass_module]
    temp_files = []
    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = {ex.submit(func, domain, outdir): func for func in tools}
        for fut in as_completed(futures):
            func = futures[fut]
            # nothing required here; modules write files themselves
    # expected produced files:
    temp_files = [
        os.path.join(outdir, f"subfinder_{domain}.txt"),
        os.path.join(outdir, f"assetfinder_{domain}.txt"),
        os.path.join(outdir, f"amass_{domain}.txt")
    ]
    merged = os.path.join(outdir, f"all_subs_{domain}.txt")
    merge_unique(temp_files, merged)
    return merged

def prepare_urls_from_archives(outdir, domain):
    """Run wayback and gau in parallel and merge"""
    with ThreadPoolExecutor(max_workers=2) as ex:
        ex.submit(wayback_module, domain, outdir)
        ex.submit(gau_module, domain, outdir)
    wayback = os.path.join(outdir, f"wayback_{domain}.txt")
    gauf = os.path.join(outdir, f"gau_{domain}.txt")
    urls_all = os.path.join(outdir, f"urls_all_{domain}.txt")
    merge_unique([wayback, gauf], urls_all)
    return urls_all

def run_all(domain, outdir, headers, threads, only_set=None, skip_set=None):
    # Create directory
    os.makedirs(outdir, exist_ok=True)

    # Step 1: subdomains
    if (only_set and "subfinder" not in only_set) or (skip_set and "subfinder" in skip_set):
        # skip subfinder explicitly
        pass
    subdomains_file = prepare_subdomains(outdir, domain)

    # Also run katana, wayback, gau in parallel
    tasks = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        # katana (crawler)
        if (not only_set or "katana" in only_set) and (not skip_set or "katana" not in skip_set):
            tasks.append(ex.submit(katana_module, domain, outdir, headers))
        # archives
        if (not only_set or "waybackurls" in only_set) and (not skip_set or "waybackurls" not in skip_set):
            tasks.append(ex.submit(wayback_module, domain, outdir))
        if (not only_set or "gau" in only_set) and (not skip_set or "gau" not in skip_set):
            tasks.append(ex.submit(gau_module, domain, outdir))
        # assetfinder/amass already run in prepare_subdomains
        # wait for the archive tasks to finish so urls_all exists
        for t in as_completed(tasks):
            pass

    urls_all = os.path.join(outdir, f"urls_all_{domain}.txt")
    merge_unique([os.path.join(outdir, f"wayback_{domain}.txt"),
                  os.path.join(outdir, f"gau_{domain}.txt")], urls_all)

    # Step 2: probe live subdomains with httpx (depends on subdomains)
    if (not only_set or "httpx" in only_set) and (not skip_set or "httpx" not in skip_set):
        # httpx accepts headers
        httpx_module(subdomains_file, outdir, headers)

    # Step 3: run dnsx / naabu / nuclei against live hosts or subs
    # Decide input file for port scanning and nuclei: prefer httpx live output if present
    httpx_out = safe_join(outdir, f"httpx_live_{os.path.basename(subdomains_file)}.txt")
    if os.path.exists(httpx_out):
        input_for_scans = httpx_out
    else:
        input_for_scans = subdomains_file

    # dnsx
    if (not only_set or "dnsx" in only_set) and (not skip_set or "dnsx" not in skip_set):
        dnsx_module(input_for_scans, outdir)

    # naabu
    if (not only_set or "naabu" in only_set) and (not skip_set or "naabu" not in skip_set):
        naabu_module(input_for_scans, outdir)

    # nuclei (supports headers)
    if (not only_set or "nuclei" in only_set) and (not skip_set or "nuclei" not in skip_set):
        nuclei_module(input_for_scans, outdir, headers)

    # Step 4: parameter extraction and XSS scanning from urls_all
    if os.path.exists(urls_all):
        # use gf to create param-specific lists
        if (not only_set or "gf" in only_set) and (not skip_set or "gf" not in skip_set):
            gf_outputs = gf_module(urls_all, outdir)  # returns dict with xss/sqli/etc file names
            if gf_outputs and "xss" in gf_outputs:
                xss_file = gf_outputs["xss"]
                # dalfox
                if (not only_set or "dalfox" in only_set) and (not skip_set or "dalfox" not in skip_set):
                    dalfox_module(xss_file, outdir, headers)

        # uro - filter and dedupe urls
        if (not only_set or "uro" in only_set) and (not skip_set or "uro" not in skip_set):
            uro_module([urls_all], outdir)

        # unfurl keys
        if (not only_set or "unfurl" in only_set) and (not skip_set or "unfurl" not in skip_set):
            unfurl_module(urls_all, outdir)

    # Step 5: httprobe on subs or urls list
    if (not only_set or "httprobe" in only_set) and (not skip_set or "httprobe" not in skip_set):
        httprobe_module(subdomains_file, outdir)

    # Step 6: fuzzers (ffuf/gobuster) - these require wordlists and urls; we provide examples but do not auto-run large jobs
    # The script will only run ffuf/gobuster if the user explicitly requested them via --only or not skipped.
    if (not only_set or "ffuf" in only_set) and (not skip_set or "ffuf" not in skip_set):
        # require the user to place a wordlist at ./wordlists/common.txt or skip
        wl = "wordlists/common.txt"
        if os.path.exists(wl):
            # Example template: httpx results might have scheme+host - pick first live host for template
            first_host = None
            if os.path.exists(input_for_scans):
                with open(input_for_scans, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        first_host = line.strip().split()[0]
                        if first_host:
                            break
            if first_host:
                # ffuf expects a URL template, e.g. https://example/FUZZ
                url_template = first_host.rstrip("/") + "/FUZZ"
                ffuf_module(wl, url_template, outdir, headers)
        else:
            write_file(safe_join(outdir, "ffuf_missing_wordlist.txt"),
                       "ffuf wordlist not found at wordlists/common.txt; skipping ffuf.\n")

    if (not only_set or "gobuster" in only_set) and (not skip_set or "gobuster" not in skip_set):
        wl = "wordlists/common.txt"
        if os.path.exists(wl):
            # pick first host as target
            first_host = None
            if os.path.exists(input_for_scans):
                with open(input_for_scans, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        first_host = line.strip().split()[0]
                        if first_host:
                            break
            if first_host:
                gobuster_module(wl, first_host, outdir, headers)
        else:
            write_file(safe_join(outdir, "gobuster_missing_wordlist.txt"),
                       "gobuster wordlist not found at wordlists/common.txt; skipping gobuster.\n")

    # Final: create a merged 'summary' file listing outputs present
    summary = []
    for fname in sorted(os.listdir(outdir)):
        summary.append(fname)
    write_file(os.path.join(outdir, "outputs_index.txt"), "\n".join(summary))
    print(f"Madrecon run completed. Outputs are in: {outdir}")

# --- CLI / Arg parsing ---

def parse_csv_set(s):
    if not s:
        return None
    return set([x.strip() for x in s.split(",") if x.strip()])

def main_cli():
    parser = argparse.ArgumentParser(description="Madrecon - full recon automation")
    parser.add_argument("-u", "--url", required=True, help="Target domain (example.com)")
    parser.add_argument("-o", "--output", default="outputs", help="Output directory")
    parser.add_argument("-H", "--header", action="append", default=[], help="Custom header, repeatable: -H 'X-H: val'")
    parser.add_argument("-t", "--threads", type=int, default=8, help="Thread count for parallel operations")
    parser.add_argument("--only", help="Comma-separated list of tools to run (from list)")
    parser.add_argument("--skip", help="Comma-separated list of tools to skip")
    args = parser.parse_args()

    only_set = parse_csv_set(args.only)
    skip_set = parse_csv_set(args.skip)

    # Validate only/skip values
    for sname, sset in (("only", only_set), ("skip", skip_set)):
        if sset:
            invalid = [x for x in sset if x not in ALL_TOOLS]
            if invalid:
                print(f"Invalid tool names in --{sname}: {', '.join(invalid)}")
                print("Valid tools:", ", ".join(ALL_TOOLS))
                sys.exit(1)

    run_all(args.url, args.output, args.header, args.threads, only_set, skip_set)

if __name__ == "__main__":
    main_cli()
