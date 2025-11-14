#!/usr/bin/env python3

import argparse
import subprocess
import os
from concurrent.futures import ThreadPoolExecutor


def run_cmd(cmd, output_file=None):
    print(f"[+] Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if output_file:
            with open(output_file, 'w') as f:
                f.write(result.stdout)
        return result.stdout
    except Exception as e:
        print(f"[!] Error running command {' '.join(cmd)}: {e}")
        return ""


def run_wayback(url, outdir):
    output_file = os.path.join(outdir, "wayback_urls.txt")
    cmd = ["waybackurls", url]
    run_cmd(cmd, output_file)


def run_httpx(input_file, outdir, headers):
    output_file = os.path.join(outdir, "live_hosts.txt")
    cmd = ["httpx", "-l", input_file, "-silent", "-status-code", "-follow-redirects"]

    for h in headers:
        cmd.extend(["-H", h])

    run_cmd(cmd, output_file)


def main():
    parser = argparse.ArgumentParser(description="Madrecon – Automated Recon Pipeline")

    parser.add_argument("url", help="Target domain")
    parser.add_argument("--header", "-H", action="append", default=[], help="Custom header (e.g. -H 'X-Test: value')")
    parser.add_argument("--output", "-o", default="recon_output", help="Output directory")
    parser.add_argument("--wayback-only", action="store_true", help="Run only Wayback extraction")
    parser.add_argument("--httpx-only", action="store_true", help="Run only HTTPX")
    parser.add_argument("--threads", type=int, default=4, help="Thread count for parallel tasks")

    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    tasks = []

    if not args.httpx_only:
        tasks.append((run_wayback, (args.url, args.output)))

    if not args.wayback_only:
        wayback_file = os.path.join(args.output, "wayback_urls.txt")
        tasks.append((run_httpx, (wayback_file, args.output, args.header)))

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(func, *params) for func, params in tasks]
        for f in futures:
            f.result()

    print(f"Recon complete. Output saved in: {args.output}/")


if __name__ == "__main__":
    main()
