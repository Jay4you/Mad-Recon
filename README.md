-----------------------------------------
       MAD RECON — Recon Automation 
-----------------------------------------

This is the standalone README.md for the Madrecon Python Recon Toolkit.

(You can tell me anytime to expand, format, or style it professionally.)

---

# Madrecon Python Recon Toolkit

Madrecon is a fast, parallel, extensible automated reconnaissance framework for bug bounty hunters and penetration testers. It collects URLs, probes hosts, and stores outputs in real time — each tool writes its own results without waiting for others.

## Features

* **Parallel execution** using Python threads
* **Immediate output saving per tool** (no waiting for the full run)
* **Custom header support** for all tools that accept headers
* **Flexible flag system**
* **WaybackURL + HTTPX pipeline**
* Extensible Python architecture

## Tools Used

* `waybackurls` – Collect historical URLs
* `httpx` – Probe live URLs/domains

Ensure both are installed and available in your `$PATH`.

## Installation

Clone the repo:

```bash
git clone https://github.com/yourusername/madrecon
cd madrecon
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Make executable:

```bash
chmod +x madrecon.py
```

Run:

```bash
python3 madrecon.py -u example.com
```

## Usage

```
python3 madrecon.py [options]
```

### Required Flags

| Flag        | Description                       |
| ----------- | --------------------------------- |
| `-u, --url` | Target domain (e.g., example.com) |

### Optional Flags

| Flag             | Description                           |
| ---------------- | ------------------------------------- |
| `-H, --header`   | Add custom headers (multiple allowed) |
| `--wayback-only` | Run only waybackurls                  |
| `--httpx-only`   | Run only httpx                        |
| `-t, --threads`  | Thread count (default: 10)            |

Example with headers:

```bash
python3 madrecon.py -u example.com -H "X-HackerOne: game0va"
```

## Output Structure

Results are stored immediately per tool:

```
./outputs/
  ├── wayback_example.com.txt
  ├── httpx_example.com.txt
```

## Extending Madrecon

To add new tools:

1. Create a new Python function
2. Add it to the task runner
3. Output automatically gets its own file

## Example Workflow

```bash
python3 madrecon.py -u hackerone.com -H "X-Source: bounty" -t 20
```

Workflow:

1. Gather historical URLs (Wayback)
2. Probe for live hosts (HTTPX)
3. Save outputs immediately

## Troubleshooting

If `waybackurls` or `httpx` aren't found:

```bash
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

## Author

Built for high-performance bug bounty recon.

For badges, logos, diagrams, or installer scripts — ask anytime.
