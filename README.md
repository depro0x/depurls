# depurls

Collect URLs related to a target domain from multiple OSINT data sources:
Wayback Machine, Common Crawl, AlienVault OTX, urlscan.io, and (optionally) VirusTotal.

<p align="center">
<a href="https://github.com/depro0x/depurls"><img src="https://img.shields.io/badge/status-alpha-orange" alt="status"></a>
<a href="https://github.com/depro0x/depurls/issues"><img src="https://img.shields.io/github/issues/depro0x/depurls" alt="issues"></a>
</p>

## Features
- Parallel collection from multiple providers
- Automatic deduplication (uses system `sort -u`, falls back to Python)
- Simple local config file for API keys and per-domain Discord webhook notifications
- Console entry point: `depurls` after installation

## Installation

### Option 1: Install with pip (editable for local development)
```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
```

### Option 2: Install globally with pipx
```bash
pipx install git+https://github.com/depro0x/depurls.git
```

After installation you can run:
```bash
depurls -d example.com -o urls.txt
```

## Usage
```bash
depurls -d target.com -o output/urls.txt
```

### Arguments
| Flag | Description |
|------|-------------|
| `-d, --domain` | Target domain (required for collection or setup) |
| `-o, --output` | Output file to write unique URLs (required) |
| `--setup` | Interactive setup to store API keys & per-domain webhook |
| `-w, --workers` | Concurrent worker threads (default 5) |
| `-p, --providers` | One or more of: `wayback commoncrawl alienvault urlscan virustotal all` |

If `all` is provided (default), all providers are queried. VirusTotal is only used when a VT API key is configured via `--setup`; otherwise it's skipped automatically.

### Examples
Collect using all default providers (VirusTotal included only if API key configured):
```bash
depurls -d example.com -o urls.txt
```
Specify providers explicitly:
```bash
depurls -d example.com -o urls.txt -p wayback alienvault
```
Increase workers:
```bash
depurls -d example.com -o urls.txt -w 10
```
Setup config (API keys + webhook for a domain):
```bash
depurls --setup -d example.com
```

## Configuration & API Keys
A JSON config file is stored at:
```
~/.config/depurls/config.json
```
During `--setup`, you can enter:
- `URLSCAN_API_KEY`
- `VT_API_KEY` (VirusTotal)
- Discord webhook URL (saved per domain)

Environment variables are not used. Configure API keys and webhooks via the interactive `--setup` flow.

## Output
The final deduplicated list of URLs is written to the path passed to `-o/--output`. A temporary raw file is merged and removed. A summary is printed at the end and optionally sent to Discord if a webhook is configured.

## VirusTotal Notes
VirusTotal queries require an API key. Subdomain enumeration is limited to the first 50 discovered subdomains to stay within reasonable rate limits. Basic sleep delays are used; heavy usage may require backoff tuning.

## Limitations / Roadmap
- Retry/backoff logic could be improved for network errors
- Additional providers (Shodan crawled URLs, SecurityTrails, etc.)
- Optional output formats (JSON, CSV)
- Async implementation for higher throughput

## Contributing
Pull requests welcome! Please open an issue first to discuss significant changes. Make sure new behavior includes minimal tests or examples.

## License
MIT — see [LICENSE](LICENSE).

## Disclaimer
Use responsibly and respect each data provider's terms of service and rate limits. This tool is intended for legitimate security research and reconnaissance on domains you are authorized to probe.

## Maintainer
Created and maintained by [@depro0x](https://github.com/depro0x).
