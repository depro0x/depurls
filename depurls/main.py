import os
import requests
import importlib.util
import subprocess
import time
import tempfile
import argparse
import sys
import concurrent.futures
from threading import Lock
import json
from pathlib import Path
from urllib.parse import urlparse


def is_valid_domain_url(url, target_domain):
    """Check if URL belongs to the target domain or its subdomains (including nested subdomains)."""
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc.lower()
        
        # Remove port if present
        if ':' in hostname:
            hostname = hostname.split(':')[0]
        
        # Remove www. prefix for comparison (optional normalization)
        # hostname = hostname.removeprefix('www.')  # Python 3.9+
        
        target_domain_lower = target_domain.lower()
        
        # Exact match
        if hostname == target_domain_lower:
            return True
        
        # Subdomain match (handles all levels: api.example.com, api.v1.abd.example.com, etc.)
        if hostname.endswith('.' + target_domain_lower):
            return True
        
        return False
    except Exception:
        return False


def save_urls(urls, output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', buffering=1) as f:
        for url in urls:
            if url.strip():
                f.write(url.strip() + '\n')


def get_config_path():
    config_dir = Path.home() / '.config' / 'depurls'
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / 'config.json'


def load_config():
    config_path = get_config_path()
    if config_path.exists():
        with open(config_path, 'r') as f:
            return json.load(f)
    return {}


def save_config(config):
    config_path = get_config_path()
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)


def setup_domain_config(domain):
    config = load_config()

    if 'api_keys' not in config:
        config['api_keys'] = {}
    if 'webhooks' not in config:
        config['webhooks'] = {}

    print(f"\n[*] Setting up configuration for domain: {domain}")
    print("[*] Press Enter to skip any field and keep existing value\n")

    print("API Keys (Universal):")
    urlscan_key = input(f"  URLScan API Key [{config['api_keys'].get('URLSCAN_API_KEY', 'not set')}]: ").strip()
    if urlscan_key:
        config['api_keys']['URLSCAN_API_KEY'] = urlscan_key

    vt_key = input(f"  VirusTotal API Key [{config['api_keys'].get('VT_API_KEY', 'not set')}]: ").strip()
    if vt_key:
        config['api_keys']['VT_API_KEY'] = vt_key

    print(f"\nDiscord Webhook for {domain}:")
    discord_webhook = input(f"  Webhook URL [{config['webhooks'].get(domain, 'not set')}]: ").strip()
    if discord_webhook:
        config['webhooks'][domain] = discord_webhook

    save_config(config)
    print(f"\n[+] Configuration saved to: {get_config_path()}")
    print(f"[+] Configuration updated successfully!")


def get_domain_config(domain):
    config = load_config()
    domain_config = {}

    if 'api_keys' in config:
        domain_config.update(config['api_keys'])

    if 'webhooks' in config and domain in config['webhooks']:
        domain_config['DISCORD_WEBHOOK'] = config['webhooks'][domain]

    return domain_config


def wayback_urls(domain):
    """Fetch URLs from the Wayback Machine CDX API.

    - Increases timeout to 15 minutes (900s)
    - Prints a simple progress indicator in MB downloaded without extra deps
    - If an error occurs mid-download, returns URLs parsed from the data downloaded so far
    - Uses collapse=urlkey to reduce duplicate snapshots at source
    - Filters URLs to only include target domain and subdomains
    - Retries on HTTP 504 Gateway Timeout errors
    """
    temp_file = tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.txt')
    all_urls = []

    # collapse=urlkey returns only one record per unique URL (ignoring timestamps)
    api = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"

    # We'll accumulate the response text progressively so we can parse partial results on failure
    response_text = ""
    total_bytes = 0
    start_time = time.time()
    last_print = start_time
    
    # Retry configuration for 504 errors
    max_retries = 3
    retry_count = 0
    wait_times = [60, 120, 240]  # 1min, 2min, 4min

    try:
        print("[*] Wayback: Downloading and processing data (up to ~15 minutes)...")

        while retry_count <= max_retries:
            try:
                # 15 minutes timeout
                resp = requests.get(api, timeout=900, stream=True)

                if resp.status_code == 504:
                    # Gateway Timeout - retry
                    if retry_count < max_retries:
                        wait_time = wait_times[retry_count]
                        retry_count += 1
                        print(f"\n[!] Wayback: HTTP 504 Gateway Timeout - waiting {wait_time}s before retry {retry_count}/{max_retries}")
                        time.sleep(wait_time)
                        continue
                    else:
                        print(f"\n[!] Wayback: HTTP 504 Gateway Timeout - max retries exceeded")
                        return []
                
                if resp.status_code != 200:
                    print(f"[!] Wayback: HTTP {resp.status_code}")
                    return []

                # Success - process the response
                for chunk in resp.iter_content(chunk_size=131072, decode_unicode=True):  # 128 KiB
                    if not chunk:
                        continue
                    response_text += chunk
                    chunk_bytes = len(chunk.encode('utf-8'))
                    total_bytes += chunk_bytes

                    # Lightweight progress: MB downloaded and speed
                    now = time.time()
                    if now - last_print >= 1.0:
                        mb = total_bytes / (1024 * 1024)
                        elapsed = max(now - start_time, 0.001)
                        speed = mb / elapsed  # MB/s
                        msg = f"[Wayback] Downloaded: {mb:.2f} MB | {speed:.2f} MB/s | Elapsed: {int(elapsed)}s"
                        print("\r" + msg, end="", flush=True)
                        last_print = now
                
                # Break out of retry loop on success
                break
                
            except requests.exceptions.Timeout:
                # Parse partial data if any
                print("\n[!] Wayback: Request timed out after 15 minutes — using partial data")
                if response_text:
                    lines = response_text.splitlines()
                    unique_urls = {line.strip() for line in lines if line.strip() and is_valid_domain_url(line.strip(), domain)}
                    return list(unique_urls)
                return all_urls
            except requests.exceptions.RequestException as e:
                # Network errors - might be temporary
                if retry_count < max_retries and "504" in str(e):
                    wait_time = wait_times[retry_count]
                    retry_count += 1
                    print(f"\n[!] Wayback: Request error ({e}) - waiting {wait_time}s before retry {retry_count}/{max_retries}")
                    time.sleep(wait_time)
                    continue
                else:
                    raise

        # Final newline after progress updates
        if total_bytes > 0:
            print()

        lines = response_text.splitlines()
        unique_urls = set()
        filtered_count = 0
        for line in lines:
            url = line.strip()
            if url and is_valid_domain_url(url, domain):
                unique_urls.add(url)
            elif url:
                filtered_count += 1

        all_urls = list(unique_urls)
        mb_downloaded = total_bytes / (1024 * 1024)
        print(f"[*] Wayback: Downloaded {mb_downloaded:.2f} MB, parsed {len(lines)} lines, found {len(all_urls)} unique URLs (filtered {filtered_count} non-matching)")

        return all_urls

    except Exception as e:
        # Parse partial data if any
        print(f"\n[!] Wayback: Error — using partial data if available ({str(e)})")
        if response_text:
            lines = response_text.splitlines()
            unique_urls = {line.strip() for line in lines if line.strip() and is_valid_domain_url(line.strip(), domain)}
            return list(unique_urls)
        return all_urls
    finally:
        try:
            temp_file.close()
        except Exception:
            pass
        try:
            os.unlink(temp_file.name)
        except Exception:
            pass


def commoncrawl_urls(domain):
    try:
        import json
        collinfo_url = "https://index.commoncrawl.org/collinfo.json"
        resp = requests.get(collinfo_url, timeout=900)
        coll = resp.json()

        all_urls = set()
        print("[*] Common Crawl: Querying 5 recent indexes...")

        if isinstance(coll, list) and coll:
            recent_indexes = sorted(coll, key=lambda x: x.get('id', ''))[-5:]
        else:
            recent_indexes = [
                {'id': 'CC-MAIN-2024-51'},
                {'id': 'CC-MAIN-2024-46'},
                {'id': 'CC-MAIN-2024-42'},
                {'id': 'CC-MAIN-2024-38'},
                {'id': 'CC-MAIN-2024-33'}
            ]

        for index in recent_indexes:
            try:
                cdx_api = index.get('cdx-api', '')
                if not cdx_api:
                    index_id = index.get('id', 'CC-MAIN-2024-10')
                    cdx_api = f"https://index.commoncrawl.org/{index_id}-index"

                index_url = f"{cdx_api}?url=*.{domain}/*&output=json&fl=url"

                resp = requests.get(index_url, timeout=900, stream=True)

                for line in resp.iter_lines(decode_unicode=True):
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        if 'url' in obj:
                            url = obj['url']
                            if is_valid_domain_url(url, domain):
                                all_urls.add(url)
                    except Exception:
                        if '"url":"' in line:
                            try:
                                url = line.split('"url":"')[1].split('"')[0]
                                if is_valid_domain_url(url, domain):
                                    all_urls.add(url)
                            except Exception:
                                pass
            except Exception:
                continue

        if not all_urls:
            print("[!] Common Crawl: No URLs found (domain may not be in recent crawls)")
        return list(all_urls)
    except Exception as e:
        print(f"[!] Common Crawl: Error - {e}")
        return []


def alienvault_urls(domain):
    all_urls = []
    api = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500&page=1"

    try:
        page = 1
        retry_count = 0
        max_retries = 3
        # Wait times: 1 minute, 2 minutes, 5 minutes
        wait_times = [60, 120, 300]
        
        while True:
            resp = requests.get(api, timeout=900)
            
            if resp.status_code == 429:
                # Rate limited - wait and retry
                if retry_count >= max_retries:
                    print(f"[!] AlienVault: Rate limited (HTTP 429) - max retries exceeded")
                    break
                
                wait_time = wait_times[retry_count]
                retry_count += 1
                print(f"[!] AlienVault: Rate limited (HTTP 429) - waiting {wait_time}s ({wait_time//60}m) before retry {retry_count}/{max_retries}")
                time.sleep(wait_time)
                continue
            
            if resp.status_code != 200:
                if resp.status_code == 404:
                    print("[!] AlienVault: Domain not found in OTX database")
                else:
                    print(f"[!] AlienVault: HTTP {resp.status_code}")
                break

            # Reset retry count on success
            retry_count = 0
            
            data = resp.json()
            url_list = data.get('url_list', [])

            if not url_list:
                break

            # Filter URLs to only include target domain
            for entry in url_list:
                url = entry.get('url', '')
                if url and is_valid_domain_url(url, domain):
                    all_urls.append(url)

            has_next = data.get('has_next', False)
            if not has_next:
                break

            page += 1
            api = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500&page={page}"
            
            # Add small delay between pages to avoid rate limiting
            time.sleep(1)

        if not all_urls:
            print("[!] AlienVault: No URLs found (domain may not have threat intelligence data)")
        return all_urls
    except Exception as e:
        print(f"[!] AlienVault: Error - {e}")
        return []


def urlscan_urls(domain, api_key=None):
    all_urls = []

    try:
        size = 1000

        api = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size={size}"
        headers = {}
        if api_key:
            headers['API-Key'] = api_key

        resp = requests.get(api, headers=headers or None, timeout=900)
        if resp.status_code != 200:
            print(f"[!] URLScan: HTTP {resp.status_code}")
            return []

        data = resp.json()

        total = data.get('total', 0)
        print(f"[*] URLScan: API reports {total} total results available")

        for result in data.get('results', []):
            try:
                url = result['task']['url']
                if is_valid_domain_url(url, domain):
                    all_urls.append(url)
            except Exception as e:
                continue

        page_count = 1
        max_pages = 100

        while len(all_urls) < total and page_count < max_pages:
            try:
                # Get the last result from current data to build pagination cursor
                results = data.get('results', [])
                if not results:
                    break

                last_result = results[-1]
                sort_value = last_result.get('sort', [])
                if len(sort_value) >= 2:
                    search_after = f"&search_after={sort_value[0]},{sort_value[1]}"
                    api_paginated = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size={size}{search_after}"

                    resp = requests.get(api_paginated, headers=headers or None, timeout=900)
                    if resp.status_code != 200:
                        break

                    data = resp.json()  # Update data with NEW page
                    
                    # Now extract URLs from the NEW page
                    page_results = 0
                    for result in data.get('results', []):
                        try:
                            url = result['task']['url']
                            if is_valid_domain_url(url, domain):
                                all_urls.append(url)
                                page_results += 1
                        except:
                            continue

                    page_count += 1

                    if page_results == 0:
                        break
                else:
                    break
            except Exception as e:
                print(f"[!] URLScan pagination error: {e}")
                break

        print(f"[*] URLScan: Fetched {len(all_urls)} URLs from {page_count} page(s)")
        return all_urls
    except Exception as e:
        print(f"[!] URLScan: Error - {e}")
        return []


def virustotal_urls(domain, api_key):
    all_urls = set()
    domains_to_check = [domain]

    try:
        api = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={domain}"
        resp = requests.get(api, timeout=900)

        if resp.status_code == 200:
            data = resp.json()

            subdomains = data.get('subdomains', [])
            if subdomains:
                domains_to_check.extend(subdomains[:50])

            for url_entry in data.get('detected_urls', []):
                url = url_entry[0] if isinstance(url_entry, list) else url_entry.get('url')
                if url and is_valid_domain_url(url, domain):
                    all_urls.add(url)

            for url_entry in data.get('undetected_urls', []):
                url = url_entry[0] if isinstance(url_entry, list) else url_entry.get('url')
                if url and is_valid_domain_url(url, domain):
                    all_urls.add(url)
        elif resp.status_code == 403:
            print("[!] VirusTotal: API key invalid or rate limit exceeded")
            return []
        elif resp.status_code == 204:
            print("[!] VirusTotal: Rate limit exceeded")
            return []
        else:
            print(f"[!] VirusTotal: HTTP {resp.status_code}")
            return []

        for subdomain in domains_to_check[1:]:
            try:
                time.sleep(0.5)
                api = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={subdomain}"
                resp = requests.get(api, timeout=900)

                if resp.status_code == 200:
                    data = resp.json()

                    for url_entry in data.get('detected_urls', []):
                        url = url_entry[0] if isinstance(url_entry, list) else url_entry.get('url')
                        if url and is_valid_domain_url(url, domain):
                            all_urls.add(url)

                    for url_entry in data.get('undetected_urls', []):
                        url = url_entry[0] if isinstance(url_entry, list) else url_entry.get('url')
                        if url and is_valid_domain_url(url, domain):
                            all_urls.add(url)
            except:
                continue

        if not all_urls:
            print("[!] VirusTotal: No URLs found (domain may not be in VT database)")
        return list(all_urls)
    except Exception as e:
        print(f"[!] VirusTotal: Error - {e}")
        return []


def update_tool():
    """Update depurls to the latest version from GitHub."""
    print("[*] Updating depurls to the latest version...")
    print("[*] Fetching from: https://github.com/depro0x/depurls.git\n")
    
    try:
        # Use pip to upgrade from GitHub
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", 
             "git+https://github.com/depro0x/depurls.git"],
            capture_output=True,
            text=True,
            timeout=900
        )
        
        if result.returncode == 0:
            print("[+] Update successful!")
            print("\n[*] Output:")
            print(result.stdout)
            
            # Try to get the new version
            try:
                from depurls import __version__
                print(f"[+] Current version: {__version__}")
            except:
                pass
            
            print("\n[!] Note: If you installed with pipx, use: pipx upgrade depurls")
            print("[!]       or: pipx install --force git+https://github.com/depro0x/depurls.git")
        else:
            print("[!] Update failed!")
            print("\n[*] Error output:")
            print(result.stderr)
            print("\n[*] Try manually:")
            print("    pip install --upgrade git+https://github.com/depro0x/depurls.git")
            print("    or for pipx:")
            print("    pipx install --force git+https://github.com/depro0x/depurls.git")
            sys.exit(1)
            
    except subprocess.TimeoutExpired:
        print("[!] Update timed out after 2 minutes")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Update error: {e}")
        print("\n[*] Try manually:")
        print("    pip install --upgrade git+https://github.com/depro0x/depurls.git")
        sys.exit(1)


def parse_args():
    parser = argparse.ArgumentParser(description='Collect URLs for a domain')
    parser.add_argument('--setup', action='store_true', help='Setup configuration for a domain')
    parser.add_argument('--update', action='store_true', help='Update depurls to the latest version from GitHub')
    parser.add_argument('-d', '--domain', help='Target domain')
    parser.add_argument('-o', '--output', dest='output', help='Output file path for URLs')
    parser.add_argument('-w', '--workers', type=int, default=5, help='Number of concurrent worker threads')
    parser.add_argument('-p', '--providers', nargs='+',
                        choices=['wayback', 'commoncrawl', 'alienvault', 'urlscan', 'virustotal', 'all'],
                        default=['all'],
                        help='Providers to use for URL collection (default: all)')
    return parser.parse_args()


def main(argv=None):
    args = parse_args() if argv is None else parse_args()

    if args.update:
        update_tool()
        return

    if args.setup:
        if not args.domain:
            print("[!] Error: --setup requires -d/--domain argument")
            sys.exit(1)
        setup_domain_config(args.domain)
        return

    if not args.output:
        print("[!] Error: -o/--output is required for URL collection")
        sys.exit(1)

    if not args.domain:
        print("[!] Error: -d/--domain is required for URL collection")
        sys.exit(1)

    domain = args.domain
    domain_config = get_domain_config(domain)
    if domain_config:
        print(f"[*] Loaded configuration for domain: {domain}")

    # Try to import optional repo-level config.py if present (best-effort)
    try:
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
        config_path = os.path.join(repo_root, "config.py")
        spec = importlib.util.spec_from_file_location("config", config_path)
        config = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(config)
    except Exception:
        config = None

    providers = args.providers
    if 'all' in providers:
        providers = ['wayback', 'commoncrawl', 'alienvault', 'urlscan', 'virustotal']
    else:
        providers = list(set(providers))

    output_path = args.output

    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    if output_dir:
        raw_path = os.path.join(output_dir, "urls_raw.txt")
    else:
        raw_path = "urls_raw.txt"

    open(raw_path, 'w').close()

    per_service_counts = {
        'wayback': 0,
        'commoncrawl': 0,
        'alienvault': 0,
        'urlscan': 0,
        'virustotal': 0,
    }

    raw_count = 0

    workers = getattr(args, 'workers', 5)
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    write_lock = Lock()

    print(f"\n[=] Collecting URLs for: {domain}")

    futures = {}

    if 'wayback' in providers:
        print("[*] Starting Wayback Machine...")
        futures['wayback'] = executor.submit(wayback_urls, domain)

    if 'commoncrawl' in providers:
        print("[*] Starting Common Crawl...")
        futures['commoncrawl'] = executor.submit(commoncrawl_urls, domain)

    if 'alienvault' in providers:
        print("[*] Starting AlienVault OTX...")
        futures['alienvault'] = executor.submit(alienvault_urls, domain)

    if 'urlscan' in providers:
        print("[*] Starting URLScan...")
        urlscan_key = domain_config.get('URLSCAN_API_KEY', '')
        if not urlscan_key and config:
            urlscan_key = getattr(config, "URLSCAN_API_KEY", "")
        futures['urlscan'] = executor.submit(urlscan_urls, domain, urlscan_key)

    if 'virustotal' in providers:
        vt_key = domain_config.get('VT_API_KEY', '')
        if not vt_key and config:
            vt_key = getattr(config, "VT_API_KEY", "")
        if vt_key:
            print("[*] Starting VirusTotal...")
            futures['virustotal'] = executor.submit(virustotal_urls, domain, vt_key)
        else:
            print("[!] Skipping VirusTotal (no API key)")

    for provider_name, future in futures.items():
        try:
            # All services now have 15 minute timeout
            timeout = 900
            urls_list = future.result(timeout=timeout)
            
            if urls_list:
                print(f"[+] {provider_name.title()}: Found {len(urls_list)} URLs")
                per_service_counts[provider_name] += len(urls_list)

                with write_lock:
                    with open(raw_path, 'a') as f:
                        for url in urls_list:
                            f.write(url.strip() + '\n')
                            raw_count += 1
            else:
                print(f"[!] {provider_name.title()}: Found 0 URLs (check domain spelling, API keys, or rate limits)")
        except concurrent.futures.TimeoutError:
            print(f"[!] {provider_name.title()}: Timeout after 15 minutes")
        except Exception as e:
            print(f"[!] {provider_name.title()}: Error - {str(e)}")

    executor.shutdown(wait=True)

    print('\n[=] Deduplicating URLs...')
    
    # Load existing URLs from output file if it exists
    existing_urls = set()
    if os.path.exists(output_path):
        print(f"[*] Output file exists, loading existing URLs to avoid duplicates...")
        try:
            with open(output_path, 'r') as f:
                for line in f:
                    url = line.rstrip()
                    if url:
                        existing_urls.add(url)
            print(f"[*] Loaded {len(existing_urls)} existing URLs from {output_path}")
        except Exception as e:
            print(f"[!] Warning: Could not read existing file: {e}")
    
    # Deduplicate and merge with existing URLs
    try:
        # Read new URLs from raw file
        new_urls = set()
        with open(raw_path, 'r') as f:
            for line in f:
                url = line.rstrip()
                if url:
                    new_urls.add(url)
        
        # Find truly new URLs (not in existing file)
        unique_new_urls = new_urls - existing_urls
        
        if existing_urls:
            # Append mode: add only new unique URLs
            if unique_new_urls:
                with open(output_path, 'a') as f:
                    for url in sorted(unique_new_urls):
                        f.write(url + '\n')
                print(f"[*] Appended {len(unique_new_urls)} new unique URLs to {output_path}")
                print(f"[*] Total URLs in file: {len(existing_urls) + len(unique_new_urls)}")
            else:
                print(f"[*] No new URLs to append (all URLs already exist in {output_path})")
                print(f"[*] Total URLs in file: {len(existing_urls)}")
        else:
            # New file: write all unique URLs
            with open(output_path, 'w') as f:
                for url in sorted(new_urls):
                    f.write(url + '\n')
            print(f"[*] Saved {len(new_urls)} unique URLs to {output_path}")
    except Exception as e:
        print(f'[!] Deduplication error: {e}')
        print('[!] Falling back to system sort deduplication')
        try:
            res = subprocess.run(['sort', '-u', raw_path, '-o', output_path], check=False)
            if res.returncode == 0:
                final_count = sum(1 for _ in open(output_path))
                print(f"[*] Saved {final_count} unique URLs to {output_path}")
            else:
                raise RuntimeError('sort returned non-zero')
        except Exception:
            print('[!] System sort also failed — using basic Python deduplication')
            seen = set()
            final_count = 0
            with open(raw_path, 'r') as rf, open(output_path, 'w') as of:
                for line in rf:
                    u = line.rstrip()
                    if u and u not in seen:
                        of.write(u + "\n")
                        seen.add(u)
                        final_count += 1
            print(f"[*] Saved {final_count} unique URLs to {output_path}")

    print('\n[Summary] Total URLs found per service:')
    for svc, cnt in per_service_counts.items():
        if svc in providers:
            print(f"  {svc}: {cnt}")

    try:
        if os.path.exists(raw_path):
            os.unlink(raw_path)
    except Exception:
        pass

    temp_dir = tempfile.gettempdir()
    for filename in os.listdir(temp_dir):
        if filename.startswith('wayback_') and filename.endswith('.txt'):
            try:
                os.unlink(os.path.join(temp_dir, filename))
            except Exception:
                pass

    try:
        webhook_url = domain_config.get('DISCORD_WEBHOOK', '')

        if not webhook_url and config:
            default_channel = getattr(config, 'DISCORD_DEFAULT_CHANNEL', '')
            webhooks = getattr(config, 'DISCORD_WEBHOOKS', {})
            webhook_url = webhooks.get(default_channel, '')

        if webhook_url:
            total_found = sum(per_service_counts.values())
            final_count = 0
            if os.path.exists(output_path):
                with open(output_path, 'r') as f:
                    for _ in f:
                        final_count += 1
            message = (
                f"[+] URL collection finished for: {domain}\n"
                f"Services total hits: {total_found}\n"
                f"Unique URLs saved: {final_count}\n"
            )

            payload = {"content": message}
            requests.post(webhook_url, json=payload, timeout=900)
    except Exception:
        pass


if __name__ == "__main__":
    main()
