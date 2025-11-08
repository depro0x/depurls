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


# Timeout Configuration:
# - requests.get(timeout=(connect_timeout, read_timeout)) 
#   * connect_timeout: 60s (1 minute) for all services
#   * read_timeout: 900s (15 minutes) for all services
# - future.result(timeout=X): maximum wait time for service completion
#   * All services: 960s (16 minutes) to allow for full read timeout + buffer


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
    
    alienvault_key = input(f"  AlienVault OTX API Key [{config['api_keys'].get('ALIENVAULT_API_KEY', 'not set')}]: ").strip()
    if alienvault_key:
        config['api_keys']['ALIENVAULT_API_KEY'] = alienvault_key
    
    shodan_key = input(f"  Shodan API Key [{config['api_keys'].get('SHODAN_API_KEY', 'not set')}]: ").strip()
    if shodan_key:
        config['api_keys']['SHODAN_API_KEY'] = shodan_key

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

    - Connection timeout: 60s, Read timeout: 15 minutes
    - Prints a simple progress indicator in MB downloaded without extra deps
    - If an error occurs mid-download, returns URLs parsed from the data downloaded so far
    - Fetches URLs TWICE: once with collapse=urlkey, once without collapse
    - Sorts and deduplicates at file level to maximize unique URL collection
    - Filters URLs to only include target domain and subdomains
    - Retries on HTTP 504 Gateway Timeout errors with exponential backoff
    """
    all_urls_set = set()
    
    # We'll fetch twice: with collapse and without collapse
    fetch_configs = [
        {
            'name': 'collapsed',
            'api': f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey",
            'description': 'with collapse=urlkey (unique URLs only)'
        },
        {
            'name': 'full',
            'api': f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original",
            'description': 'without collapse (all snapshots)'
        }
    ]

    # Retry configuration for 504 errors
    max_retries = 3
    wait_times = [30, 60, 120]  # 30s, 1min, 2min
    
    for config in fetch_configs:
        api = config['api']
        config_name = config['name']
        config_desc = config['description']
        
        # We'll accumulate the response text progressively so we can parse partial results on failure
        response_text = ""
        total_bytes = 0
        start_time = time.time()
        last_print = start_time
        retry_count = 0

        try:
            while retry_count <= max_retries:
                try:
                    # Connection timeout: 60s, Read timeout: 15min
                    resp = requests.get(api, timeout=(60, 900), stream=True)

                    if resp.status_code == 504:
                        # Gateway Timeout - retry
                        if retry_count < max_retries:
                            wait_time = wait_times[retry_count]
                            retry_count += 1
                            time.sleep(wait_time)
                            continue
                        else:
                            break
                    
                    if resp.status_code != 200:
                        if resp.status_code == 404:
                            raise Exception(f"HTTP 404 - Domain not found in Wayback archive")
                        elif resp.status_code == 403:
                            raise Exception(f"HTTP 403 - Access forbidden")
                        else:
                            raise Exception(f"HTTP {resp.status_code} - Request failed")

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
                            msg = f"[Wayback ({config_name})] Downloaded: {mb:.2f} MB | {speed:.2f} MB/s | Elapsed: {int(elapsed)}s"
                            print("\r" + msg, end="", flush=True)
                            last_print = now
                    
                    # Break out of retry loop on success
                    break
                    
                except requests.exceptions.Timeout:
                    # Parse partial data if any
                    break
                except requests.exceptions.RequestException as e:
                    # Network errors - might be temporary
                    if retry_count < max_retries and "504" in str(e):
                        wait_time = wait_times[retry_count]
                        retry_count += 1
                        time.sleep(wait_time)
                        continue
                    else:
                        raise

            # Final newline after progress updates
            if total_bytes > 0:
                print()

            # Parse and add URLs to the set
            lines = response_text.splitlines()
            for line in lines:
                url = line.strip()
                if url and is_valid_domain_url(url, domain):
                    all_urls_set.add(url)

        except Exception as e:
            # Parse partial data if any
            if response_text:
                lines = response_text.splitlines()
                for line in lines:
                    url = line.strip()
                    if url and is_valid_domain_url(url, domain):
                        all_urls_set.add(url)

    # Convert set to sorted list
    all_urls = sorted(list(all_urls_set))
    return all_urls


def commoncrawl_urls(domain):
    try:
        import json
        collinfo_url = "https://index.commoncrawl.org/collinfo.json"
        # Connection timeout: 60s, Read timeout: 15min
        resp = requests.get(collinfo_url, timeout=(60, 900))
        coll = resp.json()

        all_urls = set()

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

                # Connection timeout: 60s, Read timeout: 15min
                resp = requests.get(index_url, timeout=(60, 900), stream=True)

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
            raise Exception("Domain not found in recent Common Crawl indexes")
        return list(all_urls)
    except Exception as e:
        if "Domain not found" in str(e):
            raise
        raise Exception(f"Request failed - {str(e)}")


def alienvault_urls(domain, api_key=None):
    all_urls = []
    api = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500&page=1"

    try:
        page = 1
        retry_count = 0
        max_retries = 3
        # Wait times: 30s, 1 minute, 2 minutes
        wait_times = [30, 60, 120]
        
        # Setup headers with API key if provided
        headers = {}
        if api_key:
            headers['X-OTX-API-KEY'] = api_key
        
        while True:
            # Connection timeout: 60s, Read timeout: 15min
            resp = requests.get(api, headers=headers if headers else None, timeout=(60, 900))
            
            if resp.status_code == 429:
                # Rate limited - wait and retry
                if retry_count >= max_retries:
                    raise Exception(f"HTTP 429 - Rate limit exceeded after {max_retries} retries")
                    break
                
                wait_time = wait_times[retry_count]
                retry_count += 1
                time.sleep(wait_time)
                continue
            
            if resp.status_code != 200:
                if resp.status_code == 404:
                    raise Exception(f"HTTP 404 - Domain not found in OTX database")
                elif resp.status_code == 403:
                    raise Exception(f"HTTP 403 - Invalid or expired API key")
                else:
                    raise Exception(f"HTTP {resp.status_code} - Request failed")
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
            raise Exception("No threat intelligence data available for this domain")
        return all_urls
    except Exception as e:
        if "HTTP" in str(e) or "threat intelligence" in str(e):
            raise
        raise Exception(f"Request failed - {str(e)}")


def urlscan_urls(domain, api_key=None):
    all_urls = []

    try:
        size = 1000

        api = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size={size}"
        headers = {}
        if api_key:
            headers['API-Key'] = api_key

        # Connection timeout: 60s, Read timeout: 15min
        resp = requests.get(api, headers=headers or None, timeout=(60, 900))
        if resp.status_code != 200:
            if resp.status_code == 401:
                raise Exception(f"HTTP 401 - Invalid API key")
            elif resp.status_code == 429:
                raise Exception(f"HTTP 429 - Rate limit exceeded")
            elif resp.status_code == 404:
                raise Exception(f"HTTP 404 - Domain not found")
            else:
                raise Exception(f"HTTP {resp.status_code} - Request failed")
            return []

        data = resp.json()

        total = data.get('total', 0)

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

                    # Connection timeout: 60s, Read timeout: 15min
                    resp = requests.get(api_paginated, headers=headers or None, timeout=(60, 900))
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
                break

        if not all_urls:
            raise Exception("No scan results found for this domain")
        return all_urls
    except Exception as e:
        if "HTTP" in str(e) or "scan results" in str(e):
            raise
        raise Exception(f"Request failed - {str(e)}")


def virustotal_urls(domain, api_key):
    all_urls = set()
    domains_to_check = [domain]

    try:
        api = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={domain}"
        # Connection timeout: 60s, Read timeout: 15min
        resp = requests.get(api, timeout=(60, 900))

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
            raise Exception(f"HTTP 403 - Invalid API key or rate limit exceeded")
        elif resp.status_code == 204:
            raise Exception(f"HTTP 204 - Rate limit exceeded (quota depleted)")
        elif resp.status_code == 404:
            raise Exception(f"HTTP 404 - Domain not found in VirusTotal database")
        else:
            raise Exception(f"HTTP {resp.status_code} - Request failed")

        for subdomain in domains_to_check[1:]:
            try:
                time.sleep(0.5)
                api = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={subdomain}"
                # Connection timeout: 60s, Read timeout: 15min
                resp = requests.get(api, timeout=(60, 900))

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
            raise Exception("No URL data available in VirusTotal database")
        return list(all_urls)
    except Exception as e:
        if "HTTP" in str(e) or "URL data" in str(e):
            raise
        raise Exception(f"Request failed - {str(e)}")


def shodan_urls(domain, api_key):
    """Fetch URLs from Shodan by discovering web services on the domain.
    
    Extracts URLs from:
    - HTTP response HTML (href links, src attributes)
    - HTTP headers (Location redirects, Link headers)
    - Hostnames/subdomains running web services
    """
    all_urls = set()
    
    try:
        # Try multiple search strategies for better coverage
        search_queries = [
            f"hostname:{domain}",  # Exact hostname match
            f"ssl:{domain}",        # SSL certificate match (often finds more results)
            f"http.html:{domain}",  # Domain in HTML content
        ]
        
        all_matches = []
        
        for query in search_queries:
            try:
                api_url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}"
                # Connection timeout: 60s, Read timeout: 15min
                resp = requests.get(api_url, timeout=(60, 900))
                
                if resp.status_code == 401:
                    raise Exception("HTTP 401 - Invalid API key")
                elif resp.status_code == 403:
                    raise Exception("HTTP 403 - Access forbidden")
                elif resp.status_code != 200:
                    continue  # Try next query
                
                data = resp.json()
                matches = data.get('matches', [])
                
                if matches:
                    all_matches.extend(matches)
                    
            except Exception as e:
                # If it's an auth error, stop trying
                if "401" in str(e) or "403" in str(e):
                    raise
                # Otherwise continue with next query
                continue
        
        if not all_matches:
            raise Exception("No Shodan results found for this domain")
        
        # Remove duplicate matches by IP+port
        seen_services = set()
        unique_matches = []
        for match in all_matches:
            service_id = f"{match.get('ip_str', '')}:{match.get('port', 0)}"
            if service_id not in seen_services:
                seen_services.add(service_id)
                unique_matches.append(match)
        
        for match in unique_matches:
            try:
                # Get hostname and port
                hostname = match.get('hostnames', [domain])[0] if match.get('hostnames') else domain
                port = match.get('port', 80)
                ip = match.get('ip_str', '')
                
                # Determine protocol
                if port == 443 or 'ssl' in str(match.get('ssl', '')):
                    protocol = 'https'
                else:
                    protocol = 'http'
                
                # Base URL
                if port in [80, 443]:
                    base_url = f"{protocol}://{hostname}"
                else:
                    base_url = f"{protocol}://{hostname}:{port}"
                
                # Add base URL if it's valid
                if is_valid_domain_url(base_url, domain):
                    all_urls.add(base_url)
                
                # Extract from HTTP data
                http_data = match.get('http', {})
                
                # Get URL from location header (redirects)
                location = http_data.get('location', '')
                if location:
                    if location.startswith('http'):
                        if is_valid_domain_url(location, domain):
                            all_urls.add(location)
                    else:
                        # Relative URL
                        full_url = base_url + location
                        if is_valid_domain_url(full_url, domain):
                            all_urls.add(full_url)
                
                # Parse HTML for URLs
                html = http_data.get('html', '')
                if html:
                    import re
                    # Extract href and src attributes
                    url_patterns = [
                        r'href=["\']([^"\']+)["\']',
                        r'src=["\']([^"\']+)["\']',
                        r'action=["\']([^"\']+)["\']',
                    ]
                    
                    for pattern in url_patterns:
                        found_urls = re.findall(pattern, html, re.IGNORECASE)
                        for url in found_urls:
                            # Skip anchors, javascript, data URIs
                            if url.startswith(('#', 'javascript:', 'data:', 'mailto:')):
                                continue
                            
                            # Handle absolute URLs
                            if url.startswith('http'):
                                if is_valid_domain_url(url, domain):
                                    all_urls.add(url)
                            # Handle protocol-relative URLs
                            elif url.startswith('//'):
                                full_url = f"{protocol}:{url}"
                                if is_valid_domain_url(full_url, domain):
                                    all_urls.add(full_url)
                            # Handle root-relative URLs
                            elif url.startswith('/'):
                                full_url = base_url + url
                                if is_valid_domain_url(full_url, domain):
                                    all_urls.add(full_url)
                            # Handle relative URLs
                            elif not url.startswith('http'):
                                full_url = base_url + '/' + url
                                if is_valid_domain_url(full_url, domain):
                                    all_urls.add(full_url)
                
            except Exception as e:
                # Skip individual service errors, continue processing others
                continue
        
        if not all_urls:
            raise Exception("No URLs extracted from Shodan data")
        
        return list(all_urls)
        
    except Exception as e:
        if "HTTP" in str(e) or "No" in str(e):
            raise
        raise Exception(f"Request failed - {str(e)}")


def update_tool():
    """Update depurls to the latest version from GitHub."""
    print("[*] Updating depurls to the latest version...")
    print("[*] Fetching from: https://github.com/depro0x/depurls.git\n")
    
    try:
        # Detect if running from local development directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        repo_root = os.path.abspath(os.path.join(script_dir, os.pardir))
        is_git_repo = os.path.exists(os.path.join(repo_root, '.git'))
        
        # Check if installed via pipx by looking at the Python executable path or script location
        is_pipx = (
            '.local/pipx/venvs' in sys.executable or 
            'pipx/venvs' in sys.executable or
            '.local/share/pipx' in sys.executable or
            '.local/pipx' in script_dir or
            'pipx/venvs' in script_dir
        )
        
        if is_pipx:
            print("[*] Detected pipx installation")
            print("[*] Running: pipx install --force git+https://github.com/depro0x/depurls.git\n")
            
            result = subprocess.run(
                ['pipx', 'install', '--force', 'git+https://github.com/depro0x/depurls.git'],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                print("[+] Update successful!")
                print("\n[*] Output:")
                print(result.stdout)
                print("\n[+] depurls has been updated to the latest version")
            else:
                print("[!] Update failed!")
                print("\n[*] Error output:")
                print(result.stderr)
                print("\n[*] Try manually:")
                print("    pipx install --force git+https://github.com/depro0x/depurls.git")
                sys.exit(1)
                
        elif is_git_repo:
            print("[*] Detected local git repository")
            print(f"[*] Repository path: {repo_root}\n")
            
            # Git pull to update
            print("[*] Running: git pull origin main")
            result = subprocess.run(
                ['git', 'pull', 'origin', 'main'],
                cwd=repo_root,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                print("[+] Update successful!")
                print("\n[*] Output:")
                print(result.stdout)
                
                # Check if there were actual changes
                if "Already up to date" in result.stdout or "Already up-to-date" in result.stdout:
                    print("[*] You already have the latest version!")
                else:
                    print("[+] Repository updated with latest changes")
                    
                    # Reinstall in editable mode if using pip
                    print("\n[*] Reinstalling package...")
                    reinstall = subprocess.run(
                        [sys.executable, "-m", "pip", "install", "-e", repo_root],
                        capture_output=True,
                        text=True,
                        timeout=60
                    )
                    if reinstall.returncode == 0:
                        print("[+] Package reinstalled successfully")
                    else:
                        print("[!] Warning: Could not reinstall package")
                        print(f"[!] You may need to run: pip install -e {repo_root}")
            else:
                print("[!] Git pull failed!")
                print("\n[*] Error output:")
                print(result.stderr)
                print("\n[*] Try manually:")
                print(f"    cd {repo_root}")
                print("    git pull origin main")
                sys.exit(1)
        else:
            # Regular pip installation
            print("[*] Installing from GitHub repository via pip")
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--upgrade", "--force-reinstall",
                 "git+https://github.com/depro0x/depurls.git"],
                capture_output=True,
                text=True,
                timeout=300
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
            else:
                print("[!] Update failed!")
                print("\n[*] Error output:")
                print(result.stderr)
                print("\n[*] Try manually:")
                print("    pip install --upgrade --force-reinstall git+https://github.com/depro0x/depurls.git")
                sys.exit(1)
            
    except subprocess.TimeoutExpired:
        print("[!] Update timed out")
        sys.exit(1)
    except FileNotFoundError as e:
        if 'pipx' in str(e):
            print("[!] pipx not found in PATH")
            print("[*] Please install pipx or update manually:")
            print("    pipx install --force git+https://github.com/depro0x/depurls.git")
        else:
            print(f"[!] Update error: {e}")
            print("\n[*] Try manually:")
            print("    pipx install --force git+https://github.com/depro0x/depurls.git")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Update error: {e}")
        print("\n[*] Try manually:")
        if 'pipx' in sys.executable or 'pipx' in os.path.dirname(os.path.abspath(__file__)):
            print("    pipx install --force git+https://github.com/depro0x/depurls.git")
        else:
            print("    cd /path/to/depurls && git pull origin main")
            print("    or: pip install --upgrade git+https://github.com/depro0x/depurls.git")
        sys.exit(1)


def parse_args():
    parser = argparse.ArgumentParser(description='Collect URLs for a domain')
    parser.add_argument('--setup', action='store_true', help='Setup configuration for a domain')
    parser.add_argument('--update', action='store_true', help='Update depurls to the latest version from GitHub')
    parser.add_argument('-d', '--domain', help='Target domain')
    parser.add_argument('-o', '--output', dest='output', help='Output file path for URLs')
    parser.add_argument('-w', '--workers', type=int, default=5, help='Number of concurrent worker threads')
    parser.add_argument('-p', '--providers', nargs='+',
                        choices=['wayback', 'commoncrawl', 'alienvault', 'urlscan', 'virustotal', 'shodan', 'all'],
                        default=['all'],
                        help='Providers to use for URL collection (default: all)')
    parser.add_argument('-e', '--exclude', nargs='+',
                        choices=['wayback', 'commoncrawl', 'alienvault', 'urlscan', 'virustotal', 'shodan'],
                        default=[],
                        help='Providers to exclude from URL collection')
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
        providers = ['wayback', 'commoncrawl', 'alienvault', 'urlscan', 'virustotal', 'shodan']
    else:
        providers = list(set(providers))
    
    # Apply exclusions
    if args.exclude:
        providers = [p for p in providers if p not in args.exclude]
        if not providers:
            print("[!] Error: All providers have been excluded. No services to run.")
            sys.exit(1)

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
        'shodan': 0,
    }

    raw_count = 0
    
    # Track execution start time
    start_time = time.time()

    workers = getattr(args, 'workers', 5)
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    write_lock = Lock()

    print(f"\n[=] Collecting URLs for: {domain}")
    print(f"[=] Running {len(providers)} service(s) concurrently...\n")

    futures = {}
    service_status = {}

    # Start all services with initial status
    if 'wayback' in providers:
        print("[⏳] Wayback Machine...")
        service_status['wayback'] = 'running'
        futures['wayback'] = executor.submit(wayback_urls, domain)

    if 'commoncrawl' in providers:
        print("[⏳] Common Crawl...")
        service_status['commoncrawl'] = 'running'
        futures['commoncrawl'] = executor.submit(commoncrawl_urls, domain)

    if 'alienvault' in providers:
        print("[⏳] AlienVault OTX...")
        service_status['alienvault'] = 'running'
        alienvault_key = domain_config.get('ALIENVAULT_API_KEY', '')
        if not alienvault_key and config:
            alienvault_key = getattr(config, "ALIENVAULT_API_KEY", "")
        futures['alienvault'] = executor.submit(alienvault_urls, domain, alienvault_key)

    if 'urlscan' in providers:
        print("[⏳] URLScan...")
        service_status['urlscan'] = 'running'
        urlscan_key = domain_config.get('URLSCAN_API_KEY', '')
        if not urlscan_key and config:
            urlscan_key = getattr(config, "URLSCAN_API_KEY", "")
        futures['urlscan'] = executor.submit(urlscan_urls, domain, urlscan_key)

    if 'virustotal' in providers:
        vt_key = domain_config.get('VT_API_KEY', '')
        if not vt_key and config:
            vt_key = getattr(config, "VT_API_KEY", "")
        if vt_key:
            print("[⏳] VirusTotal...")
            service_status['virustotal'] = 'running'
            futures['virustotal'] = executor.submit(virustotal_urls, domain, vt_key)
        else:
            print("[⏭️] VirusTotal: Skipped (no API key)")
            service_status['virustotal'] = 'skipped'

    if 'shodan' in providers:
        shodan_key = domain_config.get('SHODAN_API_KEY', '')
        if not shodan_key and config:
            shodan_key = getattr(config, "SHODAN_API_KEY", "")
        if shodan_key:
            print("[⏳] Shodan...")
            service_status['shodan'] = 'running'
            futures['shodan'] = executor.submit(shodan_urls, domain, shodan_key)
        else:
            print("[⏭️] Shodan: Skipped (no API key)")
            service_status['shodan'] = 'skipped'

    print()  # Empty line before results start appearing

    # Process results as they complete with unified timeout
    # 16 minutes allows for 15min read timeout + 1min connection + buffer
    service_timeout = 960  # 16 minutes for all services
    
    for provider_name, future in futures.items():
        try:
            # Use unified timeout for all services
            urls_list = future.result(timeout=service_timeout)
            
            if urls_list:
                print(f"[✓] {provider_name.title()}: {len(urls_list)} URLs")
                per_service_counts[provider_name] += len(urls_list)
                service_status[provider_name] = f'completed ({len(urls_list)} URLs)'

                with write_lock:
                    with open(raw_path, 'a') as f:
                        for url in urls_list:
                            f.write(url.strip() + '\n')
                            raw_count += 1
            else:
                print(f"[✗] {provider_name.title()}: 0 URLs")
                service_status[provider_name] = 'completed (0 URLs)'
        except concurrent.futures.TimeoutError:
            print(f"[✗] {provider_name.title()}: Timeout (16min)")
            service_status[provider_name] = 'timeout (16min)'
        except Exception as e:
            error_msg = str(e)
            print(f"[✗] {provider_name.title()}: {error_msg}")
            service_status[provider_name] = f'error ({error_msg})'

    executor.shutdown(wait=True)
    
    print('\n[=] Deduplicating URLs...')
    
    # Load existing URLs from output file if it exists
    existing_urls = set()
    if os.path.exists(output_path):
        try:
            with open(output_path, 'r') as f:
                for line in f:
                    url = line.rstrip()
                    if url:
                        existing_urls.add(url)
        except Exception as e:
            pass
    
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
                print(f"[+] Added {len(unique_new_urls)} new URLs (Total: {len(existing_urls) + len(unique_new_urls)})")
            else:
                print(f"[*] No new URLs (Total: {len(existing_urls)})")
        else:
            # New file: write all unique URLs
            with open(output_path, 'w') as f:
                for url in sorted(new_urls):
                    f.write(url + '\n')
            print(f"[+] Saved {len(new_urls)} URLs to {output_path}")
    except Exception as e:
        print(f'[!] Deduplication error: {e}')
        print('[!] Falling back to system sort deduplication')
        try:
            res = subprocess.run(['sort', '-u', raw_path, '-o', output_path], check=False)
            if res.returncode == 0:
                final_count = sum(1 for _ in open(output_path))
                print(f"[+] Saved {final_count} URLs")
            else:
                raise RuntimeError('sort returned non-zero')
        except Exception:
            seen = set()
            final_count = 0
            with open(raw_path, 'r') as rf, open(output_path, 'w') as of:
                for line in rf:
                    u = line.rstrip()
                    if u and u not in seen:
                        of.write(u + "\n")
                        seen.add(u)
                        final_count += 1
            print(f"[+] Saved {final_count} URLs")

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
            # Calculate execution time
            end_time = time.time()
            elapsed_seconds = int(end_time - start_time)
            hours = elapsed_seconds // 3600
            minutes = (elapsed_seconds % 3600) // 60
            seconds = elapsed_seconds % 60
            
            if hours > 0:
                time_str = f"{hours}h {minutes}m {seconds}s"
            elif minutes > 0:
                time_str = f"{minutes}m {seconds}s"
            else:
                time_str = f"{seconds}s"
            
            # Count total and new unique URLs
            total_found = sum(per_service_counts.values())
            final_count = 0
            if os.path.exists(output_path):
                with open(output_path, 'r') as f:
                    for _ in f:
                        final_count += 1
            
            # Calculate new unique URLs (from the deduplication step)
            new_unique = len(unique_new_urls) if 'unique_new_urls' in locals() else 0
            if not existing_urls:  # If it was a new file
                new_unique = final_count
            
            # Build per-service breakdown
            service_breakdown = "\n".join([f"  • {svc.title()}: {cnt}" for svc, cnt in per_service_counts.items() if svc in providers])
            
            message = (
                f"**🎯 URL Collection Complete**\n\n"
                f"**Domain:** `{domain}`\n"
                f"**Time:** {time_str}\n\n"
                f"**Service Results:**\n{service_breakdown}\n"
                f"**Total Found:** {total_found} URLs\n\n"
                f"**Output:**\n"
                f"  • New Unique: {new_unique}\n"
                f"  • Total in File: {final_count}"
            )

            payload = {"content": message}
            # Discord webhook: Connection timeout: 60s, Read timeout: 15min
            requests.post(webhook_url, json=payload, timeout=(60, 900))
    except Exception:
        pass


if __name__ == "__main__":
    main()
