#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web Directory Buster - A lightweight vulnerability scanner for hidden paths.
Author: Candidate for IIT Kanpur B.Cyber
Description: Multi-threaded directory enumeration using HTTP status codes.
"""

import argparse
import sys
import threading
import queue
import time
from urllib.parse import urljoin, urlparse

# Third-party library (standard in most Python environments)
import requests
from requests.exceptions import RequestException, Timeout, ConnectionError, SSLError

# ----------------------------------------------------------------------
# ASCII Signature Header (Clean, professional, and informative)
# ----------------------------------------------------------------------
BANNER = r"""
  __        __   _     _ _            _         _   _                 
  \ \      / /__| |__ | | | ___ _ __ | |__  ___| |_| |_ ___ _ __ ___ 
   \ \ /\ / / _ \ '_ \| | |/ _ \ '_ \| '_ \/ __| __| __/ _ \ '__/ __|
    \ V  V /  __/ |_) | | |  __/ | | | |_) \__ \ |_| ||  __/ |  \__ \
     \_/\_/ \___|_.__/|_|_|\___|_| |_|_.__/|___/\__|\__\___|_|  |___/
                                                                      
            IIT Kanpur B.Cyber - Web Directory Buster v1.0
            Multi-threaded | Status-Filtered | Production Ready
"""

# ----------------------------------------------------------------------
# Configuration (tweak these for performance)
# ----------------------------------------------------------------------
DEFAULT_THREADS = 20
DEFAULT_TIMEOUT = 5   # seconds
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Status codes we want to display (all except 404, but we can also filter)
# We'll print all statuses except 404, and optionally show 403, 301, 200, etc.
IGNORE_STATUS_CODES = {404}

# ----------------------------------------------------------------------
# Utility: Validate URL and normalize
# ----------------------------------------------------------------------
def validate_url(url: str) -> str:
    """Ensure URL has a scheme and ends with a slash for joining."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    # Parse to check validity
    parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError("Invalid URL: missing domain")
    # Ensure trailing slash for correct path joining
    if not url.endswith('/'):
        url += '/'
    return url

# ----------------------------------------------------------------------
# Worker function for each thread
# ----------------------------------------------------------------------
def worker(work_queue: queue.Queue, result_list: list, url_base: str,
           timeout: int, verbose: bool, show_redirects: bool):
    """
    Thread worker: pulls paths from queue, performs GET request,
    filters status, and appends results to shared list.
    """
    session = requests.Session()
    session.headers.update({'User-Agent': USER_AGENT})

    while True:
        try:
            path = work_queue.get(timeout=1)  # non-blocking with timeout
        except queue.Empty:
            break  # no more work, thread exits

        # Construct full URL
        full_url = urljoin(url_base, path.lstrip('/'))
        try:
            # Perform GET request with timeout and SSL verification disabled? 
            # (We'll allow self-signed certs but warn - configurable)
            # For security we keep verification on by default, but allow override.
            resp = session.get(full_url, timeout=timeout, allow_redirects=False)
            status = resp.status_code

            # Determine if we should report this status
            if status not in IGNORE_STATUS_CODES:
                # Build a descriptive status line
                status_desc = f"{status} {resp.reason}" if resp.reason else str(status)
                # For redirects, show Location header if asked
                if show_redirects and 300 <= status < 400:
                    location = resp.headers.get('Location', '')
                    if location:
                        status_desc += f" -> {location}"
                # Collect result
                result_list.append((full_url, status_desc))
            elif verbose:
                # If verbose, show even 404s (but we said we don't want clutter)
                # But we can optionally show them with -v
                result_list.append((full_url, f"{status} (ignored)"))

        except Timeout:
            result_list.append((full_url, "TIMEOUT"))
        except ConnectionError:
            result_list.append((full_url, "CONNECTION ERROR"))
        except SSLError:
            result_list.append((full_url, "SSL ERROR"))
        except RequestException as e:
            # Catch-all for other requests errors
            result_list.append((full_url, f"REQUEST ERROR: {str(e)}"))
        except Exception as e:
            # Unexpected errors (should not happen)
            result_list.append((full_url, f"UNEXPECTED ERROR: {str(e)}"))

        finally:
            work_queue.task_done()

# ----------------------------------------------------------------------
# Main orchestration
# ----------------------------------------------------------------------
def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Web Directory Buster - Enumerate hidden paths on a target website.",
        epilog="Example: python dirbuster.py -u http://example.com -w common.txt -t 30"
    )
    parser.add_argument(
        '-u', '--url',
        required=True,
        help="Target website URL (e.g., http://example.com)"
    )
    parser.add_argument(
        '-w', '--wordlist',
        help="Path to file containing list of paths (one per line)"
    )
    parser.add_argument(
        '-p', '--paths',
        help="Comma-separated list of paths (overrides -w if both given)"
    )
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=DEFAULT_THREADS,
        help=f"Number of concurrent threads (default: {DEFAULT_THREADS})"
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})"
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help="Display all statuses including 404 (may cause clutter)"
    )
    parser.add_argument(
        '--show-redirects',
        action='store_true',
        help="Show redirect Location header for 3xx responses"
    )
    args = parser.parse_args()

    # Display banner
    print(BANNER)
    print(f"[*] Target URL: {args.url}")
    print(f"[*] Threads: {args.threads}")
    print(f"[*] Timeout: {args.timeout}s")
    print(f"[*] Verbose: {args.verbose}")
    print("[*] Filtering out status codes:", ', '.join(str(s) for s in IGNORE_STATUS_CODES))
    print("-" * 60)

    # Validate and normalize URL
    try:
        base_url = validate_url(args.url)
    except ValueError as e:
        print(f"[!] Invalid URL: {e}")
        sys.exit(1)

    # Load paths from either wordlist file or comma-separated list
    paths = []
    if args.paths:
        # Split by comma and strip whitespace
        paths = [p.strip() for p in args.paths.split(',') if p.strip()]
        print(f"[*] Loaded {len(paths)} paths from command-line list.")
    elif args.wordlist:
        try:
            with open(args.wordlist, 'r', encoding='utf-8') as f:
                paths = [line.strip() for line in f if line.strip()]
            print(f"[*] Loaded {len(paths)} paths from wordlist '{args.wordlist}'.")
        except FileNotFoundError:
            print(f"[!] Wordlist file not found: {args.wordlist}")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error reading wordlist: {e}")
            sys.exit(1)
    else:
        print("[!] You must provide either -w or -p.")
        parser.print_help()
        sys.exit(1)

    if not paths:
        print("[!] No paths to test. Exiting.")
        sys.exit(1)

    # Create work queue and populate
    work_queue = queue.Queue()
    for path in paths:
        work_queue.put(path)

    # Shared result list (thread-safe because we only append)
    results = []

    # Start threads
    threads = []
    start_time = time.time()

    for _ in range(min(args.threads, len(paths))):  # don't create more threads than jobs
        t = threading.Thread(
            target=worker,
            args=(work_queue, results, base_url, args.timeout, args.verbose, args.show_redirects)
        )
        t.daemon = True  # allows Ctrl+C to exit
        t.start()
        threads.append(t)

    # Wait for all threads to finish (queue empty)
    work_queue.join()

    # Wait for all threads to actually terminate (optional)
    for t in threads:
        t.join(timeout=0.1)

    elapsed = time.time() - start_time

    # Sort results by URL for consistency
    results.sort(key=lambda x: x[0])

    # Output results
    print("\n" + "=" * 60)
    print(f"[*] Scan completed in {elapsed:.2f} seconds.")
    print(f"[*] Total paths tested: {len(paths)}")
    print(f"[*] Found {len([r for r in results if '404' not in r[1] and 'ignored' not in r[1]])} interesting entries.")
    print("-" * 60)

    if results:
        # Format as table (URL + status)
        max_url_len = max(len(r[0]) for r in results) if results else 0
        max_url_len = min(max_url_len, 80)  # avoid huge width
        fmt_str = f"{{:<{max_url_len + 2}}} {{}}"

        print(fmt_str.format("URL", "STATUS / MESSAGE"))
        print("-" * (max_url_len + 30))
        for url, status in results:
            print(fmt_str.format(url, status))
    else:
        print("[*] No results (all paths returned 404 or errors).")

    print("\n[+] Done.")

# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting gracefully...")
        sys.exit(0)