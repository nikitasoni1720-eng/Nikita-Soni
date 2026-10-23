"""
Main Entry Point for WebScanner
Automated Web Scanner for Secure HTTP Headers and CORS Flaws.
"""

import argparse
import sys
import os
from typing import List

from config import DEFAULT_TIMEOUT, DEFAULT_USER_AGENT
from http_client import HttpClient
from header_scanner import HeaderScanner, ScanReport
from reporter import Reporter
from logger import setup_logger


def parse_arguments() -> argparse.Namespace:
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Automated Web Scanner: Audit websites for secure HTTP headers and CORS misconfigurations.",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument(
        "-u", "--url",
        type=str,
        help="Target website URL to scan (e.g. https://example.com)",
    )
    target_group.add_argument(
        "-f", "--file",
        type=str,
        help="Path to a text file containing target URLs (one URL per line)",
    )

    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Path to save report output file (e.g. results.json or results.txt)",
    )
    parser.add_argument(
        "--format",
        choices=["json", "txt"],
        default=None,
        help="Report export format (default: inferred from --output extension, or json)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--user-agent",
        type=str,
        default=DEFAULT_USER_AGENT,
        help="Custom User-Agent header string",
    )
    parser.add_argument(
        "--no-cors",
        action="store_true",
        help="Disable active CORS origin probing (only audit static headers)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable SSL/TLS certificate verification (warning: not recommended)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in console output",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose / debug logging",
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default="webscanner.log",
        help="File path for logging output (set to 'none' to disable file logs)",
    )

    return parser.parse_args()


def load_urls_from_file(file_path: str) -> List[str]:
    """Reads and parses target URLs from a file."""
    if not os.path.exists(file_path):
        print(f"[!] Error: URL list file not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    urls = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            clean = line.strip()
            if clean and not clean.startswith("#"):
                urls.append(clean)

    if not urls:
        print(f"[!] Warning: No valid URLs found in {file_path}", file=sys.stderr)
        sys.exit(1)

    return urls


def main():
    args = parse_arguments()

    # Configure logger
    log_file_target = None if args.log_file.lower() == "none" else args.log_file
    logger = setup_logger(verbose=args.verbose, log_file=log_file_target)

    # Determine targets
    urls_to_scan: List[str] = []

    if args.url:
        urls_to_scan.append(args.url.strip())
    elif args.file:
        urls_to_scan = load_urls_from_file(args.file)
    else:
        # Interactive mode when no arguments supplied
        print("=" * 65)
        print("          WebScanner - HTTP Security & CORS Auditor")
        print("=" * 65)
        try:
            prompt_url = input("Enter target website URL (e.g., https://example.com): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nScan aborted by user.")
            sys.exit(0)

        if not prompt_url:
            print("[!] Error: No URL provided. Exiting.")
            sys.exit(1)
        urls_to_scan.append(prompt_url)

    # Initialize components
    http_client = HttpClient(
        timeout=args.timeout,
        user_agent=args.user_agent,
        verify_ssl=not args.insecure,
    )
    scanner = HeaderScanner(http_client=http_client)
    reporter = Reporter(use_color=not args.no_color)

    reports: List[ScanReport] = []
    logger.info(f"Starting audit of {len(urls_to_scan)} target(s)...")

    for idx, target in enumerate(urls_to_scan, start=1):
        logger.info(f"[{idx}/{len(urls_to_scan)}] Scanning target: {target}")
        report = scanner.scan(target, test_cors_active=not args.no_cors)
        reports.append(report)
        reporter.print_report(report)

    # Export report if requested
    if args.output:
        out_ext = os.path.splitext(args.output)[1].lower()
        fmt = args.format or ("txt" if out_ext in (".txt", ".text") else "json")

        if fmt == "json":
            reporter.save_json(reports, args.output)
        else:
            reporter.save_text(reports, args.output)

    logger.info("Scan completed successfully.")


if __name__ == "__main__":
    main()
