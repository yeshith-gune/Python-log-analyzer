#!/usr/bin/env python3
import argparse
import sys
from parser import parse_file
from aggregator import aggregate
from detector import detect
from reporter import report_terminal, report_json, report_csv


def main():
    cli = argparse.ArgumentParser(
        description="Detect brute-force attacks from auth.log files"
    )
    cli.add_argument("logfile", help="Path to auth.log (or '-' for stdin)")
    cli.add_argument("--format", choices=["terminal", "json", "csv"],
                     default="terminal")
    cli.add_argument("--severity", choices=["low", "medium", "high", "critical"],
                     default="low", help="Minimum severity to report")
    cli.add_argument("--window", type=int, default=10,
                     help="Sliding window in minutes for burst detection (default: 10)")
    args = cli.parse_args()

    # Parse
    if args.logfile == "-":
