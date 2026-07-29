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