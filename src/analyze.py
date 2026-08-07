"""Run the review: read exports, classify rules, write a findings CSV.

    python src/analyze.py \
        --aws sample_data/aws_security_groups.json \
        --azure sample_data/azure_nsgs.json \
        --out output/findings.csv

Either input is optional. Counts are reported as both rule rows and unique
resources, because they answer different questions -- rows measure remediation
work, resources measure how much of the estate is affected.
"""

import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from azure_priority import classify_effects
from normalize import load_aws, load_azure
from rules import analyze

COLUMNS = [
    "Finding Type", "Status", "Cloud Platform", "Account",
    "Group ID", "Group Name", "Direction", "Rule Name", "Priority",
    "Action", "Protocol/Port", "Source", "Destination", "Azure Effect",
    "Observation", "Initial Risk Level", "Question for Owner",
    "Recommended Next Step", "Notes",
]

RISK_ORDER = ["High", "Medium", "Needs Review", "Low"]


def summarize(findings, rule_count):
    """Print counts to the terminal."""
    print(f"\n  Rules examined     {rule_count}")
    print(f"  Findings           {len(findings)}")
    print(f"  Scoped, no finding {rule_count - len(findings)}")

    if not findings:
        return

    print("\n  By risk level")
    for level in RISK_ORDER:
        rows = [f for f in findings if f["Initial Risk Level"] == level]
        if rows:
            groups = len({f["Group ID"] for f in rows})
            print(f"    {level:14} {len(rows):>4} rows   {groups:>4} groups")

    print("\n  By finding type")
    types = sorted({f["Finding Type"] for f in findings})
    width = max(len(t) for t in types)
    for name in types:
        rows = [f for f in findings if f["Finding Type"] == name]
        groups = len({f["Group ID"] for f in rows})
        print(f"    {name:{width}}  {len(rows):>4} rows   {groups:>4} groups")


def main():
    parser = argparse.ArgumentParser(
        description="Review AWS Security Group and Azure NSG configurations.")
    parser.add_argument("--aws", help="aws ec2 describe-security-groups JSON")
    parser.add_argument("--azure", help="az network nsg list JSON")
    parser.add_argument("--out", default="output/findings.csv",
                        help="where to write the findings CSV")
    args = parser.parse_args()

    if not args.aws and not args.azure:
        parser.error("provide --aws, --azure, or both")

    rules = []
    if args.aws:
        rules += load_aws(args.aws)
    if args.azure:
        rules += load_azure(args.azure)

    classify_effects(rules)
    findings = analyze(rules)

    findings.sort(key=lambda f: (
        RISK_ORDER.index(f["Initial Risk Level"]),
        f["Cloud Platform"],
        f["Group Name"],
    ))

    directory = os.path.dirname(args.out)
    if directory:
        os.makedirs(directory, exist_ok=True)

    with open(args.out, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(findings)

    summarize(findings, len(rules))
    print(f"\n  Written to {args.out}\n")


if __name__ == "__main__":
    main()
