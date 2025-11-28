#!/usr/bin/env python3
"""
Mantissa Log - Rule Testing Tool

Test detection rules against AWS Athena:
- Dry run (validate SQL without executing)
- Test run (execute and show results)
- Backtest (run against historical data)
"""

import sys
import os
import yaml
import argparse
import boto3
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional

class RuleTester:
    def __init__(self, rule_file: str, profile: Optional[str] = None):
        self.rule_file = Path(rule_file)
        self.rule = self.load_rule()

        # Initialize AWS clients
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.athena = session.client('athena')
        self.s3 = session.client('s3')

    def load_rule(self) -> Dict:
        """Load rule from YAML file"""
        try:
            with open(self.rule_file, 'r') as f:
                rule = yaml.safe_load(f)
            return rule
        except Exception as e:
            print(f"Error loading rule: {e}", file=sys.stderr)
            sys.exit(1)

    def dry_run(self):
        """Print SQL without executing"""
        print("=" * 80)
        print(f"DRY RUN: {self.rule['name']}")
        print("=" * 80)
        print(f"\nDescription: {self.rule['description']}")
        print(f"Severity: {self.rule['severity']}")
        print(f"Category: {self.rule['category']}")

        print("\nSQL Query:")
        print("-" * 80)
        print(self.rule['query'])
        print("-" * 80)

        print("\nThreshold:")
        threshold = self.rule.get('threshold', {})
        print(f"  Count: {threshold.get('count')}")
        print(f"  Window: {threshold.get('window')}")

        if 'metadata' in self.rule:
            print("\nMetadata:")
            metadata = self.rule['metadata']
            if 'mitre_attack' in metadata:
                print(f"  MITRE ATT&CK: {', '.join(metadata['mitre_attack'])}")
            if 'tags' in metadata:
                print(f"  Tags: {', '.join(metadata['tags'])}")

    def test_run(self, database: str, output_location: str, max_results: int = 100):
        """Execute rule against Athena"""
        print("=" * 80)
        print(f"TEST RUN: {self.rule['name']}")
        print("=" * 80)

        query = self.rule['query']

        print("\nExecuting query...")
        try:
            response = self.athena.start_query_execution(
                QueryString=query,
                QueryExecutionContext={'Database': database},
                ResultConfiguration={'OutputLocation': output_location}
            )

            query_execution_id = response['QueryExecutionId']
            print(f"Query execution ID: {query_execution_id}")

            # Wait for query to complete
            status = self.wait_for_query(query_execution_id)

            if status != 'SUCCEEDED':
                print(f"\nQuery failed with status: {status}")
                self.print_query_error(query_execution_id)
                return

            # Get results
            results = self.get_query_results(query_execution_id, max_results)
            self.print_results(results)

            # Check threshold
            self.check_threshold(results)

        except Exception as e:
            print(f"\nError executing query: {e}", file=sys.stderr)
            sys.exit(1)

    def backtest(self, database: str, output_location: str, days_back: int = 7):
        """Backtest rule against historical data"""
        print("=" * 80)
        print(f"BACKTEST: {self.rule['name']}")
        print("=" * 80)
        print(f"\nBacktesting over last {days_back} days...")

        # Get the time window from threshold
        window = self.rule.get('threshold', {}).get('window', '1h')
        window_minutes = self.parse_window(window)

        # Calculate time buckets
        now = datetime.utcnow()
        buckets = []

        for i in range(0, days_back * 24 * 60, window_minutes):
            end_time = now - timedelta(minutes=i)
            start_time = end_time - timedelta(minutes=window_minutes)
            buckets.append((start_time, end_time))

        triggered_count = 0
        total_buckets = len(buckets)

        print(f"Testing {total_buckets} time windows...\n")

        for idx, (start_time, end_time) in enumerate(buckets[:20], 1):  # Limit to 20 for demo
            # Modify query to use specific time range
            modified_query = self.modify_query_time_range(
                self.rule['query'],
                start_time,
                end_time
            )

            try:
                response = self.athena.start_query_execution(
                    QueryString=modified_query,
                    QueryExecutionContext={'Database': database},
                    ResultConfiguration={'OutputLocation': output_location}
                )

                query_execution_id = response['QueryExecutionId']
                status = self.wait_for_query(query_execution_id, silent=True)

                if status == 'SUCCEEDED':
                    results = self.get_query_results(query_execution_id, 1)
                    row_count = len(results.get('Rows', [])) - 1  # Subtract header

                    if row_count > 0:
                        threshold_count = self.rule.get('threshold', {}).get('count', 1)
                        if row_count >= threshold_count:
                            triggered_count += 1
                            print(f"[{idx}/{total_buckets}] {start_time.isoformat()} - {end_time.isoformat()}: TRIGGERED ({row_count} matches)")

            except Exception as e:
                print(f"Error in bucket {idx}: {e}")
                continue

        print(f"\nBacktest Summary:")
        print(f"  Windows tested: {min(20, total_buckets)}")
        print(f"  Triggered: {triggered_count}")
        print(f"  Trigger rate: {(triggered_count / min(20, total_buckets)) * 100:.1f}%")

    def wait_for_query(self, query_execution_id: str, silent: bool = False) -> str:
        """Wait for query to complete"""
        while True:
            response = self.athena.get_query_execution(
                QueryExecutionId=query_execution_id
            )

            status = response['QueryExecution']['Status']['State']

            if status in ['SUCCEEDED', 'FAILED', 'CANCELLED']:
                return status

            if not silent:
                print(".", end="", flush=True)

            time.sleep(2)

    def get_query_results(self, query_execution_id: str, max_results: int = 100) -> Dict:
        """Get query results"""
        response = self.athena.get_query_results(
            QueryExecutionId=query_execution_id,
            MaxResults=max_results
        )
        return response['ResultSet']

    def print_query_error(self, query_execution_id: str):
        """Print query error details"""
        response = self.athena.get_query_execution(
            QueryExecutionId=query_execution_id
        )
        error = response['QueryExecution']['Status'].get('StateChangeReason', 'Unknown error')
        print(f"Error: {error}")

    def print_results(self, results: Dict):
        """Print query results in table format"""
        rows = results.get('Rows', [])

        if not rows:
            print("\nNo results")
            return

        print(f"\n\nResults ({len(rows) - 1} rows):")
        print("=" * 80)

        # Get column names
        columns = [col['VarCharValue'] for col in rows[0]['Data']]

        # Print header
        header = " | ".join(f"{col[:20]:20}" for col in columns)
        print(header)
        print("-" * len(header))

        # Print data rows
        for row in rows[1:]:
            values = [cell.get('VarCharValue', 'NULL') for cell in row['Data']]
            print(" | ".join(f"{str(val)[:20]:20}" for val in values))

    def check_threshold(self, results: Dict):
        """Check if results meet threshold"""
        row_count = len(results.get('Rows', [])) - 1  # Subtract header
        threshold = self.rule.get('threshold', {})
        threshold_count = threshold.get('count', 1)

        print(f"\n\nThreshold Check:")
        print(f"  Matches: {row_count}")
        print(f"  Threshold: {threshold_count}")

        if row_count >= threshold_count:
            print(f"  Result: WOULD TRIGGER ALERT")
        else:
            print(f"  Result: Would not trigger")

    def parse_window(self, window: str) -> int:
        """Parse window string to minutes"""
        if window.endswith('m'):
            return int(window[:-1])
        elif window.endswith('h'):
            return int(window[:-1]) * 60
        elif window.endswith('d'):
            return int(window[:-1]) * 24 * 60
        else:
            return 60  # Default 1 hour

    def modify_query_time_range(self, query: str, start_time: datetime, end_time: datetime) -> str:
        """Modify query to use specific time range"""
        # Simple replacement - assumes CURRENT_TIMESTAMP - INTERVAL pattern
        # For production, would use proper SQL parsing
        query = query.replace(
            "CURRENT_TIMESTAMP - INTERVAL",
            f"TIMESTAMP '{end_time.isoformat()}' - INTERVAL"
        )
        return query

def main():
    parser = argparse.ArgumentParser(description='Test Mantissa Log detection rules')
    parser.add_argument('rule_file', help='Path to rule YAML file')
    parser.add_argument('--mode', choices=['dry-run', 'test', 'backtest'], default='dry-run',
                        help='Testing mode (default: dry-run)')
    parser.add_argument('--database', help='Athena database name')
    parser.add_argument('--output-location', help='S3 output location for query results')
    parser.add_argument('--profile', help='AWS profile name')
    parser.add_argument('--max-results', type=int, default=100,
                        help='Maximum results to display (default: 100)')
    parser.add_argument('--days-back', type=int, default=7,
                        help='Days to backtest (default: 7)')

    args = parser.parse_args()

    tester = RuleTester(args.rule_file, args.profile)

    if args.mode == 'dry-run':
        tester.dry_run()
    elif args.mode == 'test':
        if not args.database or not args.output_location:
            print("Error: --database and --output-location required for test mode", file=sys.stderr)
            sys.exit(1)
        tester.test_run(args.database, args.output_location, args.max_results)
    elif args.mode == 'backtest':
        if not args.database or not args.output_location:
            print("Error: --database and --output-location required for backtest mode", file=sys.stderr)
            sys.exit(1)
        tester.backtest(args.database, args.output_location, args.days_back)

if __name__ == '__main__':
    main()
