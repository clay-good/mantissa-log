"""
Kubernetes Audit Log Collector

Processes Kubernetes audit logs delivered to S3 (via Fluent Bit, Fluentd,
or audit webhook). Normalizes events and stores in the Mantissa Log data lake.

Deployment Models:
1. S3 Event Notification: Lambda triggered when new audit logs land in S3
2. Scheduled Processing: Lambda polls S3 prefix for new files
3. Audit Webhook: API Gateway -> Lambda for direct audit webhook delivery

This collector supports all three models.
"""

import json
import os
import gzip
import boto3
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from io import BytesIO

from shared.parsers.kubernetes import KubernetesParser


class KubernetesCollector:
    """Processes Kubernetes audit logs from S3"""

    def __init__(
        self,
        s3_bucket: str,
        source_prefix: str,
        output_prefix: str,
        checkpoint_table: str
    ):
        """
        Initialize Kubernetes collector.

        Args:
            s3_bucket: S3 bucket containing audit logs
            source_prefix: S3 prefix where raw audit logs land
            output_prefix: S3 prefix for normalized output
            checkpoint_table: DynamoDB table for checkpoint tracking
        """
        self.s3_bucket = s3_bucket
        self.source_prefix = source_prefix
        self.output_prefix = output_prefix
        self.checkpoint_table = checkpoint_table

        self.s3 = boto3.client('s3')
        self.dynamodb = boto3.resource('dynamodb')
        self.table = self.dynamodb.Table(checkpoint_table)

        self.parser = KubernetesParser()

    def get_last_checkpoint(self, cluster_name: str = 'default') -> Optional[str]:
        """
        Get last processed file marker from DynamoDB.

        Args:
            cluster_name: Kubernetes cluster identifier

        Returns:
            Last processed S3 key or None
        """
        try:
            response = self.table.get_item(
                Key={'source': f'kubernetes:{cluster_name}'}
            )
            if 'Item' in response:
                return response['Item'].get('last_processed_key')
        except Exception as e:
            print(f"Error getting checkpoint: {str(e)}")

        return None

    def save_checkpoint(self, s3_key: str, cluster_name: str = 'default') -> None:
        """
        Save checkpoint to DynamoDB.

        Args:
            s3_key: Last processed S3 key
            cluster_name: Kubernetes cluster identifier
        """
        try:
            self.table.put_item(
                Item={
                    'source': f'kubernetes:{cluster_name}',
                    'last_processed_key': s3_key,
                    'updated_at': datetime.now(timezone.utc).isoformat()
                }
            )
        except Exception as e:
            print(f"Error saving checkpoint: {str(e)}")

    def list_unprocessed_files(
        self,
        cluster_name: str = 'default',
        max_files: int = 100
    ) -> List[str]:
        """
        List S3 files that haven't been processed yet.

        Args:
            cluster_name: Kubernetes cluster identifier
            max_files: Maximum files to process in one run

        Returns:
            List of S3 keys to process
        """
        last_key = self.get_last_checkpoint(cluster_name)

        # List files in source prefix
        paginator = self.s3.get_paginator('list_objects_v2')
        prefix = f"{self.source_prefix}/{cluster_name}/"

        files = []
        for page in paginator.paginate(Bucket=self.s3_bucket, Prefix=prefix):
            for obj in page.get('Contents', []):
                key = obj['Key']

                # Skip directories
                if key.endswith('/'):
                    continue

                # Skip already processed files
                if last_key and key <= last_key:
                    continue

                files.append(key)

                if len(files) >= max_files:
                    break

            if len(files) >= max_files:
                break

        # Sort by key (typically includes timestamp)
        files.sort()
        return files

    def read_audit_file(self, s3_key: str) -> List[Dict[str, Any]]:
        """
        Read and parse audit log file from S3.

        Supports:
        - JSON lines format
        - Gzipped JSON lines
        - Single JSON array

        Args:
            s3_key: S3 key to read

        Returns:
            List of audit events
        """
        try:
            response = self.s3.get_object(Bucket=self.s3_bucket, Key=s3_key)
            content = response['Body'].read()

            # Check if gzipped
            if s3_key.endswith('.gz') or content[:2] == b'\x1f\x8b':
                content = gzip.decompress(content)

            # Decode
            text = content.decode('utf-8')

            events = []

            # Try JSON lines format first
            for line in text.strip().split('\n'):
                line = line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)

                    # Handle wrapped events (e.g., from Fluent Bit)
                    if 'log' in event and isinstance(event['log'], str):
                        event = json.loads(event['log'])

                    # Handle array format within line
                    if isinstance(event, list):
                        events.extend(event)
                    else:
                        events.append(event)

                except json.JSONDecodeError:
                    continue

            # If no events parsed as JSON lines, try as single JSON array
            if not events:
                try:
                    data = json.loads(text)
                    if isinstance(data, list):
                        events = data
                    elif isinstance(data, dict):
                        # Single event
                        events = [data]
                except json.JSONDecodeError:
                    print(f"Failed to parse file as JSON: {s3_key}")

            return events

        except Exception as e:
            print(f"Error reading file {s3_key}: {str(e)}")
            return []

    def process_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse and normalize audit events.

        Args:
            events: Raw audit events

        Returns:
            Normalized events
        """
        normalized = []

        for event in events:
            # Validate event structure
            if not self.parser.validate(event):
                print(f"Invalid audit event: {event.get('auditID', 'unknown')}")
                continue

            try:
                normalized_event = self.parser.parse(event)
                normalized.append(normalized_event)
            except Exception as e:
                print(f"Error parsing event: {str(e)}")
                continue

        return normalized

    def write_normalized_events(
        self,
        events: List[Dict[str, Any]],
        cluster_name: str,
        timestamp: datetime
    ) -> Optional[str]:
        """
        Write normalized events to S3.

        Args:
            events: Normalized events
            cluster_name: Kubernetes cluster name
            timestamp: Timestamp for partitioning

        Returns:
            S3 key where data was written
        """
        if not events:
            return None

        # Create partition path
        year = timestamp.strftime('%Y')
        month = timestamp.strftime('%m')
        day = timestamp.strftime('%d')
        hour = timestamp.strftime('%H')
        minute = timestamp.strftime('%M')
        second = timestamp.strftime('%S')

        s3_key = (
            f"{self.output_prefix}/{cluster_name}/normalized/"
            f"{year}/{month}/{day}/{hour}/events_{minute}{second}.json"
        )

        # Write as newline-delimited JSON
        data = '\n'.join([json.dumps(event) for event in events])

        try:
            self.s3.put_object(
                Bucket=self.s3_bucket,
                Key=s3_key,
                Body=data.encode('utf-8'),
                ContentType='application/json'
            )
            print(f"Wrote {len(events)} events to s3://{self.s3_bucket}/{s3_key}")
            return s3_key

        except Exception as e:
            print(f"Error writing to S3: {str(e)}")
            raise

    def process_file(self, s3_key: str, cluster_name: str = 'default') -> Dict[str, Any]:
        """
        Process a single audit log file.

        Args:
            s3_key: S3 key to process
            cluster_name: Kubernetes cluster identifier

        Returns:
            Processing statistics
        """
        print(f"Processing file: {s3_key}")

        # Read events
        events = self.read_audit_file(s3_key)

        if not events:
            return {
                'source_key': s3_key,
                'events_read': 0,
                'events_normalized': 0,
                'output_key': None
            }

        # Normalize events
        normalized = self.process_events(events)

        # Write normalized output
        output_key = None
        if normalized:
            now = datetime.now(timezone.utc)
            output_key = self.write_normalized_events(normalized, cluster_name, now)

        return {
            'source_key': s3_key,
            'events_read': len(events),
            'events_normalized': len(normalized),
            'output_key': output_key
        }

    def collect_scheduled(self, cluster_name: str = 'default') -> Dict[str, Any]:
        """
        Scheduled collection mode: process all unprocessed files.

        Args:
            cluster_name: Kubernetes cluster identifier

        Returns:
            Collection statistics
        """
        # List unprocessed files
        files = self.list_unprocessed_files(cluster_name)
        print(f"Found {len(files)} unprocessed files")

        total_events = 0
        total_normalized = 0
        processed_files = []

        for s3_key in files:
            result = self.process_file(s3_key, cluster_name)
            total_events += result['events_read']
            total_normalized += result['events_normalized']
            processed_files.append(result)

            # Update checkpoint after each file
            self.save_checkpoint(s3_key, cluster_name)

        return {
            'mode': 'scheduled',
            'cluster_name': cluster_name,
            'files_processed': len(files),
            'total_events': total_events,
            'total_normalized': total_normalized,
            'files': processed_files
        }

    def collect_s3_event(self, s3_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        S3 event notification mode: process specific file from event.

        Args:
            s3_event: S3 event notification

        Returns:
            Processing statistics
        """
        results = []

        for record in s3_event.get('Records', []):
            bucket = record['s3']['bucket']['name']
            key = record['s3']['object']['key']

            # Extract cluster name from path
            # Expected: {source_prefix}/{cluster_name}/...
            path_parts = key.split('/')
            cluster_name = 'default'
            if len(path_parts) > 1:
                for i, part in enumerate(path_parts):
                    if part == self.source_prefix.split('/')[-1]:
                        if i + 1 < len(path_parts):
                            cluster_name = path_parts[i + 1]
                        break

            result = self.process_file(key, cluster_name)
            self.save_checkpoint(key, cluster_name)
            results.append(result)

        total_events = sum(r['events_read'] for r in results)
        total_normalized = sum(r['events_normalized'] for r in results)

        return {
            'mode': 's3_event',
            'files_processed': len(results),
            'total_events': total_events,
            'total_normalized': total_normalized,
            'files': results
        }

    def process_webhook_events(self, events: List[Dict[str, Any]], cluster_name: str = 'default') -> Dict[str, Any]:
        """
        Webhook mode: process events sent directly via API.

        Args:
            events: Raw audit events from webhook
            cluster_name: Kubernetes cluster identifier

        Returns:
            Processing statistics
        """
        # Normalize events
        normalized = self.process_events(events)

        # Write normalized output
        output_key = None
        if normalized:
            now = datetime.now(timezone.utc)
            output_key = self.write_normalized_events(normalized, cluster_name, now)

        return {
            'mode': 'webhook',
            'cluster_name': cluster_name,
            'events_received': len(events),
            'events_normalized': len(normalized),
            'output_key': output_key
        }


def lambda_handler(event, context):
    """
    AWS Lambda handler for Kubernetes audit log collection.

    Supports three invocation modes:
    1. Scheduled: Triggered by EventBridge rule
    2. S3 Event: Triggered by S3 event notification
    3. Webhook: Direct API Gateway invocation from audit webhook

    Environment Variables:
        S3_BUCKET: S3 bucket for log storage
        SOURCE_PREFIX: S3 prefix where raw audit logs land
        OUTPUT_PREFIX: S3 prefix for normalized output
        CHECKPOINT_TABLE: DynamoDB table for checkpoint tracking
        CLUSTER_NAME: Default cluster name (optional)
    """
    # Get configuration from environment
    s3_bucket = os.environ.get('S3_BUCKET', 'mantissa-log-data')
    source_prefix = os.environ.get('SOURCE_PREFIX', 'kubernetes/raw')
    output_prefix = os.environ.get('OUTPUT_PREFIX', 'kubernetes')
    checkpoint_table = os.environ.get('CHECKPOINT_TABLE', 'mantissa-log-checkpoints')
    default_cluster = os.environ.get('CLUSTER_NAME', 'default')

    # Initialize collector
    collector = KubernetesCollector(
        s3_bucket=s3_bucket,
        source_prefix=source_prefix,
        output_prefix=output_prefix,
        checkpoint_table=checkpoint_table
    )

    try:
        # Determine invocation mode

        # Mode 1: S3 Event Notification
        if 'Records' in event and event['Records'][0].get('eventSource') == 'aws:s3':
            print("Processing S3 event notification")
            result = collector.collect_s3_event(event)

        # Mode 2: API Gateway Webhook
        elif 'httpMethod' in event or 'requestContext' in event:
            print("Processing webhook request")

            # Parse body
            body = event.get('body', '{}')
            if isinstance(body, str):
                body = json.loads(body)

            # Handle single event or array
            if isinstance(body, dict):
                # Single audit event
                events = [body] if 'auditID' in body else body.get('items', [])
            elif isinstance(body, list):
                events = body
            else:
                events = []

            # Get cluster name from path or query params
            path_params = event.get('pathParameters', {}) or {}
            query_params = event.get('queryStringParameters', {}) or {}
            cluster_name = (
                path_params.get('cluster') or
                query_params.get('cluster') or
                default_cluster
            )

            result = collector.process_webhook_events(events, cluster_name)

            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': json.dumps(result)
            }

        # Mode 3: Scheduled Execution (EventBridge)
        else:
            print("Processing scheduled collection")

            # Check if specific cluster requested
            cluster_name = event.get('cluster_name', default_cluster)
            result = collector.collect_scheduled(cluster_name)

        return {
            'statusCode': 200,
            'body': json.dumps(result)
        }

    except Exception as e:
        print(f"Collection failed: {str(e)}")
        import traceback
        traceback.print_exc()

        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }
