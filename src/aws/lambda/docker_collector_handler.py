"""
Docker Container Runtime Log Collector

Processes Docker daemon events and container logs delivered to S3 (via Fluent Bit,
Fluentd, Vector, or similar log shippers). Normalizes events and stores in the
Mantissa Log data lake.

Deployment Models:
1. S3 Event Notification: Lambda triggered when new logs land in S3
2. Scheduled Processing: Lambda polls S3 prefix for new files
3. API Gateway: Direct log shipping endpoint

Supported Log Formats:
- Docker events API JSON (from `docker events --format '{{json .}}'`)
- Container stdout/stderr logs (JSON format from logging drivers)
- Fluent Bit/Fluentd wrapped logs
- Vector formatted logs
"""

import json
import os
import gzip
import boto3
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from io import BytesIO

from shared.parsers.docker import DockerParser


class DockerCollector:
    """Processes Docker logs from S3"""

    def __init__(
        self,
        s3_bucket: str,
        source_prefix: str,
        output_prefix: str,
        checkpoint_table: str
    ):
        """
        Initialize Docker collector.

        Args:
            s3_bucket: S3 bucket containing Docker logs
            source_prefix: S3 prefix where raw logs land
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

        self.parser = DockerParser()

    def get_last_checkpoint(self, host_name: str = 'default') -> Optional[str]:
        """
        Get last processed file marker from DynamoDB.

        Args:
            host_name: Docker host identifier

        Returns:
            Last processed S3 key or None
        """
        try:
            response = self.table.get_item(
                Key={'source': f'docker:{host_name}'}
            )
            if 'Item' in response:
                return response['Item'].get('last_processed_key')
        except Exception as e:
            print(f"Error getting checkpoint: {str(e)}")

        return None

    def save_checkpoint(self, s3_key: str, host_name: str = 'default') -> None:
        """
        Save checkpoint to DynamoDB.

        Args:
            s3_key: Last processed S3 key
            host_name: Docker host identifier
        """
        try:
            self.table.put_item(
                Item={
                    'source': f'docker:{host_name}',
                    'last_processed_key': s3_key,
                    'updated_at': datetime.now(timezone.utc).isoformat()
                }
            )
        except Exception as e:
            print(f"Error saving checkpoint: {str(e)}")

    def list_unprocessed_files(
        self,
        host_name: str = 'default',
        max_files: int = 100
    ) -> List[str]:
        """
        List S3 files that haven't been processed yet.

        Args:
            host_name: Docker host identifier
            max_files: Maximum files to process in one run

        Returns:
            List of S3 keys to process
        """
        last_key = self.get_last_checkpoint(host_name)

        # List files in source prefix
        paginator = self.s3.get_paginator('list_objects_v2')
        prefix = f"{self.source_prefix}/{host_name}/"

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

    def read_log_file(self, s3_key: str) -> List[Dict[str, Any]]:
        """
        Read and parse log file from S3.

        Supports:
        - JSON lines format
        - Gzipped JSON lines
        - Single JSON array
        - Fluent Bit/Fluentd wrapped format

        Args:
            s3_key: S3 key to read

        Returns:
            List of log events
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

                    # Handle Fluent Bit/Fluentd wrapped events
                    if 'log' in event and isinstance(event['log'], str):
                        try:
                            inner = json.loads(event['log'])
                            # Merge wrapper fields
                            inner['_wrapper'] = {k: v for k, v in event.items() if k != 'log'}
                            event = inner
                        except json.JSONDecodeError:
                            # Keep as container log
                            pass

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
                        events = [data]
                except json.JSONDecodeError:
                    print(f"Failed to parse file as JSON: {s3_key}")

            return events

        except Exception as e:
            print(f"Error reading file {s3_key}: {str(e)}")
            return []

    def process_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse and normalize Docker events.

        Args:
            events: Raw Docker events

        Returns:
            Normalized events
        """
        normalized = []

        for event in events:
            # Validate event structure
            if not self.parser.validate(event):
                print(f"Invalid Docker event: skipping")
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
        host_name: str,
        timestamp: datetime
    ) -> Optional[str]:
        """
        Write normalized events to S3.

        Args:
            events: Normalized events
            host_name: Docker host name
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
            f"{self.output_prefix}/{host_name}/normalized/"
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

    def process_file(self, s3_key: str, host_name: str = 'default') -> Dict[str, Any]:
        """
        Process a single log file.

        Args:
            s3_key: S3 key to process
            host_name: Docker host identifier

        Returns:
            Processing statistics
        """
        print(f"Processing file: {s3_key}")

        # Read events
        events = self.read_log_file(s3_key)

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
            output_key = self.write_normalized_events(normalized, host_name, now)

        return {
            'source_key': s3_key,
            'events_read': len(events),
            'events_normalized': len(normalized),
            'output_key': output_key
        }

    def collect_scheduled(self, host_name: str = 'default') -> Dict[str, Any]:
        """
        Scheduled collection mode: process all unprocessed files.

        Args:
            host_name: Docker host identifier

        Returns:
            Collection statistics
        """
        # List unprocessed files
        files = self.list_unprocessed_files(host_name)
        print(f"Found {len(files)} unprocessed files")

        total_events = 0
        total_normalized = 0
        processed_files = []

        for s3_key in files:
            result = self.process_file(s3_key, host_name)
            total_events += result['events_read']
            total_normalized += result['events_normalized']
            processed_files.append(result)

            # Update checkpoint after each file
            self.save_checkpoint(s3_key, host_name)

        return {
            'mode': 'scheduled',
            'host_name': host_name,
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

            # Extract host name from path
            # Expected: {source_prefix}/{host_name}/...
            path_parts = key.split('/')
            host_name = 'default'
            if len(path_parts) > 1:
                for i, part in enumerate(path_parts):
                    if part == self.source_prefix.split('/')[-1]:
                        if i + 1 < len(path_parts):
                            host_name = path_parts[i + 1]
                        break

            result = self.process_file(key, host_name)
            self.save_checkpoint(key, host_name)
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

    def process_direct_events(
        self,
        events: List[Dict[str, Any]],
        host_name: str = 'default'
    ) -> Dict[str, Any]:
        """
        Direct mode: process events sent via API.

        Args:
            events: Raw Docker events
            host_name: Docker host identifier

        Returns:
            Processing statistics
        """
        # Normalize events
        normalized = self.process_events(events)

        # Write normalized output
        output_key = None
        if normalized:
            now = datetime.now(timezone.utc)
            output_key = self.write_normalized_events(normalized, host_name, now)

        return {
            'mode': 'direct',
            'host_name': host_name,
            'events_received': len(events),
            'events_normalized': len(normalized),
            'output_key': output_key
        }


def lambda_handler(event, context):
    """
    AWS Lambda handler for Docker log collection.

    Supports three invocation modes:
    1. Scheduled: Triggered by EventBridge rule
    2. S3 Event: Triggered by S3 event notification
    3. Direct: API Gateway invocation for direct log shipping

    Environment Variables:
        S3_BUCKET: S3 bucket for log storage
        SOURCE_PREFIX: S3 prefix where raw logs land
        OUTPUT_PREFIX: S3 prefix for normalized output
        CHECKPOINT_TABLE: DynamoDB table for checkpoint tracking
        HOST_NAME: Default Docker host name (optional)
    """
    # Get configuration from environment
    s3_bucket = os.environ.get('S3_BUCKET', 'mantissa-log-data')
    source_prefix = os.environ.get('SOURCE_PREFIX', 'docker/raw')
    output_prefix = os.environ.get('OUTPUT_PREFIX', 'docker')
    checkpoint_table = os.environ.get('CHECKPOINT_TABLE', 'mantissa-log-checkpoints')
    default_host = os.environ.get('HOST_NAME', 'default')

    # Initialize collector
    collector = DockerCollector(
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

        # Mode 2: API Gateway Direct Log Shipping
        elif 'httpMethod' in event or 'requestContext' in event:
            print("Processing direct API request")

            # Parse body
            body = event.get('body', '{}')
            if isinstance(body, str):
                body = json.loads(body)

            # Handle single event or array
            if isinstance(body, dict):
                # Single event or wrapped events
                if 'Type' in body or 'type' in body or 'log' in body:
                    events = [body]
                elif 'events' in body:
                    events = body['events']
                else:
                    events = [body]
            elif isinstance(body, list):
                events = body
            else:
                events = []

            # Get host name from path or query params
            path_params = event.get('pathParameters', {}) or {}
            query_params = event.get('queryStringParameters', {}) or {}
            host_name = (
                path_params.get('host') or
                query_params.get('host') or
                default_host
            )

            result = collector.process_direct_events(events, host_name)

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

            # Check if specific host requested
            host_name = event.get('host_name', default_host)
            result = collector.collect_scheduled(host_name)

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
