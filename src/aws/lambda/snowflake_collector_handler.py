"""
Snowflake Audit Log Collector

Fetches audit logs from Snowflake ACCOUNT_USAGE schema views including:
- LOGIN_HISTORY (authentication events)
- QUERY_HISTORY (data access and query execution)
- ACCESS_HISTORY (object-level access tracking)
- SESSIONS (session lifecycle)
- GRANTS_TO_USERS / GRANTS_TO_ROLES (permission changes)
- WAREHOUSE_EVENTS_HISTORY (warehouse operations)
- COPY_HISTORY (data loading)
- DATA_TRANSFER_HISTORY (data export/replication)

Stores logs in S3 for processing by Mantissa Log.

API Reference: https://docs.snowflake.com/en/sql-reference/account-usage
"""

import json
import os
import boto3
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
import snowflake.connector
from snowflake.connector import DictCursor


class SnowflakeCollector:
    """Collects audit logs from Snowflake ACCOUNT_USAGE schema"""

    # Available log views in ACCOUNT_USAGE
    LOG_VIEWS = {
        'login_history': {
            'view': 'SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY',
            'timestamp_field': 'EVENT_TIMESTAMP',
            'lookback_hours': 1,
            'order_by': 'EVENT_TIMESTAMP'
        },
        'query_history': {
            'view': 'SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY',
            'timestamp_field': 'START_TIME',
            'lookback_hours': 1,
            'order_by': 'START_TIME'
        },
        'access_history': {
            'view': 'SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY',
            'timestamp_field': 'QUERY_START_TIME',
            'lookback_hours': 1,
            'order_by': 'QUERY_START_TIME'
        },
        'sessions': {
            'view': 'SNOWFLAKE.ACCOUNT_USAGE.SESSIONS',
            'timestamp_field': 'CREATED_ON',
            'lookback_hours': 1,
            'order_by': 'CREATED_ON'
        },
        'grants_to_users': {
            'view': 'SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS',
            'timestamp_field': 'CREATED_ON',
            'lookback_hours': 24,
            'order_by': 'CREATED_ON'
        },
        'grants_to_roles': {
            'view': 'SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES',
            'timestamp_field': 'CREATED_ON',
            'lookback_hours': 24,
            'order_by': 'CREATED_ON'
        },
        'warehouse_events': {
            'view': 'SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_EVENTS_HISTORY',
            'timestamp_field': 'TIMESTAMP',
            'lookback_hours': 1,
            'order_by': 'TIMESTAMP'
        },
        'copy_history': {
            'view': 'SNOWFLAKE.ACCOUNT_USAGE.COPY_HISTORY',
            'timestamp_field': 'LAST_LOAD_TIME',
            'lookback_hours': 1,
            'order_by': 'LAST_LOAD_TIME'
        },
        'data_transfer': {
            'view': 'SNOWFLAKE.ACCOUNT_USAGE.DATA_TRANSFER_HISTORY',
            'timestamp_field': 'START_TIME',
            'lookback_hours': 24,
            'order_by': 'START_TIME'
        }
    }

    def __init__(
        self,
        account: str,
        user: str,
        password: str = None,
        private_key: str = None,
        private_key_passphrase: str = None,
        warehouse: str = 'COMPUTE_WH',
        role: str = 'ACCOUNTADMIN',
        s3_bucket: str = None,
        checkpoint_table: str = None
    ):
        """
        Initialize Snowflake collector.

        Args:
            account: Snowflake account identifier (e.g., xy12345.us-east-1)
            user: Snowflake username
            password: Snowflake password (for password auth)
            private_key: Private key content (for key-pair auth)
            private_key_passphrase: Passphrase for encrypted private key
            warehouse: Warehouse to use for queries
            role: Role to use (needs ACCOUNT_USAGE access)
            s3_bucket: S3 bucket for log storage
            checkpoint_table: DynamoDB table for checkpoint tracking
        """
        self.account = account
        self.user = user
        self.password = password
        self.private_key = private_key
        self.private_key_passphrase = private_key_passphrase
        self.warehouse = warehouse
        self.role = role
        self.s3_bucket = s3_bucket
        self.checkpoint_table = checkpoint_table

        self.s3 = boto3.client('s3')
        self.dynamodb = boto3.resource('dynamodb')
        self.table = self.dynamodb.Table(checkpoint_table) if checkpoint_table else None

        self.connection = None

    def connect(self) -> bool:
        """
        Establish connection to Snowflake.

        Returns:
            True if connection successful
        """
        try:
            conn_params = {
                'account': self.account,
                'user': self.user,
                'warehouse': self.warehouse,
                'role': self.role,
                'database': 'SNOWFLAKE',
                'schema': 'ACCOUNT_USAGE'
            }

            if self.private_key:
                # Key-pair authentication
                from cryptography.hazmat.backends import default_backend
                from cryptography.hazmat.primitives import serialization

                p_key = serialization.load_pem_private_key(
                    self.private_key.encode('utf-8'),
                    password=self.private_key_passphrase.encode('utf-8') if self.private_key_passphrase else None,
                    backend=default_backend()
                )

                pkb = p_key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )

                conn_params['private_key'] = pkb
            else:
                # Password authentication
                conn_params['password'] = self.password

            self.connection = snowflake.connector.connect(**conn_params)
            print(f"Connected to Snowflake account: {self.account}")
            return True

        except Exception as e:
            print(f"Failed to connect to Snowflake: {str(e)}")
            raise

    def disconnect(self):
        """Close Snowflake connection."""
        if self.connection:
            try:
                self.connection.close()
                print("Disconnected from Snowflake")
            except Exception as e:
                print(f"Error disconnecting: {str(e)}")

    def get_last_checkpoint(self, log_type: str) -> Optional[str]:
        """
        Get last fetch timestamp from DynamoDB.

        Args:
            log_type: Type of log

        Returns:
            ISO timestamp or None
        """
        if not self.table:
            return None

        try:
            response = self.table.get_item(Key={'source': f'snowflake:{log_type}'})
            if 'Item' in response:
                return response['Item'].get('last_fetch_timestamp')
        except Exception as e:
            print(f"Error getting checkpoint: {str(e)}")

        return None

    def save_checkpoint(self, log_type: str, timestamp: str) -> None:
        """
        Save checkpoint timestamp to DynamoDB.

        Args:
            log_type: Type of log
            timestamp: ISO timestamp to save
        """
        if not self.table:
            return

        try:
            self.table.put_item(
                Item={
                    'source': f'snowflake:{log_type}',
                    'last_fetch_timestamp': timestamp,
                    'updated_at': datetime.now(timezone.utc).isoformat()
                }
            )
        except Exception as e:
            print(f"Error saving checkpoint: {str(e)}")

    def fetch_logs(
        self,
        log_type: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 10000
    ) -> List[Dict]:
        """
        Fetch logs from a specific ACCOUNT_USAGE view.

        Args:
            log_type: Type of log (key from LOG_VIEWS)
            start_time: Start timestamp (ISO format)
            end_time: End timestamp (ISO format)
            limit: Maximum rows to fetch

        Returns:
            List of log events
        """
        if log_type not in self.LOG_VIEWS:
            raise ValueError(f"Unknown log type: {log_type}")

        view_config = self.LOG_VIEWS[log_type]
        view_name = view_config['view']
        ts_field = view_config['timestamp_field']
        order_by = view_config['order_by']
        default_lookback = view_config['lookback_hours']

        # Default time range
        if not end_time:
            end_time = datetime.now(timezone.utc).isoformat()

        if not start_time:
            lookback = datetime.now(timezone.utc) - timedelta(hours=default_lookback)
            start_time = lookback.isoformat()

        # Build query
        query = f"""
        SELECT *
        FROM {view_name}
        WHERE {ts_field} >= '{start_time}'
          AND {ts_field} < '{end_time}'
        ORDER BY {order_by}
        LIMIT {limit}
        """

        events = []

        try:
            cursor = self.connection.cursor(DictCursor)
            cursor.execute(query)
            rows = cursor.fetchall()

            # Convert to JSON-serializable format
            for row in rows:
                event = {}
                for key, value in row.items():
                    if isinstance(value, datetime):
                        event[key] = value.isoformat()
                    elif isinstance(value, bytes):
                        event[key] = value.decode('utf-8', errors='replace')
                    elif hasattr(value, '__dict__'):
                        event[key] = str(value)
                    else:
                        event[key] = value
                events.append(event)

            cursor.close()
            print(f"Fetched {len(events)} {log_type} events")

        except Exception as e:
            print(f"Error fetching {log_type} logs: {str(e)}")
            raise

        return events

    def fetch_login_history(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict]:
        """Fetch login history events."""
        return self.fetch_logs('login_history', start_time, end_time)

    def fetch_query_history(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict]:
        """Fetch query history events."""
        return self.fetch_logs('query_history', start_time, end_time)

    def fetch_access_history(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict]:
        """Fetch access history events."""
        return self.fetch_logs('access_history', start_time, end_time)

    def fetch_sessions(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict]:
        """Fetch session events."""
        return self.fetch_logs('sessions', start_time, end_time)

    def fetch_grants_to_users(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict]:
        """Fetch user grants events."""
        return self.fetch_logs('grants_to_users', start_time, end_time)

    def fetch_grants_to_roles(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict]:
        """Fetch role grants events."""
        return self.fetch_logs('grants_to_roles', start_time, end_time)

    def fetch_warehouse_events(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict]:
        """Fetch warehouse events."""
        return self.fetch_logs('warehouse_events', start_time, end_time)

    def fetch_copy_history(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict]:
        """Fetch data copy history events."""
        return self.fetch_logs('copy_history', start_time, end_time)

    def fetch_data_transfer(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict]:
        """Fetch data transfer history events."""
        return self.fetch_logs('data_transfer', start_time, end_time)

    def write_to_s3(self, events: List[Dict], log_type: str, timestamp: datetime) -> Optional[str]:
        """
        Write events to S3 in partitioned structure.

        Args:
            events: List of log events
            log_type: Type of log for path
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

        s3_key = f"snowflake/{log_type}/raw/{year}/{month}/{day}/{hour}/events_{minute}.json"

        # Write as newline-delimited JSON
        data = '\n'.join([json.dumps(event, default=str) for event in events])

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

    def collect_log_type(self, log_type: str) -> Dict:
        """
        Collect logs of a specific type.

        Args:
            log_type: Type of log to collect

        Returns:
            Collection statistics
        """
        # Get last checkpoint
        last_checkpoint = self.get_last_checkpoint(log_type)

        if not last_checkpoint:
            # Use default lookback
            lookback_hours = self.LOG_VIEWS[log_type]['lookback_hours']
            last_checkpoint = (datetime.now(timezone.utc) - timedelta(hours=lookback_hours)).isoformat()

        print(f"Fetching Snowflake {log_type} since {last_checkpoint}")

        # Fetch logs
        now = datetime.now(timezone.utc)
        events = self.fetch_logs(log_type, start_time=last_checkpoint, end_time=now.isoformat())

        # Write to S3
        s3_key = None
        if events:
            s3_key = self.write_to_s3(events, log_type, now)

            # Update checkpoint to latest event timestamp
            view_config = self.LOG_VIEWS[log_type]
            ts_field = view_config['timestamp_field']

            latest_ts = None
            for event in events:
                event_ts = event.get(ts_field)
                if event_ts:
                    if latest_ts is None or event_ts > latest_ts:
                        latest_ts = event_ts

            if latest_ts:
                # Add small offset to avoid duplicates
                if isinstance(latest_ts, str):
                    self.save_checkpoint(log_type, latest_ts)
                else:
                    self.save_checkpoint(log_type, latest_ts.isoformat())
        else:
            self.save_checkpoint(log_type, now.isoformat())

        return {
            'log_type': log_type,
            'events_fetched': len(events),
            's3_key': s3_key
        }

    def collect(self, log_types: Optional[List[str]] = None) -> Dict:
        """
        Main collection logic - collects specified or all log types.

        Args:
            log_types: List of log types to collect (None = all)

        Returns:
            Dictionary with collection statistics
        """
        if log_types is None:
            log_types = ['login_history', 'query_history', 'grants_to_users', 'grants_to_roles']

        results = {
            'log_types': {},
            'total_events': 0
        }

        for log_type in log_types:
            try:
                result = self.collect_log_type(log_type)
                results['log_types'][log_type] = result
                results['total_events'] += result['events_fetched']
            except Exception as e:
                print(f"Error collecting {log_type}: {str(e)}")
                results['log_types'][log_type] = {'error': str(e)}

        return results


def lambda_handler(event, context):
    """
    AWS Lambda handler for Snowflake log collection.

    Environment Variables:
        SNOWFLAKE_SECRET_ID: AWS Secrets Manager secret ID containing Snowflake credentials
        S3_BUCKET: S3 bucket for log storage
        CHECKPOINT_TABLE: DynamoDB table for checkpoint tracking
        SNOWFLAKE_WAREHOUSE: Snowflake warehouse to use (default: COMPUTE_WH)
        SNOWFLAKE_ROLE: Snowflake role to use (default: ACCOUNTADMIN)
    """
    # Get configuration from environment
    secret_id = os.environ.get('SNOWFLAKE_SECRET_ID', "mantissa/snowflake/secret/id")
    s3_bucket = os.environ['S3_BUCKET']
    checkpoint_table = os.environ.get('CHECKPOINT_TABLE', 'mantissa-log-checkpoints')
    warehouse = os.environ.get('SNOWFLAKE_WAREHOUSE', 'COMPUTE_WH')
    role = os.environ.get('SNOWFLAKE_ROLE', 'ACCOUNTADMIN')

    # Retrieve credentials from Secrets Manager
    secrets_client = boto3.client('secretsmanager')
    try:
        secret_response = secrets_client.get_secret_value(SecretId=secret_id)
        secret_data = json.loads(secret_response['SecretString'])

        account = secret_data['account']
        user = secret_data['user']
        password = secret_data.get('password')
        private_key = secret_data.get('private_key')
        private_key_passphrase = secret_data.get('private_key_passphrase')

    except Exception as e:
        print(f"Error retrieving secret: {str(e)}")
        raise

    # Initialize collector
    collector = SnowflakeCollector(
        account=account,
        user=user,
        password=password,
        private_key=private_key,
        private_key_passphrase=private_key_passphrase,
        warehouse=warehouse,
        role=role,
        s3_bucket=s3_bucket,
        checkpoint_table=checkpoint_table
    )

    # Get log types from event or use defaults
    log_types = event.get('log_types')

    # Specific log type can be passed as single value
    if 'log_type' in event:
        log_types = [event['log_type']]

    try:
        # Connect to Snowflake
        collector.connect()

        # Collect logs
        result = collector.collect(log_types=log_types)

        return {
            'statusCode': 200,
            'body': json.dumps(result)
        }

    except Exception as e:
        print(f"Collection failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }

    finally:
        collector.disconnect()
