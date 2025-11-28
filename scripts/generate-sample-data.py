#!/usr/bin/env python3
"""
Mantissa Log - Sample Data Generator

Generates realistic test data for development and testing:
- CloudTrail events
- VPC Flow Logs
- GuardDuty findings
"""

import json
import random
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any


class SampleDataGenerator:
    def __init__(self, output_dir: str = 'sample-data'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Sample data
        self.users = ['alice', 'bob', 'charlie', 'admin', 'service-account']
        self.ips = ['203.0.113.42', '198.51.100.5', '192.0.2.10', '172.16.0.50']
        self.suspicious_ips = ['198.51.100.99', '203.0.113.254']

        self.event_names = [
            'ConsoleLogin', 'PutBucketPolicy', 'CreateAccessKey',
            'AuthorizeSecurityGroupIngress', 'AssumeRole', 'PutObject',
            'GetObject', 'CreateUser', 'AttachUserPolicy', 'DeleteTrail'
        ]

    def generate_cloudtrail(
        self,
        count: int = 100,
        start_time: datetime = None,
        include_suspicious: bool = True
    ) -> List[Dict[str, Any]]:
        """Generate CloudTrail events"""
        if not start_time:
            start_time = datetime.utcnow() - timedelta(hours=24)

        events = []

        for i in range(count):
            # Determine if this should be suspicious
            is_suspicious = include_suspicious and random.random() < 0.1

            user = random.choice(self.users)
            ip = random.choice(self.suspicious_ips if is_suspicious else self.ips)
            event_name = random.choice(self.event_names)

            # Generate timestamp
            event_time = start_time + timedelta(seconds=i * (86400 / count))

            # Base event
            event = {
                'eventVersion': '1.08',
                'userIdentity': {
                    'type': 'IAMUser',
                    'principalId': f'AIDAI23HXK2X{user.upper()}',
                    'arn': f'arn:aws:iam::123456789012:user/{user}',
                    'accountId': '123456789012',
                    'userName': user
                },
                'eventTime': event_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
                'eventSource': self._get_event_source(event_name),
                'eventName': event_name,
                'awsRegion': 'us-east-1',
                'sourceIPAddress': ip,
                'userAgent': self._get_user_agent(),
                'requestParameters': self._get_request_parameters(event_name),
                'responseElements': self._get_response_elements(event_name, is_suspicious),
                'eventID': f'{i:08d}-{random.randint(1000, 9999)}',
                'eventType': 'AwsApiCall',
                'recipientAccountId': '123456789012'
            }

            # Add error for suspicious login attempts
            if event_name == 'ConsoleLogin' and is_suspicious:
                event['errorCode'] = 'Failed authentication'
                event['errorMessage'] = 'Incorrect username or password'
                event['additionalEventData'] = {
                    'LoginTo': 'https://console.aws.amazon.com',
                    'MFAUsed': 'No'
                }
            elif event_name == 'ConsoleLogin':
                event['additionalEventData'] = {
                    'LoginTo': 'https://console.aws.amazon.com',
                    'MFAUsed': random.choice(['Yes', 'No'])
                }

            events.append(event)

        return events

    def generate_vpc_flow_logs(
        self,
        count: int = 100,
        include_suspicious: bool = True
    ) -> List[str]:
        """Generate VPC Flow Log records"""
        records = []

        for i in range(count):
            is_suspicious = include_suspicious and random.random() < 0.15

            # SSH brute force pattern
            if is_suspicious:
                src_addr = random.choice(self.suspicious_ips)
                dst_addr = '10.0.1.5'
                dst_port = 22
                action = 'REJECT'
                packets = random.randint(1, 5)
                bytes_count = packets * 64
            else:
                src_addr = f'10.0.{random.randint(1, 10)}.{random.randint(1, 254)}'
                dst_addr = f'172.217.{random.randint(1, 254)}.{random.randint(1, 254)}'
                dst_port = random.choice([80, 443, 53, 3306, 5432])
                action = 'ACCEPT'
                packets = random.randint(10, 100)
                bytes_count = packets * random.randint(500, 1500)

            src_port = random.randint(49152, 65535)
            protocol = 6  # TCP

            start_time = int((datetime.utcnow() - timedelta(minutes=i)).timestamp())
            end_time = start_time + random.randint(1, 60)

            record = (
                f'2 123456789012 eni-{random.randint(1000, 9999)}abcd '
                f'{src_addr} {dst_addr} {src_port} {dst_port} {protocol} '
                f'{packets} {bytes_count} {start_time} {end_time} {action} OK'
            )

            records.append(record)

        return records

    def generate_guardduty_findings(
        self,
        count: int = 10
    ) -> List[Dict[str, Any]]:
        """Generate GuardDuty findings"""
        findings = []

        finding_types = [
            'UnauthorizedAccess:EC2/SSHBruteForce',
            'Recon:EC2/PortProbeUnprotectedPort',
            'CryptoCurrency:EC2/BitcoinTool.B',
            'Backdoor:EC2/C&CActivity.B',
            'UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B'
        ]

        for i in range(count):
            finding_type = random.choice(finding_types)
            severity = random.uniform(2.0, 9.0)

            finding = {
                'schemaVersion': '2.0',
                'accountId': '123456789012',
                'region': 'us-east-1',
                'partition': 'aws',
                'id': f'{random.randint(100000, 999999)}',
                'arn': f'arn:aws:guardduty:us-east-1:123456789012:detector/abc123/finding/{i}',
                'type': finding_type,
                'resource': self._get_guardduty_resource(finding_type),
                'service': {
                    'serviceName': 'guardduty',
                    'detectorId': 'abc123def456',
                    'action': self._get_guardduty_action(finding_type),
                    'eventFirstSeen': (datetime.utcnow() - timedelta(hours=2)).isoformat() + 'Z',
                    'eventLastSeen': (datetime.utcnow() - timedelta(minutes=5)).isoformat() + 'Z',
                    'count': random.randint(1, 50)
                },
                'severity': round(severity, 1),
                'title': self._get_guardduty_title(finding_type),
                'description': f'Sample finding of type {finding_type}',
                'createdAt': (datetime.utcnow() - timedelta(hours=3)).isoformat() + 'Z',
                'updatedAt': datetime.utcnow().isoformat() + 'Z'
            }

            findings.append(finding)

        return findings

    def _get_event_source(self, event_name: str) -> str:
        """Get event source for event name"""
        sources = {
            'ConsoleLogin': 'signin.amazonaws.com',
            'PutBucketPolicy': 's3.amazonaws.com',
            'PutObject': 's3.amazonaws.com',
            'GetObject': 's3.amazonaws.com',
            'CreateAccessKey': 'iam.amazonaws.com',
            'CreateUser': 'iam.amazonaws.com',
            'AttachUserPolicy': 'iam.amazonaws.com',
            'AuthorizeSecurityGroupIngress': 'ec2.amazonaws.com',
            'AssumeRole': 'sts.amazonaws.com',
            'DeleteTrail': 'cloudtrail.amazonaws.com'
        }
        return sources.get(event_name, 'unknown.amazonaws.com')

    def _get_user_agent(self) -> str:
        """Get random user agent"""
        agents = [
            'aws-cli/2.13.0',
            'Mozilla/5.0',
            'Boto3/1.28.0',
            'aws-sdk-java/2.20.0'
        ]
        return random.choice(agents)

    def _get_request_parameters(self, event_name: str) -> Dict:
        """Get request parameters for event"""
        if event_name == 'PutBucketPolicy':
            return {
                'bucketName': 'my-test-bucket',
                'bucketPolicy': {
                    'Statement': [{'Effect': 'Allow', 'Principal': '*'}]
                }
            }
        return None

    def _get_response_elements(self, event_name: str, is_error: bool) -> Dict:
        """Get response elements for event"""
        if event_name == 'ConsoleLogin':
            return {
                'ConsoleLogin': 'Failure' if is_error else 'Success'
            }
        return None

    def _get_guardduty_resource(self, finding_type: str) -> Dict:
        """Get resource for GuardDuty finding"""
        return {
            'resourceType': 'Instance',
            'instanceDetails': {
                'instanceId': f'i-{random.randint(100000, 999999)}',
                'instanceType': 't2.micro',
                'launchTime': '2024-11-27T10:00:00Z',
                'networkInterfaces': [{
                    'privateIpAddress': f'10.0.1.{random.randint(1, 254)}',
                    'publicIp': random.choice(self.ips)
                }]
            }
        }

    def _get_guardduty_action(self, finding_type: str) -> Dict:
        """Get action for GuardDuty finding"""
        return {
            'actionType': 'NETWORK_CONNECTION',
            'networkConnectionAction': {
                'connectionDirection': 'INBOUND',
                'remoteIpDetails': {
                    'ipAddressV4': random.choice(self.suspicious_ips)
                },
                'localPortDetails': {
                    'port': 22 if 'SSH' in finding_type else 80
                }
            }
        }

    def _get_guardduty_title(self, finding_type: str) -> str:
        """Get title for GuardDuty finding"""
        titles = {
            'UnauthorizedAccess:EC2/SSHBruteForce': 'SSH brute force attack detected',
            'Recon:EC2/PortProbeUnprotectedPort': 'Port probe detected',
            'CryptoCurrency:EC2/BitcoinTool.B': 'Cryptocurrency mining detected',
            'Backdoor:EC2/C&CActivity.B': 'Command and control activity detected',
            'UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B': 'Suspicious console login'
        }
        return titles.get(finding_type, 'Security finding')

    def save_to_files(self, data_type: str, data: List, format: str = 'json'):
        """Save generated data to files"""
        output_path = self.output_dir / data_type
        output_path.mkdir(parents=True, exist_ok=True)

        if format == 'json':
            for i, item in enumerate(data):
                file_path = output_path / f'{data_type}_{i:04d}.json'
                with open(file_path, 'w') as f:
                    json.dump(item, f, indent=2)
        elif format == 'text':
            file_path = output_path / f'{data_type}.txt'
            with open(file_path, 'w') as f:
                f.write('\n'.join(data))

        print(f'Saved {len(data)} {data_type} records to {output_path}')


def main():
    parser = argparse.ArgumentParser(description='Generate sample data for Mantissa Log')
    parser.add_argument('--cloudtrail', type=int, help='Number of CloudTrail events')
    parser.add_argument('--vpc-flow', type=int, help='Number of VPC Flow Log records')
    parser.add_argument('--guardduty', type=int, help='Number of GuardDuty findings')
    parser.add_argument('--output-dir', default='sample-data', help='Output directory')
    parser.add_argument('--no-suspicious', action='store_true',
                        help='Do not include suspicious activity')

    args = parser.parse_args()

    generator = SampleDataGenerator(args.output_dir)

    if args.cloudtrail:
        print(f'Generating {args.cloudtrail} CloudTrail events...')
        events = generator.generate_cloudtrail(
            count=args.cloudtrail,
            include_suspicious=not args.no_suspicious
        )
        generator.save_to_files('cloudtrail', events, 'json')

    if args.vpc_flow:
        print(f'Generating {args.vpc_flow} VPC Flow Log records...')
        records = generator.generate_vpc_flow_logs(
            count=args.vpc_flow,
            include_suspicious=not args.no_suspicious
        )
        generator.save_to_files('vpc_flow', records, 'text')

    if args.guardduty:
        print(f'Generating {args.guardduty} GuardDuty findings...')
        findings = generator.generate_guardduty_findings(count=args.guardduty)
        generator.save_to_files('guardduty', findings, 'json')

    if not any([args.cloudtrail, args.vpc_flow, args.guardduty]):
        print('No data type specified. Use --cloudtrail, --vpc-flow, or --guardduty')
        print('Example: python generate-sample-data.py --cloudtrail 100 --vpc-flow 200')

if __name__ == '__main__':
    main()
