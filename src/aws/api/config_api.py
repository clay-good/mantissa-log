"""
Config API for Mantissa Log

Returns platform configuration including enabled features/modules.
This endpoint allows the frontend to adapt its UI based on deployed modules.
"""

import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, Any

# Add shared modules to path
sys.path.append(str(Path(__file__).parent.parent.parent / 'shared'))

from auth.cors import get_cors_headers, cors_preflight_response

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Feature flags from environment variables
ENABLE_SIEM = os.environ.get('ENABLE_SIEM', 'true').lower() == 'true'
ENABLE_APM = os.environ.get('ENABLE_APM', 'false').lower() == 'true'
ENABLE_SOAR = os.environ.get('ENABLE_SOAR', 'false').lower() == 'true'

# Version from environment or default
VERSION = os.environ.get('MANTISSA_VERSION', '1.0.0')


class ConfigAPI:
    """API handler for platform configuration"""

    def lambda_handler(self, event: Dict[str, Any], context: Any) -> Dict[str, Any]:
        """Main Lambda handler for config endpoint"""

        http_method = event.get('httpMethod')

        # Handle CORS preflight
        if http_method == 'OPTIONS':
            return cors_preflight_response(event)

        try:
            if http_method == 'GET':
                return self.get_config(event)
            else:
                return {
                    'statusCode': 405,
                    'body': json.dumps({'error': 'Method not allowed'}),
                    'headers': {'Content-Type': 'application/json', **get_cors_headers(event)}
                }

        except Exception as e:
            logger.error(f"Error in config API: {e}", exc_info=True)
            return self._error_response(event, 'Internal server error', 500)

    def get_config(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Get platform configuration including enabled features"""

        config = {
            'features': {
                'siem': ENABLE_SIEM,
                'apm': ENABLE_APM,
                'soar': ENABLE_SOAR,
            },
            'version': VERSION,
            'modules': {
                'siem': {
                    'enabled': ENABLE_SIEM,
                    'name': 'SIEM',
                    'description': 'Log aggregation, detection, and alerting',
                    'components': [
                        'Log Collection',
                        'NL Queries',
                        'Sigma Detection',
                        'Alert Routing',
                        'ITDR'
                    ]
                },
                'apm': {
                    'enabled': ENABLE_APM,
                    'name': 'Observability',
                    'description': 'Distributed tracing and metrics',
                    'components': [
                        'OTLP Receiver',
                        'Trace Storage',
                        'Metrics Storage',
                        'Service Map',
                        'Trace Viewer',
                        'APM Detection'
                    ]
                },
                'soar': {
                    'enabled': ENABLE_SOAR,
                    'name': 'SOAR',
                    'description': 'Automated response and playbooks',
                    'components': [
                        'Playbook Management',
                        'IR Plan Parser',
                        'Code Generator',
                        'Execution Engine',
                        'Approval Workflow',
                        'Alert Actions'
                    ]
                }
            },
            'upsell': self._get_upsell_info()
        }

        return {
            'statusCode': 200,
            'body': json.dumps(config),
            'headers': {'Content-Type': 'application/json', **get_cors_headers(event)}
        }

    def _get_upsell_info(self) -> Dict[str, Any]:
        """Get information about disabled modules for upsell UI"""

        upsell = {}

        if not ENABLE_APM:
            upsell['apm'] = {
                'title': 'Enable Observability',
                'description': 'Add metrics, traces, and service maps to your platform',
                'benefits': [
                    'Distributed tracing with OpenTelemetry',
                    'Service dependency visualization',
                    'Latency and error detection',
                    'NL queries for performance issues'
                ],
                'docs_url': '/docs/DEPLOYMENT_GUIDE.md#mode-2-siem--observability-deployment'
            }

        if not ENABLE_SOAR:
            upsell['soar'] = {
                'title': 'Enable Automated Response',
                'description': 'Add playbooks and quick actions to your alerts',
                'benefits': [
                    'Convert IR plans to executable playbooks',
                    'One-click actions: isolate host, disable user, block IP',
                    'Approval workflow for dangerous actions',
                    'Full audit trail of automated actions'
                ],
                'docs_url': '/docs/DEPLOYMENT_GUIDE.md#mode-3-full-platform-deployment'
            }

        return upsell

    def _error_response(self, event: Dict[str, Any], message: str, status_code: int = 400) -> Dict[str, Any]:
        """Standard error response with secure CORS headers"""
        return {
            'statusCode': status_code,
            'body': json.dumps({'error': message}),
            'headers': {'Content-Type': 'application/json', **get_cors_headers(event)}
        }


# Lambda handler
api = ConfigAPI()


def lambda_handler(event, context):
    """Lambda entry point"""
    return api.lambda_handler(event, context)
