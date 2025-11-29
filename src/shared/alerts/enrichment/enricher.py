"""
Alert Enricher

Main module for LLM-powered alert enrichment.
Coordinates behavioral analysis, LLM calls, and response formatting.
"""

import logging
from datetime import datetime
from typing import Dict, Any, Optional, List

from .config import EnrichmentConfig
from .prompts import EnrichmentPromptBuilder
from .behavioral import BehavioralAnalyzer

logger = logging.getLogger(__name__)


class AlertEnricher:
    """
    Enriches security alerts with LLM-powered contextual analysis.

    Provides:
    - 5W1H Summary (Who, What, When, Where, Why, How)
    - Behavioral Context (historical patterns)
    - Baseline Deviation Analysis
    - Detection Explainer
    - Recommended Actions
    """

    def __init__(
        self,
        config: Optional[EnrichmentConfig] = None,
        llm_provider=None,
        query_executor=None
    ):
        """
        Initialize alert enricher.

        Args:
            config: Enrichment configuration
            llm_provider: LLM provider instance (from provider_factory)
            query_executor: Query executor for behavioral analysis
        """
        self.config = config or EnrichmentConfig()
        self.llm_provider = llm_provider
        self.behavioral_analyzer = BehavioralAnalyzer(
            query_executor=query_executor,
            config={
                'baseline_window_days': self.config.baseline_window_days,
                'max_historical_events_per_query': self.config.max_historical_events_per_query,
            }
        )
        self.prompt_builder = EnrichmentPromptBuilder()

    def enrich_alert(
        self,
        alert_payload: Dict[str, Any],
        rule_info: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Enrich an alert with LLM-powered contextual analysis.

        Args:
            alert_payload: Original alert payload
            rule_info: Sigma rule metadata
            user_id: User ID for LLM provider selection

        Returns:
            Enriched alert payload with additional context
        """
        severity = alert_payload.get('severity', 'medium').lower()

        # Check if enrichment is enabled and applicable
        if not self.config.enabled:
            logger.debug("Enrichment disabled, returning original payload")
            return self._add_basic_enrichment(alert_payload)

        if not self.config.should_enrich_severity(severity):
            logger.debug(f"Severity {severity} not configured for enrichment")
            return self._add_basic_enrichment(alert_payload)

        try:
            # Get event data
            events = alert_payload.get('events', alert_payload.get('results', []))
            first_event = events[0] if isinstance(events, list) and events else events

            # Get behavioral context
            behavioral_context = {}
            baseline_stats = {}

            if self.config.include_behavioral_context or self.config.include_baseline_deviation:
                behavioral_context = self.behavioral_analyzer.get_behavioral_context(
                    alert_data=alert_payload,
                    event_data=first_event
                )

            if self.config.include_baseline_deviation:
                event_name = first_event.get('eventName', first_event.get('event_name'))
                user = self._extract_user(first_event)
                if event_name:
                    baseline_stats = self.behavioral_analyzer.get_baseline_stats(
                        event_name=event_name,
                        user=user
                    )

            # Build enrichment prompt
            include_components = {
                'five_w_one_h': self.config.include_five_w_one_h,
                'behavioral_context': self.config.include_behavioral_context,
                'baseline_deviation': self.config.include_baseline_deviation,
                'detection_explainer': self.config.include_detection_explainer,
                'recommended_actions': self.config.include_recommended_actions,
            }

            prompt = self.prompt_builder.build_enrichment_prompt(
                alert_data=alert_payload,
                rule_info=rule_info or {},
                behavioral_context=behavioral_context,
                baseline_stats=baseline_stats,
                include_components=include_components
            )

            # Call LLM for enrichment
            enrichment_response = self._call_llm(
                prompt=prompt,
                severity=severity,
                user_id=user_id
            )

            if enrichment_response:
                # Parse the response
                enrichment_sections = self.prompt_builder.parse_enrichment_response(
                    enrichment_response
                )

                # Build enriched payload
                enriched_payload = self._build_enriched_payload(
                    original_payload=alert_payload,
                    enrichment_sections=enrichment_sections,
                    behavioral_context=behavioral_context,
                    baseline_stats=baseline_stats
                )

                return enriched_payload

            else:
                logger.warning("LLM enrichment returned empty response")
                if self.config.fallback_on_error:
                    return self._add_basic_enrichment(alert_payload)
                raise Exception("LLM enrichment failed")

        except Exception as e:
            logger.error(f"Error during alert enrichment: {e}")
            if self.config.fallback_on_error:
                return self._add_basic_enrichment(alert_payload)
            raise

    def _call_llm(
        self,
        prompt: str,
        severity: str,
        user_id: Optional[str] = None
    ) -> Optional[str]:
        """
        Call the LLM for enrichment.

        Args:
            prompt: Enrichment prompt
            severity: Alert severity (for model selection)
            user_id: User ID for provider selection

        Returns:
            LLM response text or None
        """
        if not self.llm_provider:
            logger.warning("No LLM provider configured for enrichment")
            return None

        try:
            # Build messages
            messages = [
                {
                    'role': 'user',
                    'content': prompt
                }
            ]

            # Get model for this severity
            model = self.config.get_model_for_severity(severity)

            # Call LLM
            response = self.llm_provider.generate(
                messages=messages,
                system_prompt=self.prompt_builder.SYSTEM_PROMPT,
                max_tokens=self.config.max_tokens_per_enrichment
            )

            return response

        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            return None

    def _build_enriched_payload(
        self,
        original_payload: Dict[str, Any],
        enrichment_sections: Dict[str, str],
        behavioral_context: Dict[str, Any],
        baseline_stats: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Build the final enriched alert payload.

        Args:
            original_payload: Original alert data
            enrichment_sections: Parsed LLM enrichment sections
            behavioral_context: Behavioral analysis results
            baseline_stats: Baseline statistics

        Returns:
            Enriched alert payload
        """
        enriched = original_payload.copy()

        # Add enrichment metadata
        enriched['enrichment'] = {
            'enriched_at': datetime.utcnow().isoformat(),
            'enrichment_version': '1.0',
            'llm_model': self.config.llm_model,
        }

        # Add structured enrichment sections
        if enrichment_sections.get('five_w_one_h'):
            enriched['enrichment']['five_w_one_h'] = enrichment_sections['five_w_one_h']

        if enrichment_sections.get('behavioral_context'):
            enriched['enrichment']['behavioral_analysis'] = enrichment_sections['behavioral_context']

        if enrichment_sections.get('baseline_comparison'):
            enriched['enrichment']['baseline_comparison'] = enrichment_sections['baseline_comparison']

        if enrichment_sections.get('detection_details'):
            enriched['enrichment']['detection_details'] = enrichment_sections['detection_details']

        if enrichment_sections.get('recommended_actions'):
            enriched['enrichment']['recommended_actions'] = enrichment_sections['recommended_actions']

        # Add raw behavioral data for reference
        if behavioral_context:
            enriched['enrichment']['behavioral_data'] = behavioral_context

        if baseline_stats:
            enriched['enrichment']['baseline_data'] = baseline_stats

        # Generate formatted description for integrations
        enriched['enriched_description'] = self.prompt_builder.format_enriched_alert(
            original_payload=original_payload,
            enrichment_sections=enrichment_sections,
            severity=original_payload.get('severity', 'medium')
        )

        return enriched

    def _add_basic_enrichment(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Add basic enrichment without LLM (fallback).

        Args:
            payload: Original alert payload

        Returns:
            Payload with basic enrichment
        """
        enriched = payload.copy()

        enriched['enrichment'] = {
            'enriched_at': datetime.utcnow().isoformat(),
            'enrichment_version': '1.0',
            'enrichment_type': 'basic',
            'note': 'LLM enrichment not applied (disabled or unavailable)'
        }

        # Add basic metadata extraction
        events = payload.get('events', payload.get('results', []))
        if events:
            first_event = events[0] if isinstance(events, list) else events

            # Extract basic 5W1H
            enriched['enrichment']['who'] = self._extract_user(first_event) or 'Unknown'
            enriched['enrichment']['what'] = first_event.get('eventName', first_event.get('event_name', 'Unknown'))
            enriched['enrichment']['when'] = first_event.get('eventTime', payload.get('timestamp', 'Unknown'))
            enriched['enrichment']['where'] = first_event.get('awsRegion', first_event.get('sourceIPAddress', 'Unknown'))

            # Check if IP is internal
            source_ip = first_event.get('sourceIPAddress', first_event.get('source_ip'))
            if source_ip:
                enriched['enrichment']['source_ip'] = source_ip
                enriched['enrichment']['is_internal_ip'] = self.behavioral_analyzer._is_internal_ip(source_ip)

        return enriched

    def _extract_user(self, event_data: Dict[str, Any]) -> Optional[str]:
        """Extract user identifier from event data."""
        if 'userIdentity' in event_data:
            ui = event_data['userIdentity']
            return (
                ui.get('userName') or
                ui.get('principalId') or
                (ui.get('arn', '').split('/')[-1] if ui.get('arn') else None)
            )
        return event_data.get('user') or event_data.get('userName')


def create_enricher_from_config(
    config_dict: Optional[Dict[str, Any]] = None,
    user_id: Optional[str] = None,
    query_executor=None
) -> AlertEnricher:
    """
    Factory function to create an AlertEnricher with proper configuration.

    Args:
        config_dict: Enrichment configuration dictionary
        user_id: User ID for LLM provider selection
        query_executor: Query executor for behavioral analysis

    Returns:
        Configured AlertEnricher instance
    """
    # Build config
    config = EnrichmentConfig.from_dict(config_dict) if config_dict else EnrichmentConfig()

    # Get LLM provider
    llm_provider = None
    if config.enabled:
        try:
            from ...llm.provider_factory import get_provider_factory
            factory = get_provider_factory()
            llm_provider = factory.get_provider_for_use_case(
                user_id=user_id or 'system',
                use_case='alert_enrichment',
                fallback_to_bedrock=True
            )
        except Exception as e:
            logger.warning(f"Could not initialize LLM provider for enrichment: {e}")

    return AlertEnricher(
        config=config,
        llm_provider=llm_provider,
        query_executor=query_executor
    )
