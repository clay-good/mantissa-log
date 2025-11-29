"""
Configuration for Self-Learning Detection Engineer.
"""

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class TuningConfig:
    """Configuration for detection tuning analysis."""

    # General settings
    enabled: bool = True
    analysis_window_days: int = 30
    min_alerts_for_analysis: int = 25

    # Confidence thresholds
    false_positive_rate_threshold: float = 0.70  # 70%+ from same source = recommend exclusion
    threshold_deviation_stddev: float = 3.0  # 3+ std deviations = recommend threshold change
    rule_overlap_threshold: float = 0.90  # 90%+ overlap = recommend consolidation
    zero_alert_warning_days: int = 30  # Days before warning about zero-alert rules

    # Output configuration
    create_jira_tickets: bool = True
    jira_project_key: str = ""
    jira_issue_type: str = "Task"
    jira_labels: List[str] = field(default_factory=lambda: [
        "detection-tuning",
        "auto-generated",
        "mantissa-log"
    ])

    # Feedback loop settings
    suppress_rejected_days: int = 90  # Days to suppress after rejection
    max_rejections_before_permanent: int = 3  # Permanently suppress after N rejections
    stale_ticket_days: int = 30  # Days before marking ticket as ignored

    # LLM settings (for generating recommendations)
    use_llm_for_analysis: bool = True
    llm_model: str = "claude-3-5-sonnet-20241022"
    max_tokens_per_analysis: int = 2000

    @classmethod
    def from_dict(cls, config_dict: Optional[Dict[str, Any]] = None) -> 'TuningConfig':
        """Create config from dictionary."""
        if not config_dict:
            return cls()

        return cls(
            enabled=config_dict.get('enabled', True),
            analysis_window_days=config_dict.get('analysis_window_days', 30),
            min_alerts_for_analysis=config_dict.get('min_alerts_for_analysis', 25),
            false_positive_rate_threshold=config_dict.get('false_positive_rate_threshold', 0.70),
            threshold_deviation_stddev=config_dict.get('threshold_deviation_stddev', 3.0),
            rule_overlap_threshold=config_dict.get('rule_overlap_threshold', 0.90),
            zero_alert_warning_days=config_dict.get('zero_alert_warning_days', 30),
            create_jira_tickets=config_dict.get('create_jira_tickets', True),
            jira_project_key=config_dict.get('jira_project_key', ''),
            jira_issue_type=config_dict.get('jira_issue_type', 'Task'),
            jira_labels=config_dict.get('jira_labels', [
                'detection-tuning', 'auto-generated', 'mantissa-log'
            ]),
            suppress_rejected_days=config_dict.get('suppress_rejected_days', 90),
            max_rejections_before_permanent=config_dict.get('max_rejections_before_permanent', 3),
            stale_ticket_days=config_dict.get('stale_ticket_days', 30),
            use_llm_for_analysis=config_dict.get('use_llm_for_analysis', True),
            llm_model=config_dict.get('llm_model', 'claude-3-5-sonnet-20241022'),
            max_tokens_per_analysis=config_dict.get('max_tokens_per_analysis', 2000),
        )

    @classmethod
    def from_environment(cls) -> 'TuningConfig':
        """Create config from environment variables."""
        return cls(
            enabled=os.environ.get('TUNING_ENABLED', 'true').lower() == 'true',
            analysis_window_days=int(os.environ.get('TUNING_WINDOW_DAYS', '30')),
            min_alerts_for_analysis=int(os.environ.get('TUNING_MIN_ALERTS', '25')),
            jira_project_key=os.environ.get('JIRA_PROJECT_KEY', ''),
            jira_issue_type=os.environ.get('JIRA_ISSUE_TYPE', 'Task'),
            use_llm_for_analysis=os.environ.get('TUNING_USE_LLM', 'true').lower() == 'true',
            llm_model=os.environ.get('TUNING_LLM_MODEL', 'claude-3-5-sonnet-20241022'),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'enabled': self.enabled,
            'analysis_window_days': self.analysis_window_days,
            'min_alerts_for_analysis': self.min_alerts_for_analysis,
            'false_positive_rate_threshold': self.false_positive_rate_threshold,
            'threshold_deviation_stddev': self.threshold_deviation_stddev,
            'rule_overlap_threshold': self.rule_overlap_threshold,
            'zero_alert_warning_days': self.zero_alert_warning_days,
            'create_jira_tickets': self.create_jira_tickets,
            'jira_project_key': self.jira_project_key,
            'jira_issue_type': self.jira_issue_type,
            'jira_labels': self.jira_labels,
            'suppress_rejected_days': self.suppress_rejected_days,
            'max_rejections_before_permanent': self.max_rejections_before_permanent,
            'stale_ticket_days': self.stale_ticket_days,
            'use_llm_for_analysis': self.use_llm_for_analysis,
            'llm_model': self.llm_model,
            'max_tokens_per_analysis': self.max_tokens_per_analysis,
        }
