"""Identity test fixtures package."""

from .sample_events import (
    create_auth_success_event,
    create_auth_failure_event,
    create_mfa_challenge_event,
    create_mfa_success_event,
    create_mfa_failure_event,
    create_privilege_grant_event,
    create_session_start_event,
    create_logout_event,
    create_password_change_event,
)
from .attack_scenarios import (
    BruteForceScenario,
    PasswordSprayScenario,
    MFAFatigueScenario,
    ImpossibleTravelScenario,
    PrivilegeEscalationScenario,
    CredentialStuffingScenario,
)
from .sample_baselines import (
    create_office_worker_baseline,
    create_remote_worker_baseline,
    create_service_account_baseline,
    create_admin_user_baseline,
    create_executive_baseline,
)

__all__ = [
    # Sample events
    "create_auth_success_event",
    "create_auth_failure_event",
    "create_mfa_challenge_event",
    "create_mfa_success_event",
    "create_mfa_failure_event",
    "create_privilege_grant_event",
    "create_session_start_event",
    "create_logout_event",
    "create_password_change_event",
    # Attack scenarios
    "BruteForceScenario",
    "PasswordSprayScenario",
    "MFAFatigueScenario",
    "ImpossibleTravelScenario",
    "PrivilegeEscalationScenario",
    "CredentialStuffingScenario",
    # Sample baselines
    "create_office_worker_baseline",
    "create_remote_worker_baseline",
    "create_service_account_baseline",
    "create_admin_user_baseline",
    "create_executive_baseline",
]
