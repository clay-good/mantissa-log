"""MITRE ATT&CK coverage analysis for detection rules.

Maps detection rules to the MITRE ATT&CK framework to identify:
- Techniques covered by current detection rules
- Gaps in detection coverage
- Recommendations for new rules to cover uncovered techniques
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class Tactic(Enum):
    """MITRE ATT&CK Tactics (Enterprise)."""

    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


# MITRE ATT&CK Enterprise Techniques (v14, subset of high-priority techniques)
# Format: technique_id -> (name, tactics, sub_techniques)
MITRE_TECHNIQUES: Dict[str, Tuple[str, List[Tactic], List[str]]] = {
    # Initial Access
    "T1078": ("Valid Accounts", [Tactic.INITIAL_ACCESS, Tactic.PERSISTENCE, Tactic.PRIVILEGE_ESCALATION, Tactic.DEFENSE_EVASION],
              ["T1078.001", "T1078.002", "T1078.003", "T1078.004"]),
    "T1566": ("Phishing", [Tactic.INITIAL_ACCESS], ["T1566.001", "T1566.002", "T1566.003"]),
    "T1190": ("Exploit Public-Facing Application", [Tactic.INITIAL_ACCESS], []),
    "T1133": ("External Remote Services", [Tactic.INITIAL_ACCESS, Tactic.PERSISTENCE], []),
    "T1199": ("Trusted Relationship", [Tactic.INITIAL_ACCESS], []),
    "T1195": ("Supply Chain Compromise", [Tactic.INITIAL_ACCESS], ["T1195.001", "T1195.002", "T1195.003"]),

    # Execution
    "T1059": ("Command and Scripting Interpreter", [Tactic.EXECUTION],
              ["T1059.001", "T1059.002", "T1059.003", "T1059.004", "T1059.005", "T1059.006", "T1059.007", "T1059.008", "T1059.009"]),
    "T1204": ("User Execution", [Tactic.EXECUTION], ["T1204.001", "T1204.002", "T1204.003"]),
    "T1047": ("Windows Management Instrumentation", [Tactic.EXECUTION], []),
    "T1053": ("Scheduled Task/Job", [Tactic.EXECUTION, Tactic.PERSISTENCE, Tactic.PRIVILEGE_ESCALATION],
              ["T1053.002", "T1053.003", "T1053.005", "T1053.006", "T1053.007"]),

    # Persistence
    "T1098": ("Account Manipulation", [Tactic.PERSISTENCE, Tactic.PRIVILEGE_ESCALATION],
              ["T1098.001", "T1098.002", "T1098.003", "T1098.004", "T1098.005"]),
    "T1136": ("Create Account", [Tactic.PERSISTENCE], ["T1136.001", "T1136.002", "T1136.003"]),
    "T1543": ("Create or Modify System Process", [Tactic.PERSISTENCE, Tactic.PRIVILEGE_ESCALATION],
              ["T1543.001", "T1543.002", "T1543.003", "T1543.004"]),
    "T1546": ("Event Triggered Execution", [Tactic.PERSISTENCE, Tactic.PRIVILEGE_ESCALATION],
              ["T1546.001", "T1546.002", "T1546.003", "T1546.004", "T1546.005", "T1546.008", "T1546.010", "T1546.011", "T1546.012", "T1546.013", "T1546.015"]),
    "T1547": ("Boot or Logon Autostart Execution", [Tactic.PERSISTENCE, Tactic.PRIVILEGE_ESCALATION],
              ["T1547.001", "T1547.002", "T1547.003", "T1547.004", "T1547.005", "T1547.006", "T1547.008", "T1547.009", "T1547.010", "T1547.012", "T1547.014", "T1547.015"]),

    # Privilege Escalation
    "T1068": ("Exploitation for Privilege Escalation", [Tactic.PRIVILEGE_ESCALATION], []),
    "T1548": ("Abuse Elevation Control Mechanism", [Tactic.PRIVILEGE_ESCALATION, Tactic.DEFENSE_EVASION],
              ["T1548.001", "T1548.002", "T1548.003", "T1548.004"]),
    "T1134": ("Access Token Manipulation", [Tactic.PRIVILEGE_ESCALATION, Tactic.DEFENSE_EVASION],
              ["T1134.001", "T1134.002", "T1134.003", "T1134.004", "T1134.005"]),

    # Defense Evasion
    "T1562": ("Impair Defenses", [Tactic.DEFENSE_EVASION],
              ["T1562.001", "T1562.002", "T1562.003", "T1562.004", "T1562.006", "T1562.007", "T1562.008", "T1562.009", "T1562.010"]),
    "T1070": ("Indicator Removal", [Tactic.DEFENSE_EVASION],
              ["T1070.001", "T1070.002", "T1070.003", "T1070.004", "T1070.005", "T1070.006", "T1070.007", "T1070.008", "T1070.009"]),
    "T1027": ("Obfuscated Files or Information", [Tactic.DEFENSE_EVASION],
              ["T1027.001", "T1027.002", "T1027.003", "T1027.004", "T1027.005", "T1027.006", "T1027.007", "T1027.008", "T1027.009", "T1027.010", "T1027.011"]),
    "T1036": ("Masquerading", [Tactic.DEFENSE_EVASION],
              ["T1036.001", "T1036.002", "T1036.003", "T1036.004", "T1036.005", "T1036.006", "T1036.007", "T1036.008"]),
    "T1218": ("System Binary Proxy Execution", [Tactic.DEFENSE_EVASION],
              ["T1218.001", "T1218.002", "T1218.003", "T1218.004", "T1218.005", "T1218.007", "T1218.008", "T1218.009", "T1218.010", "T1218.011", "T1218.012", "T1218.013", "T1218.014"]),
    "T1112": ("Modify Registry", [Tactic.DEFENSE_EVASION], []),
    "T1550": ("Use Alternate Authentication Material", [Tactic.DEFENSE_EVASION, Tactic.LATERAL_MOVEMENT],
              ["T1550.001", "T1550.002", "T1550.003", "T1550.004"]),

    # Credential Access
    "T1110": ("Brute Force", [Tactic.CREDENTIAL_ACCESS],
              ["T1110.001", "T1110.002", "T1110.003", "T1110.004"]),
    "T1003": ("OS Credential Dumping", [Tactic.CREDENTIAL_ACCESS],
              ["T1003.001", "T1003.002", "T1003.003", "T1003.004", "T1003.005", "T1003.006", "T1003.007", "T1003.008"]),
    "T1555": ("Credentials from Password Stores", [Tactic.CREDENTIAL_ACCESS],
              ["T1555.001", "T1555.002", "T1555.003", "T1555.004", "T1555.005"]),
    "T1552": ("Unsecured Credentials", [Tactic.CREDENTIAL_ACCESS],
              ["T1552.001", "T1552.002", "T1552.003", "T1552.004", "T1552.005", "T1552.006", "T1552.007", "T1552.008"]),
    "T1558": ("Steal or Forge Kerberos Tickets", [Tactic.CREDENTIAL_ACCESS],
              ["T1558.001", "T1558.002", "T1558.003", "T1558.004"]),
    "T1606": ("Forge Web Credentials", [Tactic.CREDENTIAL_ACCESS], ["T1606.001", "T1606.002"]),

    # Discovery
    "T1087": ("Account Discovery", [Tactic.DISCOVERY], ["T1087.001", "T1087.002", "T1087.003", "T1087.004"]),
    "T1083": ("File and Directory Discovery", [Tactic.DISCOVERY], []),
    "T1057": ("Process Discovery", [Tactic.DISCOVERY], []),
    "T1082": ("System Information Discovery", [Tactic.DISCOVERY], []),
    "T1016": ("System Network Configuration Discovery", [Tactic.DISCOVERY], ["T1016.001"]),
    "T1049": ("System Network Connections Discovery", [Tactic.DISCOVERY], []),
    "T1018": ("Remote System Discovery", [Tactic.DISCOVERY], []),
    "T1069": ("Permission Groups Discovery", [Tactic.DISCOVERY], ["T1069.001", "T1069.002", "T1069.003"]),
    "T1580": ("Cloud Infrastructure Discovery", [Tactic.DISCOVERY], []),
    "T1526": ("Cloud Service Discovery", [Tactic.DISCOVERY], []),

    # Lateral Movement
    "T1021": ("Remote Services", [Tactic.LATERAL_MOVEMENT],
              ["T1021.001", "T1021.002", "T1021.003", "T1021.004", "T1021.005", "T1021.006", "T1021.007"]),
    "T1091": ("Replication Through Removable Media", [Tactic.LATERAL_MOVEMENT, Tactic.INITIAL_ACCESS], []),
    "T1072": ("Software Deployment Tools", [Tactic.LATERAL_MOVEMENT, Tactic.EXECUTION], []),
    "T1570": ("Lateral Tool Transfer", [Tactic.LATERAL_MOVEMENT], []),

    # Collection
    "T1530": ("Data from Cloud Storage", [Tactic.COLLECTION], []),
    "T1213": ("Data from Information Repositories", [Tactic.COLLECTION], ["T1213.001", "T1213.002", "T1213.003"]),
    "T1005": ("Data from Local System", [Tactic.COLLECTION], []),
    "T1039": ("Data from Network Shared Drive", [Tactic.COLLECTION], []),
    "T1114": ("Email Collection", [Tactic.COLLECTION], ["T1114.001", "T1114.002", "T1114.003"]),
    "T1119": ("Automated Collection", [Tactic.COLLECTION], []),

    # Command and Control
    "T1071": ("Application Layer Protocol", [Tactic.COMMAND_AND_CONTROL],
              ["T1071.001", "T1071.002", "T1071.003", "T1071.004"]),
    "T1105": ("Ingress Tool Transfer", [Tactic.COMMAND_AND_CONTROL], []),
    "T1571": ("Non-Standard Port", [Tactic.COMMAND_AND_CONTROL], []),
    "T1572": ("Protocol Tunneling", [Tactic.COMMAND_AND_CONTROL], []),
    "T1090": ("Proxy", [Tactic.COMMAND_AND_CONTROL], ["T1090.001", "T1090.002", "T1090.003", "T1090.004"]),
    "T1219": ("Remote Access Software", [Tactic.COMMAND_AND_CONTROL], []),
    "T1568": ("Dynamic Resolution", [Tactic.COMMAND_AND_CONTROL], ["T1568.001", "T1568.002", "T1568.003"]),

    # Exfiltration
    "T1567": ("Exfiltration Over Web Service", [Tactic.EXFILTRATION], ["T1567.001", "T1567.002", "T1567.003", "T1567.004"]),
    "T1048": ("Exfiltration Over Alternative Protocol", [Tactic.EXFILTRATION], ["T1048.001", "T1048.002", "T1048.003"]),
    "T1041": ("Exfiltration Over C2 Channel", [Tactic.EXFILTRATION], []),
    "T1537": ("Transfer Data to Cloud Account", [Tactic.EXFILTRATION], []),

    # Impact
    "T1485": ("Data Destruction", [Tactic.IMPACT], []),
    "T1486": ("Data Encrypted for Impact", [Tactic.IMPACT], []),
    "T1490": ("Inhibit System Recovery", [Tactic.IMPACT], []),
    "T1498": ("Network Denial of Service", [Tactic.IMPACT], ["T1498.001", "T1498.002"]),
    "T1499": ("Endpoint Denial of Service", [Tactic.IMPACT], ["T1499.001", "T1499.002", "T1499.003", "T1499.004"]),
    "T1489": ("Service Stop", [Tactic.IMPACT], []),
    "T1531": ("Account Access Removal", [Tactic.IMPACT], []),
    "T1565": ("Data Manipulation", [Tactic.IMPACT], ["T1565.001", "T1565.002", "T1565.003"]),
}

# High-priority techniques that should be covered for cloud environments
CLOUD_PRIORITY_TECHNIQUES = {
    "T1078": "Valid Accounts (cloud credentials)",
    "T1098": "Account Manipulation (IAM changes)",
    "T1136": "Create Account (new IAM users/roles)",
    "T1562": "Impair Defenses (disable logging/monitoring)",
    "T1070": "Indicator Removal (log deletion)",
    "T1530": "Data from Cloud Storage (S3/GCS/Blob access)",
    "T1537": "Transfer Data to Cloud Account",
    "T1580": "Cloud Infrastructure Discovery",
    "T1526": "Cloud Service Discovery",
    "T1110": "Brute Force (password spray)",
    "T1606": "Forge Web Credentials (OAuth/SAML)",
    "T1552": "Unsecured Credentials (secrets in code/env)",
}


@dataclass
class TechniqueMapping:
    """Mapping of a rule to MITRE ATT&CK technique."""

    technique_id: str
    technique_name: str
    tactics: List[str]
    sub_technique_id: Optional[str] = None
    confidence: float = 1.0  # How confident we are in the mapping


@dataclass
class RuleCoverage:
    """Coverage information for a single detection rule."""

    rule_id: str
    rule_name: str
    techniques: List[TechniqueMapping] = field(default_factory=list)
    tactics_covered: Set[str] = field(default_factory=set)
    is_cloud_priority: bool = False

    def __post_init__(self):
        # Compute tactics from techniques
        for tech in self.techniques:
            self.tactics_covered.update(tech.tactics)
        # Check if any technique is cloud priority
        for tech in self.techniques:
            if tech.technique_id in CLOUD_PRIORITY_TECHNIQUES:
                self.is_cloud_priority = True
                break


@dataclass
class CoverageGap:
    """Represents a gap in detection coverage."""

    technique_id: str
    technique_name: str
    tactics: List[str]
    priority: str  # "critical", "high", "medium", "low"
    reason: str
    recommendation: str
    log_sources_needed: List[str] = field(default_factory=list)


@dataclass
class CoverageReport:
    """Complete coverage analysis report."""

    timestamp: datetime
    total_techniques: int
    covered_techniques: int
    coverage_percentage: float
    total_rules: int
    rules_with_mapping: int

    # Coverage by tactic
    tactic_coverage: Dict[str, float] = field(default_factory=dict)  # tactic -> % covered

    # Coverage details
    covered_technique_ids: Set[str] = field(default_factory=set)
    uncovered_technique_ids: Set[str] = field(default_factory=set)

    # Gaps and recommendations
    gaps: List[CoverageGap] = field(default_factory=list)
    priority_gaps: List[CoverageGap] = field(default_factory=list)

    # Rule coverage
    rule_coverage: List[RuleCoverage] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "summary": {
                "total_techniques": self.total_techniques,
                "covered_techniques": self.covered_techniques,
                "coverage_percentage": round(self.coverage_percentage, 1),
                "total_rules": self.total_rules,
                "rules_with_mapping": self.rules_with_mapping
            },
            "tactic_coverage": {k: round(v, 1) for k, v in self.tactic_coverage.items()},
            "gaps": [
                {
                    "technique_id": g.technique_id,
                    "technique_name": g.technique_name,
                    "tactics": g.tactics,
                    "priority": g.priority,
                    "reason": g.reason,
                    "recommendation": g.recommendation,
                    "log_sources_needed": g.log_sources_needed
                }
                for g in self.priority_gaps[:20]  # Top 20 priority gaps
            ],
            "covered_techniques": list(self.covered_technique_ids),
            "uncovered_techniques": list(self.uncovered_technique_ids)[:50]
        }


class CoverageAnalyzer:
    """Analyzes detection rule coverage against MITRE ATT&CK framework."""

    # Log sources typically needed for each technique
    TECHNIQUE_LOG_SOURCES = {
        "T1078": ["authentication_logs", "aws_cloudtrail", "azure_signin", "okta", "google_workspace"],
        "T1098": ["aws_cloudtrail", "azure_activity", "gcp_audit", "okta"],
        "T1136": ["aws_cloudtrail", "azure_activity", "gcp_audit", "okta", "active_directory"],
        "T1562": ["aws_cloudtrail", "azure_activity", "gcp_audit", "endpoint_logs"],
        "T1070": ["aws_cloudtrail", "azure_activity", "gcp_audit", "endpoint_logs", "syslog"],
        "T1530": ["aws_cloudtrail", "azure_storage_logs", "gcp_audit"],
        "T1110": ["authentication_logs", "aws_cloudtrail", "azure_signin", "okta", "vpn_logs"],
        "T1059": ["endpoint_logs", "powershell_logs", "sysmon", "auditd"],
        "T1003": ["endpoint_logs", "sysmon", "windows_security"],
        "T1021": ["authentication_logs", "network_flow", "endpoint_logs", "rdp_logs"],
    }

    def __init__(
        self,
        include_sub_techniques: bool = False,
        focus_cloud: bool = True
    ):
        """Initialize coverage analyzer.

        Args:
            include_sub_techniques: Whether to track sub-technique coverage
            focus_cloud: Whether to prioritize cloud-specific techniques
        """
        self.include_sub_techniques = include_sub_techniques
        self.focus_cloud = focus_cloud

    def extract_mitre_from_rule(self, rule: Dict[str, Any]) -> List[TechniqueMapping]:
        """Extract MITRE ATT&CK mappings from a rule.

        Args:
            rule: Detection rule dictionary

        Returns:
            List of technique mappings found in rule
        """
        mappings = []

        # Check for explicit MITRE mapping in rule
        mitre_attack = rule.get("mitre_attack") or rule.get("attack") or {}

        # Handle different formats
        if isinstance(mitre_attack, dict):
            technique_id = mitre_attack.get("technique_id") or mitre_attack.get("technique")
            if technique_id:
                mapping = self._create_mapping(technique_id)
                if mapping:
                    mappings.append(mapping)

        elif isinstance(mitre_attack, list):
            for item in mitre_attack:
                if isinstance(item, dict):
                    technique_id = item.get("technique_id") or item.get("technique")
                elif isinstance(item, str):
                    technique_id = item
                else:
                    continue

                if technique_id:
                    mapping = self._create_mapping(technique_id)
                    if mapping:
                        mappings.append(mapping)

        # Check tags for ATT&CK patterns (attack.technique.T1234)
        tags = rule.get("tags", [])
        for tag in tags:
            if isinstance(tag, str) and tag.startswith("attack."):
                # Parse attack.tactic or attack.technique.T1234
                parts = tag.split(".")
                for part in parts:
                    if part.startswith("T") and part[1:].replace(".", "").isdigit():
                        mapping = self._create_mapping(part)
                        if mapping and mapping not in mappings:
                            mappings.append(mapping)

        # Check logsource for implicit mappings
        logsource = rule.get("logsource", {})
        category = logsource.get("category", "")
        product = logsource.get("product", "")

        # Infer techniques from logsource
        inferred = self._infer_techniques_from_logsource(category, product, rule)
        for mapping in inferred:
            if mapping not in mappings:
                mapping.confidence = 0.7  # Lower confidence for inferred
                mappings.append(mapping)

        return mappings

    def _create_mapping(self, technique_id: str) -> Optional[TechniqueMapping]:
        """Create a TechniqueMapping from a technique ID."""
        # Handle sub-technique format (T1234.001)
        base_id = technique_id.split(".")[0]
        sub_id = technique_id if "." in technique_id else None

        if base_id not in MITRE_TECHNIQUES:
            return None

        name, tactics, _ = MITRE_TECHNIQUES[base_id]
        return TechniqueMapping(
            technique_id=base_id,
            technique_name=name,
            tactics=[t.value for t in tactics],
            sub_technique_id=sub_id
        )

    def _infer_techniques_from_logsource(
        self,
        category: str,
        product: str,
        rule: Dict[str, Any]
    ) -> List[TechniqueMapping]:
        """Infer MITRE techniques from log source and rule content."""
        mappings = []

        # Authentication-related rules
        if category in ["authentication", "logon", "signin"]:
            # Check rule content for specific patterns
            detection = str(rule.get("detection", {})).lower()
            if "fail" in detection or "invalid" in detection:
                mapping = self._create_mapping("T1110")  # Brute Force
                if mapping:
                    mappings.append(mapping)
            else:
                mapping = self._create_mapping("T1078")  # Valid Accounts
                if mapping:
                    mappings.append(mapping)

        # CloudTrail/Cloud audit rules
        if product in ["aws", "cloudtrail", "azure", "gcp"]:
            detection = str(rule.get("detection", {})).lower()

            if any(x in detection for x in ["createuser", "createaccount", "adduser"]):
                mapping = self._create_mapping("T1136")
                if mapping:
                    mappings.append(mapping)

            if any(x in detection for x in ["attachpolicy", "putpolicy", "addrole"]):
                mapping = self._create_mapping("T1098")
                if mapping:
                    mappings.append(mapping)

            if any(x in detection for x in ["stoplogging", "deletetrail", "disablealarm"]):
                mapping = self._create_mapping("T1562")
                if mapping:
                    mappings.append(mapping)

            if any(x in detection for x in ["getobject", "listobject", "downloadblob"]):
                mapping = self._create_mapping("T1530")
                if mapping:
                    mappings.append(mapping)

        # Process execution rules
        if category in ["process_creation", "process"]:
            mapping = self._create_mapping("T1059")
            if mapping:
                mappings.append(mapping)

        return mappings

    def analyze_rules(self, rules: List[Dict[str, Any]]) -> CoverageReport:
        """Analyze coverage of a set of detection rules.

        Args:
            rules: List of detection rule dictionaries

        Returns:
            CoverageReport with analysis results
        """
        rule_coverages = []
        covered_techniques: Set[str] = set()

        for rule in rules:
            rule_id = rule.get("id", "unknown")
            rule_name = rule.get("name", rule.get("title", "Unknown Rule"))

            techniques = self.extract_mitre_from_rule(rule)
            coverage = RuleCoverage(
                rule_id=rule_id,
                rule_name=rule_name,
                techniques=techniques
            )
            rule_coverages.append(coverage)

            for tech in techniques:
                covered_techniques.add(tech.technique_id)

        # Calculate coverage
        all_technique_ids = set(MITRE_TECHNIQUES.keys())
        uncovered_techniques = all_technique_ids - covered_techniques

        # Calculate tactic coverage
        tactic_coverage = {}
        for tactic in Tactic:
            techniques_for_tactic = [
                tid for tid, (_, tactics, _) in MITRE_TECHNIQUES.items()
                if tactic in tactics
            ]
            covered_for_tactic = [t for t in techniques_for_tactic if t in covered_techniques]
            if techniques_for_tactic:
                tactic_coverage[tactic.value] = (len(covered_for_tactic) / len(techniques_for_tactic)) * 100
            else:
                tactic_coverage[tactic.value] = 0

        # Generate gaps
        gaps = []
        for tech_id in uncovered_techniques:
            name, tactics, _ = MITRE_TECHNIQUES[tech_id]

            # Determine priority
            if tech_id in CLOUD_PRIORITY_TECHNIQUES and self.focus_cloud:
                priority = "critical"
            elif any(t in [Tactic.CREDENTIAL_ACCESS, Tactic.INITIAL_ACCESS, Tactic.IMPACT] for t in tactics):
                priority = "high"
            elif any(t in [Tactic.PRIVILEGE_ESCALATION, Tactic.DEFENSE_EVASION, Tactic.EXFILTRATION] for t in tactics):
                priority = "medium"
            else:
                priority = "low"

            gap = CoverageGap(
                technique_id=tech_id,
                technique_name=name,
                tactics=[t.value for t in tactics],
                priority=priority,
                reason=f"No detection rule covers {tech_id} ({name})",
                recommendation=self._generate_recommendation(tech_id),
                log_sources_needed=self.TECHNIQUE_LOG_SOURCES.get(tech_id, [])
            )
            gaps.append(gap)

        # Sort gaps by priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        gaps.sort(key=lambda g: (priority_order.get(g.priority, 4), g.technique_id))

        priority_gaps = [g for g in gaps if g.priority in ["critical", "high"]]

        return CoverageReport(
            timestamp=datetime.utcnow(),
            total_techniques=len(all_technique_ids),
            covered_techniques=len(covered_techniques),
            coverage_percentage=(len(covered_techniques) / len(all_technique_ids)) * 100 if all_technique_ids else 0,
            total_rules=len(rules),
            rules_with_mapping=len([r for r in rule_coverages if r.techniques]),
            tactic_coverage=tactic_coverage,
            covered_technique_ids=covered_techniques,
            uncovered_technique_ids=uncovered_techniques,
            gaps=gaps,
            priority_gaps=priority_gaps,
            rule_coverage=rule_coverages
        )

    def _generate_recommendation(self, technique_id: str) -> str:
        """Generate a recommendation for covering a technique."""
        recommendations = {
            "T1078": "Create rules detecting successful logins from new locations, impossible travel, or service account misuse",
            "T1098": "Monitor IAM policy changes, role assignments, and permission modifications",
            "T1136": "Alert on new user/service account creation, especially with elevated privileges",
            "T1562": "Detect logging disablement, monitoring configuration changes, or security tool removal",
            "T1070": "Monitor for log deletion events, audit log tampering, or history clearing",
            "T1530": "Track bulk data access to cloud storage, unusual download patterns",
            "T1110": "Detect multiple failed authentication attempts, password spraying patterns",
            "T1059": "Monitor process creation with scripting interpreters (PowerShell, bash, python)",
            "T1003": "Alert on credential dumping tool execution or memory access to lsass",
            "T1021": "Track remote service connections (RDP, SSH, SMB) especially from unusual sources",
            "T1606": "Monitor OAuth token creation, SAML assertion issues, session token anomalies",
            "T1537": "Detect data transfers to external cloud accounts or cross-account access",
            "T1580": "Monitor cloud infrastructure enumeration (describe instances, list buckets)",
            "T1526": "Detect cloud service discovery (listing functions, databases, queues)",
        }
        return recommendations.get(technique_id, f"Consider creating detection rules for {technique_id}")

    def generate_rule_suggestion(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Generate a suggested Sigma rule template for a technique.

        Args:
            technique_id: MITRE ATT&CK technique ID

        Returns:
            Sigma rule template dictionary or None
        """
        if technique_id not in MITRE_TECHNIQUES:
            return None

        name, tactics, _ = MITRE_TECHNIQUES[technique_id]
        tactic_tags = [f"attack.{t.value}" for t in tactics]

        # Generate a basic rule template
        return {
            "title": f"Potential {name} ({technique_id})",
            "id": f"suggested-{technique_id.lower()}",
            "status": "experimental",
            "description": f"Detects potential {name} activity. This is a suggested rule that should be customized for your environment.",
            "author": "Mantissa Log Coverage Analyzer",
            "date": datetime.utcnow().strftime("%Y/%m/%d"),
            "tags": tactic_tags + [f"attack.{technique_id.lower()}"],
            "logsource": {
                "category": "# TODO: Specify log source category",
                "product": "# TODO: Specify log source product"
            },
            "detection": {
                "selection": {
                    "# TODO": "Add detection logic"
                },
                "condition": "selection"
            },
            "falsepositives": ["# TODO: List known false positives"],
            "level": "medium",
            "references": [
                f"https://attack.mitre.org/techniques/{technique_id}/"
            ]
        }


def analyze_detection_coverage(rules: List[Dict[str, Any]]) -> CoverageReport:
    """Convenience function to analyze detection coverage.

    Args:
        rules: List of detection rules

    Returns:
        Coverage analysis report
    """
    analyzer = CoverageAnalyzer(focus_cloud=True)
    return analyzer.analyze_rules(rules)
