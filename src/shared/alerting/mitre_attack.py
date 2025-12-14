"""
MITRE ATT&CK Tagging Enhancement.

Provides functionality to:
- Auto-tag alerts with ATT&CK techniques based on rule and alert content
- Link to ATT&CK Navigator for visualization
- Track technique coverage over time
- Generate coverage reports and gap analysis
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import Counter, defaultdict

logger = logging.getLogger(__name__)


# MITRE ATT&CK Enterprise Matrix data (v14 - partial listing)
TACTICS = {
    "TA0043": {"name": "Reconnaissance", "shortname": "reconnaissance"},
    "TA0042": {"name": "Resource Development", "shortname": "resource-development"},
    "TA0001": {"name": "Initial Access", "shortname": "initial-access"},
    "TA0002": {"name": "Execution", "shortname": "execution"},
    "TA0003": {"name": "Persistence", "shortname": "persistence"},
    "TA0004": {"name": "Privilege Escalation", "shortname": "privilege-escalation"},
    "TA0005": {"name": "Defense Evasion", "shortname": "defense-evasion"},
    "TA0006": {"name": "Credential Access", "shortname": "credential-access"},
    "TA0007": {"name": "Discovery", "shortname": "discovery"},
    "TA0008": {"name": "Lateral Movement", "shortname": "lateral-movement"},
    "TA0009": {"name": "Collection", "shortname": "collection"},
    "TA0011": {"name": "Command and Control", "shortname": "command-and-control"},
    "TA0010": {"name": "Exfiltration", "shortname": "exfiltration"},
    "TA0040": {"name": "Impact", "shortname": "impact"},
}

# Common techniques mapped by keywords/patterns
TECHNIQUE_KEYWORDS = {
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "execution",
        "keywords": ["powershell", "cmd.exe", "bash", "python", "script", "wscript", "cscript"],
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "execution",
        "keywords": ["powershell", "pwsh", "invoke-expression", "invoke-command", "-encodedcommand"],
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "tactic": "execution",
        "keywords": ["cmd.exe", "cmd /c", "command prompt"],
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "initial-access",
        "keywords": ["valid account", "compromised credential", "stolen credential", "account login"],
    },
    "T1078.004": {
        "name": "Cloud Accounts",
        "tactic": "initial-access",
        "keywords": ["cloud account", "aws account", "azure ad", "gcp account", "iam user"],
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "credential-access",
        "keywords": ["brute force", "password spray", "credential stuffing", "failed login"],
    },
    "T1110.001": {
        "name": "Password Guessing",
        "tactic": "credential-access",
        "keywords": ["password guess", "login attempt", "authentication fail"],
    },
    "T1110.003": {
        "name": "Password Spraying",
        "tactic": "credential-access",
        "keywords": ["password spray", "spray attack"],
    },
    "T1136": {
        "name": "Create Account",
        "tactic": "persistence",
        "keywords": ["create user", "new account", "add user", "createuser", "useradd"],
    },
    "T1136.003": {
        "name": "Cloud Account",
        "tactic": "persistence",
        "keywords": ["create iam", "create user", "new azure user", "add gcp user"],
    },
    "T1098": {
        "name": "Account Manipulation",
        "tactic": "persistence",
        "keywords": ["modify account", "change permission", "add role", "grant access", "privilege change"],
    },
    "T1098.001": {
        "name": "Additional Cloud Credentials",
        "tactic": "persistence",
        "keywords": ["access key", "service account key", "api key created", "new credential"],
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactic": "defense-evasion",
        "keywords": ["disable logging", "stop monitoring", "delete log", "disable security"],
    },
    "T1562.001": {
        "name": "Disable or Modify Tools",
        "tactic": "defense-evasion",
        "keywords": ["disable antivirus", "stop defender", "disable edr", "uninstall security"],
    },
    "T1562.008": {
        "name": "Disable Cloud Logs",
        "tactic": "defense-evasion",
        "keywords": ["disable cloudtrail", "stop logging", "delete trail", "disable audit"],
    },
    "T1087": {
        "name": "Account Discovery",
        "tactic": "discovery",
        "keywords": ["list user", "enum user", "whoami", "get-aduser", "net user"],
    },
    "T1087.004": {
        "name": "Cloud Account Discovery",
        "tactic": "discovery",
        "keywords": ["list iam", "describe user", "get-azureaduser", "list service account"],
    },
    "T1069": {
        "name": "Permission Groups Discovery",
        "tactic": "discovery",
        "keywords": ["list group", "enum group", "get-adgroup", "net group", "list role"],
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "discovery",
        "keywords": ["port scan", "network scan", "service enumeration", "nmap"],
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "lateral-movement",
        "keywords": ["rdp", "ssh", "remote desktop", "winrm", "psexec"],
    },
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactic": "lateral-movement",
        "keywords": ["rdp", "remote desktop", "mstsc", "3389"],
    },
    "T1021.004": {
        "name": "SSH",
        "tactic": "lateral-movement",
        "keywords": ["ssh", "secure shell", "port 22"],
    },
    "T1567": {
        "name": "Exfiltration Over Web Service",
        "tactic": "exfiltration",
        "keywords": ["upload to cloud", "exfil", "data transfer", "send to external"],
    },
    "T1567.002": {
        "name": "Exfiltration to Cloud Storage",
        "tactic": "exfiltration",
        "keywords": ["upload s3", "copy to bucket", "azure blob", "cloud storage"],
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "impact",
        "keywords": ["ransomware", "encrypt file", "ransom", "crypto locker"],
    },
    "T1531": {
        "name": "Account Access Removal",
        "tactic": "impact",
        "keywords": ["delete user", "remove account", "disable account", "lock account"],
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "command-and-control",
        "keywords": ["c2", "command and control", "beacon", "callback"],
    },
    "T1071.001": {
        "name": "Web Protocols",
        "tactic": "command-and-control",
        "keywords": ["http c2", "https beacon", "web callback"],
    },
    "T1537": {
        "name": "Transfer Data to Cloud Account",
        "tactic": "exfiltration",
        "keywords": ["copy to account", "transfer bucket", "cross account"],
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "initial-access",
        "keywords": ["exploit", "vulnerability", "cve-", "rce", "injection"],
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "initial-access",
        "keywords": ["phishing", "spear phishing", "malicious email", "suspicious attachment"],
    },
    "T1566.001": {
        "name": "Spearphishing Attachment",
        "tactic": "initial-access",
        "keywords": ["malicious attachment", "email attachment", "document macro"],
    },
    "T1204": {
        "name": "User Execution",
        "tactic": "execution",
        "keywords": ["user executed", "user ran", "clicked link", "opened file"],
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "persistence",
        "keywords": ["scheduled task", "cron job", "at job", "task scheduler"],
    },
    "T1543": {
        "name": "Create or Modify System Process",
        "tactic": "persistence",
        "keywords": ["create service", "new service", "modify service", "systemd"],
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "privilege-escalation",
        "keywords": ["bypass uac", "sudo abuse", "setuid", "elevation"],
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "credential-access",
        "keywords": ["credential dump", "mimikatz", "lsass", "sam dump", "ntds.dit"],
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "tactic": "credential-access",
        "keywords": ["plaintext password", "credential in file", "hardcoded credential"],
    },
}


@dataclass
class MitreTag:
    """A MITRE ATT&CK tag."""

    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    confidence: str = "medium"  # high, medium, low
    source: str = "auto"  # auto, rule, manual

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic_id": self.tactic_id,
            "tactic_name": self.tactic_name,
            "confidence": self.confidence,
            "source": self.source,
        }


@dataclass
class CoverageStats:
    """Statistics about MITRE ATT&CK coverage."""

    total_tactics: int = 14
    covered_tactics: int = 0
    tactic_coverage_pct: float = 0.0

    total_techniques_tracked: int = 0
    covered_techniques: int = 0
    technique_coverage_pct: float = 0.0

    # Breakdown by tactic
    by_tactic: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Most/least covered
    most_covered_tactics: List[str] = field(default_factory=list)
    least_covered_tactics: List[str] = field(default_factory=list)
    gaps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_tactics": self.total_tactics,
            "covered_tactics": self.covered_tactics,
            "tactic_coverage_pct": round(self.tactic_coverage_pct, 2),
            "total_techniques_tracked": self.total_techniques_tracked,
            "covered_techniques": self.covered_techniques,
            "technique_coverage_pct": round(self.technique_coverage_pct, 2),
            "by_tactic": self.by_tactic,
            "most_covered_tactics": self.most_covered_tactics,
            "least_covered_tactics": self.least_covered_tactics,
            "gaps": self.gaps,
        }


@dataclass
class NavigatorLayer:
    """ATT&CK Navigator layer for visualization."""

    name: str
    description: str
    domain: str = "enterprise-attack"
    version: str = "4.5"

    # Technique scores
    techniques: List[Dict[str, Any]] = field(default_factory=list)

    # Metadata
    filters: Dict[str, List[str]] = field(default_factory=dict)
    gradient: Dict[str, Any] = field(default_factory=lambda: {
        "colors": ["#ffffff", "#66b1ff", "#0078d4"],
        "minValue": 0,
        "maxValue": 100
    })

    def to_dict(self) -> Dict[str, Any]:
        """Convert to Navigator JSON format."""
        return {
            "name": self.name,
            "version": self.version,
            "domain": self.domain,
            "description": self.description,
            "filters": self.filters,
            "sorting": 0,
            "layout": {
                "layout": "side",
                "showID": True,
                "showName": True,
            },
            "hideDisabled": False,
            "techniques": self.techniques,
            "gradient": self.gradient,
            "legendItems": [],
            "metadata": [],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False,
        }


class MitreAttackTagger:
    """Auto-tags alerts with MITRE ATT&CK techniques."""

    def __init__(self):
        """Initialize tagger."""
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile keyword patterns for efficient matching."""
        self._patterns = {}
        for tech_id, data in TECHNIQUE_KEYWORDS.items():
            # Create regex pattern from keywords
            keywords = data["keywords"]
            pattern = "|".join(re.escape(kw) for kw in keywords)
            self._patterns[tech_id] = {
                "pattern": re.compile(pattern, re.IGNORECASE),
                "name": data["name"],
                "tactic": data["tactic"],
            }

    def tag_alert(self, alert: Dict[str, Any]) -> List[MitreTag]:
        """
        Auto-tag an alert with MITRE ATT&CK techniques.

        Args:
            alert: Alert data

        Returns:
            List of MitreTag objects
        """
        tags = []
        seen_techniques = set()

        # First, check if alert already has MITRE tags
        existing_mitre = alert.get("mitre_attack", {})
        if existing_mitre:
            tag = self._parse_existing_mitre(existing_mitre)
            if tag:
                tags.append(tag)
                seen_techniques.add(tag.technique_id)

        # Extract text to analyze
        text_to_analyze = self._extract_text(alert)

        # Match against technique patterns
        for tech_id, data in self._patterns.items():
            if tech_id in seen_techniques:
                continue

            if data["pattern"].search(text_to_analyze):
                # Find tactic info
                tactic_info = self._get_tactic_info(data["tactic"])

                tag = MitreTag(
                    technique_id=tech_id,
                    technique_name=data["name"],
                    tactic_id=tactic_info.get("id", ""),
                    tactic_name=tactic_info.get("name", data["tactic"]),
                    confidence="medium",
                    source="auto"
                )
                tags.append(tag)
                seen_techniques.add(tech_id)

        # Sort by technique ID
        tags.sort(key=lambda t: t.technique_id)

        return tags

    def tag_rule(self, rule: Dict[str, Any]) -> List[MitreTag]:
        """
        Extract MITRE ATT&CK tags from a Sigma rule.

        Args:
            rule: Sigma rule definition

        Returns:
            List of MitreTag objects
        """
        tags = []

        # Check rule tags
        rule_tags = rule.get("tags", [])
        for tag in rule_tags:
            if tag.startswith("attack."):
                mitre_tag = self._parse_sigma_tag(tag)
                if mitre_tag:
                    tags.append(mitre_tag)

        # Check logsource for hints
        logsource = rule.get("logsource", {})
        category = logsource.get("category", "")

        # Auto-detect from category
        category_mappings = {
            "process_creation": [("T1059", "Command and Scripting Interpreter")],
            "network_connection": [("T1071", "Application Layer Protocol")],
            "file_event": [("T1486", "Data Encrypted for Impact")],
            "registry_event": [("T1112", "Modify Registry")],
            "dns_query": [("T1071.004", "DNS")],
        }

        if category in category_mappings:
            for tech_id, tech_name in category_mappings[category]:
                if not any(t.technique_id == tech_id for t in tags):
                    tactic = TECHNIQUE_KEYWORDS.get(tech_id, {}).get("tactic", "unknown")
                    tactic_info = self._get_tactic_info(tactic)

                    tags.append(MitreTag(
                        technique_id=tech_id,
                        technique_name=tech_name,
                        tactic_id=tactic_info.get("id", ""),
                        tactic_name=tactic_info.get("name", ""),
                        confidence="low",
                        source="auto"
                    ))

        return tags

    def _parse_existing_mitre(self, mitre: Dict[str, Any]) -> Optional[MitreTag]:
        """Parse existing MITRE ATT&CK data from alert."""
        technique = mitre.get("technique", "")
        tactic = mitre.get("tactic", "")

        if not technique:
            return None

        # Try to find technique ID
        tech_id = mitre.get("technique_id", "")
        if not tech_id:
            # Try to extract from technique name
            for tid, data in TECHNIQUE_KEYWORDS.items():
                if data["name"].lower() == technique.lower():
                    tech_id = tid
                    break

        tactic_info = self._get_tactic_info(tactic)

        return MitreTag(
            technique_id=tech_id or "unknown",
            technique_name=technique,
            tactic_id=tactic_info.get("id", ""),
            tactic_name=tactic_info.get("name", tactic),
            confidence="high",
            source="rule"
        )

    def _parse_sigma_tag(self, tag: str) -> Optional[MitreTag]:
        """Parse a Sigma attack.* tag."""
        # Format: attack.tactic or attack.tXXXX
        parts = tag.split(".")
        if len(parts) < 2:
            return None

        value = parts[1]

        # Check if it's a technique ID
        if value.upper().startswith("T"):
            tech_id = value.upper()
            if tech_id in TECHNIQUE_KEYWORDS:
                data = TECHNIQUE_KEYWORDS[tech_id]
                tactic_info = self._get_tactic_info(data["tactic"])

                return MitreTag(
                    technique_id=tech_id,
                    technique_name=data["name"],
                    tactic_id=tactic_info.get("id", ""),
                    tactic_name=tactic_info.get("name", ""),
                    confidence="high",
                    source="rule"
                )

        # Check if it's a tactic name
        for tactic_id, tactic_data in TACTICS.items():
            if value.replace("_", "-") == tactic_data["shortname"]:
                return MitreTag(
                    technique_id="",
                    technique_name="",
                    tactic_id=tactic_id,
                    tactic_name=tactic_data["name"],
                    confidence="medium",
                    source="rule"
                )

        return None

    def _extract_text(self, alert: Dict[str, Any]) -> str:
        """Extract searchable text from alert."""
        text_parts = []

        # Add key fields
        for field in ["title", "description", "rule_name"]:
            if field in alert:
                text_parts.append(str(alert[field]))

        # Add results fields
        results = alert.get("results", [])
        for result in results[:5]:  # Limit to first 5 results
            if isinstance(result, dict):
                for key, value in result.items():
                    if isinstance(value, str):
                        text_parts.append(value)

        # Add tags
        tags = alert.get("tags", [])
        text_parts.extend(str(t) for t in tags)

        return " ".join(text_parts)

    def _get_tactic_info(self, tactic_name: str) -> Dict[str, str]:
        """Get tactic info from name or shortname."""
        tactic_lower = tactic_name.lower().replace("_", "-").replace(" ", "-")

        for tactic_id, data in TACTICS.items():
            if data["shortname"] == tactic_lower or data["name"].lower() == tactic_lower:
                return {"id": tactic_id, "name": data["name"]}

        return {"id": "", "name": tactic_name}


class MitreCoverageTracker:
    """Tracks MITRE ATT&CK technique coverage over time."""

    def __init__(self):
        """Initialize coverage tracker."""
        self._rule_coverage: Dict[str, Set[str]] = {}  # rule_id -> set of technique_ids
        self._technique_alerts: Dict[str, List[str]] = defaultdict(list)  # technique_id -> alert_ids
        self._tactic_techniques: Dict[str, Set[str]] = defaultdict(set)  # tactic -> technique_ids

        # Build tactic -> technique mapping
        for tech_id, data in TECHNIQUE_KEYWORDS.items():
            tactic = data["tactic"]
            self._tactic_techniques[tactic].add(tech_id)

    def record_rule_coverage(self, rule_id: str, tags: List[MitreTag]) -> None:
        """Record technique coverage from a rule."""
        technique_ids = {t.technique_id for t in tags if t.technique_id}
        self._rule_coverage[rule_id] = technique_ids

    def record_alert(self, alert_id: str, tags: List[MitreTag]) -> None:
        """Record an alert with MITRE tags."""
        for tag in tags:
            if tag.technique_id:
                self._technique_alerts[tag.technique_id].append(alert_id)

    def get_coverage_stats(self) -> CoverageStats:
        """Calculate current coverage statistics."""
        stats = CoverageStats()

        # Get all covered techniques from rules
        all_covered = set()
        for techniques in self._rule_coverage.values():
            all_covered.update(techniques)

        stats.covered_techniques = len(all_covered)
        stats.total_techniques_tracked = len(TECHNIQUE_KEYWORDS)
        stats.technique_coverage_pct = (
            stats.covered_techniques / stats.total_techniques_tracked * 100
            if stats.total_techniques_tracked > 0 else 0
        )

        # Calculate tactic coverage
        covered_tactics = set()
        for tech_id in all_covered:
            if tech_id in TECHNIQUE_KEYWORDS:
                tactic = TECHNIQUE_KEYWORDS[tech_id]["tactic"]
                covered_tactics.add(tactic)

        stats.covered_tactics = len(covered_tactics)
        stats.tactic_coverage_pct = stats.covered_tactics / stats.total_tactics * 100

        # Build by-tactic breakdown
        tactic_counts = defaultdict(lambda: {"total": 0, "covered": 0, "techniques": []})

        for tactic, techniques in self._tactic_techniques.items():
            tactic_counts[tactic]["total"] = len(techniques)
            covered = techniques & all_covered
            tactic_counts[tactic]["covered"] = len(covered)
            tactic_counts[tactic]["techniques"] = list(covered)

        stats.by_tactic = dict(tactic_counts)

        # Most/least covered
        sorted_tactics = sorted(
            tactic_counts.items(),
            key=lambda x: x[1]["covered"] / x[1]["total"] if x[1]["total"] > 0 else 0,
            reverse=True
        )

        stats.most_covered_tactics = [t[0] for t in sorted_tactics[:3] if t[1]["covered"] > 0]
        stats.least_covered_tactics = [t[0] for t in sorted_tactics[-3:] if t[1]["covered"] == 0]

        # Identify gaps (tactics with no coverage)
        stats.gaps = [
            tactic for tactic, data in tactic_counts.items()
            if data["covered"] == 0
        ]

        return stats

    def generate_navigator_layer(
        self,
        name: str = "Mantissa Log Detection Coverage",
        description: str = "Detection coverage from deployed Sigma rules"
    ) -> NavigatorLayer:
        """Generate ATT&CK Navigator layer for visualization."""
        layer = NavigatorLayer(
            name=name,
            description=description
        )

        # Get all covered techniques
        all_covered = set()
        for techniques in self._rule_coverage.values():
            all_covered.update(techniques)

        # Calculate scores based on number of rules covering each technique
        technique_rule_count = Counter()
        for techniques in self._rule_coverage.values():
            for tech_id in techniques:
                technique_rule_count[tech_id] += 1

        # Build technique entries
        for tech_id, data in TECHNIQUE_KEYWORDS.items():
            rule_count = technique_rule_count.get(tech_id, 0)

            # Score: 0 = no coverage, 100 = max coverage
            if rule_count == 0:
                score = 0
                color = ""  # No color = not covered
            else:
                # Normalize score (max out at 5+ rules)
                score = min(100, rule_count * 20)
                color = ""  # Let gradient handle color

            tactic_info = self._get_tactic_id(data["tactic"])

            layer.techniques.append({
                "techniqueID": tech_id,
                "tactic": tactic_info,
                "score": score,
                "color": color,
                "comment": f"{rule_count} rule(s) covering this technique",
                "enabled": True,
                "metadata": [],
                "showSubtechniques": False,
            })

        return layer

    def _get_tactic_id(self, tactic_name: str) -> str:
        """Get tactic shortname for Navigator."""
        tactic_lower = tactic_name.lower().replace("_", "-").replace(" ", "-")
        return tactic_lower

    def get_technique_details(self, technique_id: str) -> Dict[str, Any]:
        """Get detailed information about a technique."""
        data = TECHNIQUE_KEYWORDS.get(technique_id, {})

        # Find rules covering this technique
        covering_rules = [
            rule_id for rule_id, techniques in self._rule_coverage.items()
            if technique_id in techniques
        ]

        # Get alert count
        alert_ids = self._technique_alerts.get(technique_id, [])

        return {
            "technique_id": technique_id,
            "name": data.get("name", "Unknown"),
            "tactic": data.get("tactic", "unknown"),
            "keywords": data.get("keywords", []),
            "covering_rules": covering_rules,
            "rule_count": len(covering_rules),
            "alert_count": len(alert_ids),
            "recent_alerts": alert_ids[-10:],  # Last 10 alerts
        }


def tag_alert(alert: Dict[str, Any]) -> List[MitreTag]:
    """Convenience function to tag an alert."""
    tagger = MitreAttackTagger()
    return tagger.tag_alert(alert)


def tag_rule(rule: Dict[str, Any]) -> List[MitreTag]:
    """Convenience function to tag a rule."""
    tagger = MitreAttackTagger()
    return tagger.tag_rule(rule)


def generate_navigator_layer(
    rules: List[Dict[str, Any]],
    name: str = "Detection Coverage"
) -> Dict[str, Any]:
    """Generate ATT&CK Navigator layer from rules."""
    tagger = MitreAttackTagger()
    tracker = MitreCoverageTracker()

    for rule in rules:
        rule_id = rule.get("id", rule.get("rule_id", ""))
        tags = tagger.tag_rule(rule)
        tracker.record_rule_coverage(rule_id, tags)

    layer = tracker.generate_navigator_layer(name=name)
    return layer.to_dict()
