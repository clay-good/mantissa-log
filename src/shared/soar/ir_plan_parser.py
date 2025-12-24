"""IR Plan Parser.

This module provides functionality to parse Incident Response (IR) plans
in markdown or plain text format into structured Playbook objects using
LLM assistance for intelligent extraction.
"""

import json
import logging
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from ..llm.ir_plan_prompts import (
    IR_PLAN_EXTRACTION_PROMPT,
    ACTION_CLASSIFICATION_PROMPT,
    PARAMETER_EXTRACTION_PROMPT,
    EXPECTED_PARAMETERS,
    IR_PLAN_EXAMPLES,
)
from .playbook import (
    ActionType,
    Playbook,
    PlaybookStep,
    PlaybookTrigger,
    PlaybookTriggerType,
)

logger = logging.getLogger(__name__)


# LLM Client stub for test mocking
class LLMClient:
    """Stub LLM client for test mocking.

    Tests can patch this class to control LLM behavior.
    """

    def __init__(self, provider: str = "default"):
        """Initialize the LLM client.

        Args:
            provider: LLM provider name
        """
        self.provider = provider

    def generate(self, prompt: str, **kwargs) -> str:
        """Generate text from prompt.

        Args:
            prompt: Input prompt
            **kwargs: Additional parameters

        Returns:
            Generated text
        """
        return "{}"

    async def agenerate(self, prompt: str, **kwargs) -> str:
        """Async generate text from prompt.

        Args:
            prompt: Input prompt
            **kwargs: Additional parameters

        Returns:
            Generated text
        """
        return "{}"


# Mapping of keywords to action types
ACTION_KEYWORDS: Dict[str, ActionType] = {
    # Session termination
    "terminate session": ActionType.TERMINATE_SESSIONS,
    "end session": ActionType.TERMINATE_SESSIONS,
    "log out": ActionType.TERMINATE_SESSIONS,
    "logout": ActionType.TERMINATE_SESSIONS,
    "sign out": ActionType.TERMINATE_SESSIONS,
    "kill session": ActionType.TERMINATE_SESSIONS,

    # Account management
    "disable account": ActionType.DISABLE_ACCOUNT,
    "deactivate user": ActionType.DISABLE_ACCOUNT,
    "suspend account": ActionType.DISABLE_ACCOUNT,
    "lock account": ActionType.DISABLE_ACCOUNT,
    "disable user": ActionType.DISABLE_ACCOUNT,

    "enable account": ActionType.ENABLE_ACCOUNT,
    "reactivate user": ActionType.ENABLE_ACCOUNT,
    "unlock account": ActionType.ENABLE_ACCOUNT,
    "enable user": ActionType.ENABLE_ACCOUNT,

    # Password reset
    "reset password": ActionType.FORCE_PASSWORD_RESET,
    "force password": ActionType.FORCE_PASSWORD_RESET,
    "password reset": ActionType.FORCE_PASSWORD_RESET,
    "change password": ActionType.FORCE_PASSWORD_RESET,
    "expire password": ActionType.FORCE_PASSWORD_RESET,

    # Token revocation
    "revoke token": ActionType.REVOKE_TOKENS,
    "invalidate token": ActionType.REVOKE_TOKENS,
    "revoke oauth": ActionType.REVOKE_TOKENS,
    "revoke api key": ActionType.REVOKE_TOKENS,
    "revoke access": ActionType.REVOKE_TOKENS,

    # IP blocking
    "block ip": ActionType.BLOCK_IP,
    "ban ip": ActionType.BLOCK_IP,
    "firewall block": ActionType.BLOCK_IP,
    "blacklist ip": ActionType.BLOCK_IP,
    "deny ip": ActionType.BLOCK_IP,

    "unblock ip": ActionType.UNBLOCK_IP,
    "unban ip": ActionType.UNBLOCK_IP,
    "whitelist ip": ActionType.UNBLOCK_IP,
    "remove block": ActionType.UNBLOCK_IP,

    # Host isolation
    "isolate": ActionType.ISOLATE_HOST,
    "quarantine": ActionType.ISOLATE_HOST,
    "contain": ActionType.ISOLATE_HOST,
    "isolate host": ActionType.ISOLATE_HOST,
    "network isolation": ActionType.ISOLATE_HOST,

    "unisolate": ActionType.UNISOLATE_HOST,
    "remove isolation": ActionType.UNISOLATE_HOST,
    "restore network": ActionType.UNISOLATE_HOST,

    # Notification
    "notify": ActionType.NOTIFY,
    "alert": ActionType.NOTIFY,
    "page": ActionType.NOTIFY,
    "email": ActionType.NOTIFY,
    "send notification": ActionType.NOTIFY,
    "slack": ActionType.NOTIFY,
    "teams": ActionType.NOTIFY,
    "pagerduty": ActionType.NOTIFY,

    # Ticketing
    "create ticket": ActionType.CREATE_TICKET,
    "open ticket": ActionType.CREATE_TICKET,
    "jira": ActionType.CREATE_TICKET,
    "servicenow": ActionType.CREATE_TICKET,
    "create incident": ActionType.CREATE_TICKET,
    "open case": ActionType.CREATE_TICKET,

    # Investigation
    "investigate": ActionType.RUN_QUERY,
    "query": ActionType.RUN_QUERY,
    "search logs": ActionType.RUN_QUERY,
    "run query": ActionType.RUN_QUERY,
    "look up": ActionType.RUN_QUERY,
    "check logs": ActionType.RUN_QUERY,

    # Webhook
    "webhook": ActionType.WEBHOOK,
    "call api": ActionType.WEBHOOK,
    "http request": ActionType.WEBHOOK,
    "api call": ActionType.WEBHOOK,
}

# Actions that typically require approval
APPROVAL_REQUIRED_ACTIONS = {
    ActionType.DISABLE_ACCOUNT,
    ActionType.FORCE_PASSWORD_RESET,
    ActionType.REVOKE_TOKENS,
    ActionType.BLOCK_IP,
    ActionType.ISOLATE_HOST,
}


class IRPlanParseError(Exception):
    """Error during IR plan parsing."""
    pass


class IRPlanParser:
    """Parser for converting IR plans to Playbook objects.

    This class uses a combination of keyword matching and LLM assistance
    to parse natural language IR plans into structured, executable playbooks.
    """

    def __init__(self, llm_provider=None):
        """Initialize the IR plan parser.

        Args:
            llm_provider: Optional LLM provider for intelligent parsing.
                If not provided, will use keyword-based parsing only.
        """
        self.llm_provider = llm_provider
        self.action_keywords = ACTION_KEYWORDS

    def _build_extraction_prompt(self, plan_text: str) -> str:
        """Build the prompt for LLM extraction.

        Args:
            plan_text: Raw IR plan text

        Returns:
            Complete prompt string
        """
        # Add examples to the prompt
        examples_text = "\n\n## Examples\n\n"
        for i, example in enumerate(IR_PLAN_EXAMPLES[:2], 1):
            examples_text += f"### Example {i} Input:\n{example['input']}\n\n"
            examples_text += f"### Example {i} Output:\n```json\n{json.dumps(example['output'], indent=2)}\n```\n\n"

        prompt = IR_PLAN_EXTRACTION_PROMPT.format(plan_text=plan_text)
        return prompt.replace("## Response", examples_text + "## Response")

    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """Parse JSON from LLM response.

        Args:
            response: Raw LLM response

        Returns:
            Parsed JSON dictionary

        Raises:
            IRPlanParseError: If JSON extraction fails
        """
        # Try to extract JSON from markdown code blocks
        json_match = re.search(r'```(?:json)?\s*([\s\S]*?)```', response)
        if json_match:
            json_str = json_match.group(1).strip()
        else:
            # Try to find raw JSON
            json_str = response.strip()

        # Remove any leading/trailing non-JSON content
        json_str = re.sub(r'^[^{\[]*', '', json_str)
        json_str = re.sub(r'[^}\]]*$', '', json_str)

        try:
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response as JSON: {e}")
            logger.debug(f"Response was: {response[:500]}")
            raise IRPlanParseError(f"Failed to parse LLM response: {e}")

    def _determine_action_type(self, action_description: str) -> ActionType:
        """Determine action type from description using keyword matching.

        Args:
            action_description: Natural language action description

        Returns:
            Best matching ActionType
        """
        description_lower = action_description.lower()

        # Score each action type by keyword matches
        scores: Dict[ActionType, int] = {}

        for keyword, action_type in self.action_keywords.items():
            if keyword in description_lower:
                scores[action_type] = scores.get(action_type, 0) + len(keyword)

        if scores:
            # Return action type with highest score
            return max(scores.items(), key=lambda x: x[1])[0]

        # Fall back to LLM classification if available
        if self.llm_provider:
            try:
                prompt = ACTION_CLASSIFICATION_PROMPT.format(
                    action_description=action_description
                )
                response = self.llm_provider.generate(prompt, max_tokens=50)
                action_str = response.strip().lower().replace(" ", "_")

                # Try to match to ActionType
                for action_type in ActionType:
                    if action_type.value == action_str:
                        return action_type
            except Exception as e:
                logger.warning(f"LLM classification failed: {e}")

        # Default to CUSTOM if no match
        logger.warning(f"Could not classify action: {action_description[:50]}...")
        return ActionType.CUSTOM

    def _extract_parameters(
        self,
        step_dict: Dict[str, Any],
        action_type: ActionType
    ) -> Dict[str, Any]:
        """Extract and normalize parameters for an action.

        Args:
            step_dict: Step dictionary from LLM or manual parsing
            action_type: Determined action type

        Returns:
            Normalized parameters dictionary
        """
        params = step_dict.get("parameters", {})

        # Add default Jinja2 templates for common parameters
        if action_type in (
            ActionType.TERMINATE_SESSIONS,
            ActionType.DISABLE_ACCOUNT,
            ActionType.ENABLE_ACCOUNT,
            ActionType.FORCE_PASSWORD_RESET,
            ActionType.REVOKE_TOKENS,
        ):
            if "user_email" not in params and "user_id" not in params:
                params["user_email"] = "{{ alert.metadata.user_email }}"

        elif action_type == ActionType.BLOCK_IP:
            if "ip_address" not in params:
                params["ip_address"] = "{{ alert.metadata.source_ip }}"
            if "duration" not in params:
                params["duration"] = "24h"

        elif action_type == ActionType.ISOLATE_HOST:
            if "hostname" not in params and "host_id" not in params:
                params["hostname"] = "{{ alert.metadata.hostname }}"

        elif action_type == ActionType.NOTIFY:
            if "channel" not in params and "email" not in params:
                params["channel"] = "#security-alerts"

        elif action_type == ActionType.CREATE_TICKET:
            if "project" not in params:
                params["project"] = "SEC"
            if "summary" not in params:
                params["summary"] = "{{ alert.title }}"

        return params

    def _determine_step_dependencies(
        self,
        steps: List[Dict[str, Any]]
    ) -> List[PlaybookStep]:
        """Analyze steps and determine execution dependencies.

        Args:
            steps: List of step dictionaries

        Returns:
            List of PlaybookStep objects with dependencies set
        """
        playbook_steps = []

        for i, step_dict in enumerate(steps):
            step_id = step_dict.get("id", f"step_{i + 1}")
            action_type_str = step_dict.get("action_type", "custom")

            # Convert action type
            try:
                if isinstance(action_type_str, ActionType):
                    action_type = action_type_str
                else:
                    action_type = ActionType(action_type_str)
            except ValueError:
                action_type = self._determine_action_type(
                    step_dict.get("name", "") + " " + step_dict.get("description", "")
                )

            # Extract parameters
            parameters = self._extract_parameters(step_dict, action_type)

            # Determine if approval is required
            requires_approval = step_dict.get("requires_approval", False)
            if not requires_approval and action_type in APPROVAL_REQUIRED_ACTIONS:
                requires_approval = True

            # Determine on_success (default to next step)
            on_success = step_dict.get("on_success")
            if on_success is None and i < len(steps) - 1:
                next_step = steps[i + 1]
                # Don't link to error handler
                if not next_step.get("id", "").startswith("error"):
                    on_success = next_step.get("id", f"step_{i + 2}")

            # Determine on_failure (default to error handler if exists)
            on_failure = step_dict.get("on_failure")
            if on_failure is None:
                # Look for error handler step
                for s in steps:
                    if s.get("id", "").startswith("error"):
                        on_failure = s.get("id")
                        break

            # Create PlaybookStep
            playbook_step = PlaybookStep(
                id=step_id,
                name=step_dict.get("name", f"Step {i + 1}"),
                action_type=action_type,
                provider=step_dict.get("provider", "auto"),
                parameters=parameters,
                condition=step_dict.get("condition"),
                on_success=on_success,
                on_failure=on_failure,
                requires_approval=requires_approval,
                approval_roles=step_dict.get("approval_roles", ["security_analyst"]),
                timeout_seconds=step_dict.get("timeout_seconds", 300),
                retry_count=step_dict.get("retry_count", 0),
                retry_delay_seconds=step_dict.get("retry_delay_seconds", 60),
            )

            playbook_steps.append(playbook_step)

        return playbook_steps

    def detect_format(self, plan_text: str) -> str:
        """Detect the format of an IR plan.

        Args:
            plan_text: Raw IR plan text

        Returns:
            Format string: "yaml", "markdown", or "text"
        """
        text = plan_text.strip()

        # Check for YAML format
        if text.startswith("name:") or text.startswith("---"):
            return "yaml"

        # Check for YAML-like structure
        lines = text.split("\n")
        yaml_indicators = sum(1 for line in lines[:10] if ":" in line and not line.strip().startswith("#"))
        markdown_indicators = sum(1 for line in lines[:10] if line.strip().startswith("#") or line.strip().startswith("-"))

        if yaml_indicators > markdown_indicators and yaml_indicators > 3:
            return "yaml"

        # Check for markdown format
        if text.startswith("#") or "## " in text or "### " in text:
            return "markdown"

        return "text"

    def parse(
        self,
        plan_text: str,
        plan_name: Optional[str] = None,
        author: str = "IR Plan Parser",
        format: Optional[str] = None,
    ) -> Playbook:
        """Parse an IR plan into a Playbook object.

        This is the main entry point for parsing IR plans.

        Args:
            plan_text: IR plan in markdown, YAML, or plain text format
            plan_name: Optional name for the playbook
            author: Author name for the playbook
            format: Optional format hint ("yaml", "markdown", or "text")

        Returns:
            Parsed Playbook object

        Raises:
            IRPlanParseError: If parsing fails
        """
        if not plan_text or not plan_text.strip():
            raise IRPlanParseError("Empty IR plan provided")

        # Detect format if not specified
        if format is None:
            format = self.detect_format(plan_text)

        # Parse based on format
        if format == "yaml":
            return self._parse_yaml(plan_text, plan_name, author)

        # Try LLM parsing first if available (support both llm_provider and llm_client)
        llm = self.llm_provider or getattr(self, 'llm_client', None)
        if llm:
            try:
                # If llm_client has parse_ir_plan method, use it
                if hasattr(llm, 'parse_ir_plan'):
                    playbook_data = llm.parse_ir_plan(plan_text)
                    if playbook_data:
                        return self._create_playbook_from_data(playbook_data, plan_name, author)
                    else:
                        raise ValueError("LLM returned no data")
                else:
                    return self._parse_with_llm(plan_text, plan_name, author)
            except Exception as e:
                logger.warning(f"LLM parsing failed, falling back to keyword parsing: {e}")
                raise

        # Fall back to keyword-based parsing
        return self._parse_with_keywords(plan_text, plan_name, author)

    def _parse_yaml(
        self,
        plan_text: str,
        plan_name: Optional[str],
        author: str
    ) -> Playbook:
        """Parse YAML-formatted IR plan.

        Args:
            plan_text: YAML IR plan text
            plan_name: Optional playbook name
            author: Author name

        Returns:
            Parsed Playbook object
        """
        import yaml

        try:
            data = yaml.safe_load(plan_text)
        except yaml.YAMLError as e:
            raise IRPlanParseError(f"Invalid YAML: {e}")

        return self._create_playbook_from_data(data, plan_name, author)

    def _create_playbook_from_data(
        self,
        data: Dict[str, Any],
        plan_name: Optional[str],
        author: str
    ) -> Playbook:
        """Create a Playbook from parsed data.

        Args:
            data: Dictionary with playbook data
            plan_name: Optional playbook name override
            author: Author name

        Returns:
            Playbook object
        """
        if not isinstance(data, dict):
            raise IRPlanParseError("Invalid playbook data format")

        # Extract playbook name
        name = plan_name or data.get("name", "Parsed IR Plan")
        description = data.get("description", "")

        # Parse steps
        steps_data = data.get("steps", [])
        playbook_steps = []

        for i, step_data in enumerate(steps_data):
            step_id = f"step-{i+1}"
            step_name = step_data.get("name", f"Step {i+1}")

            # Get action type
            action_str = step_data.get("action_type") or step_data.get("action", "custom")
            action_type = self._determine_action_type(action_str)

            # Get parameters
            parameters = step_data.get("parameters", {})

            # Get dependencies
            depends_on = step_data.get("depends_on")
            if depends_on:
                # Convert step names to step IDs if needed
                if isinstance(depends_on, list):
                    # Map step names to IDs
                    deps = []
                    for dep in depends_on:
                        if dep.startswith("step-"):
                            deps.append(dep)
                        else:
                            # Find step index by name
                            for j, s in enumerate(steps_data):
                                if s.get("name") == dep:
                                    deps.append(f"step-{j+1}")
                                    break
                    depends_on = deps if deps else None

            # Get approval requirement
            requires_approval = step_data.get("requires_approval", False)

            playbook_step = PlaybookStep(
                id=step_id,
                name=step_name,
                action_type=action_type,
                parameters=parameters,
                depends_on=depends_on,
                requires_approval=requires_approval,
                timeout_seconds=step_data.get("timeout_seconds", 300),
            )
            playbook_steps.append(playbook_step)

        # Create playbook
        playbook = Playbook(
            id=str(uuid.uuid4()),
            name=name,
            description=description,
            version="1.0.0",
            author=author,
            steps=playbook_steps,
        )

        return playbook

    def _parse_with_llm(
        self,
        plan_text: str,
        plan_name: Optional[str],
        author: str
    ) -> Playbook:
        """Parse IR plan using LLM assistance.

        Args:
            plan_text: IR plan text
            plan_name: Optional playbook name
            author: Author name

        Returns:
            Parsed Playbook
        """
        # Build and execute prompt
        prompt = self._build_extraction_prompt(plan_text)
        response = self.llm_provider.generate(prompt, max_tokens=2000)

        # Parse LLM response
        parsed = self._parse_llm_response(response)

        # Convert to PlaybookStep objects
        steps_data = parsed.get("steps", [])

        # Add error handler if present
        if "error_handler" in parsed:
            steps_data.append(parsed["error_handler"])

        steps = self._determine_step_dependencies(steps_data)

        if not steps:
            raise IRPlanParseError("No valid steps extracted from IR plan")

        # Create playbook
        now = datetime.utcnow()
        playbook = Playbook(
            id=f"pb-{uuid.uuid4().hex[:8]}",
            name=plan_name or parsed.get("name", "Parsed IR Plan"),
            description=parsed.get("description", "Playbook generated from IR plan"),
            version="1.0.0",
            author=author,
            created=now,
            modified=now,
            enabled=True,
            trigger=PlaybookTrigger(
                trigger_type=PlaybookTriggerType.ALERT,
                conditions={
                    "severity": ["high", "critical"],
                }
            ),
            steps=steps,
            tags=["auto-generated", "ir-plan"],
        )

        # Validate
        is_valid, errors = playbook.validate()
        if not is_valid:
            logger.warning(f"Generated playbook has validation errors: {errors}")

        return playbook

    def _parse_with_keywords(
        self,
        plan_text: str,
        plan_name: Optional[str],
        author: str
    ) -> Playbook:
        """Parse IR plan using keyword-based extraction.

        Args:
            plan_text: IR plan text
            plan_name: Optional playbook name
            author: Author name

        Returns:
            Parsed Playbook
        """
        # Extract steps from text
        steps_data = self._extract_steps_from_text(plan_text)

        if not steps_data:
            raise IRPlanParseError("Could not extract any steps from IR plan")

        # Convert to PlaybookStep objects
        steps = self._determine_step_dependencies(steps_data)

        # Extract name from first header or use provided name
        extracted_name = self._extract_name_from_text(plan_text)

        # Create playbook
        now = datetime.utcnow()
        playbook = Playbook(
            id=f"pb-{uuid.uuid4().hex[:8]}",
            name=plan_name or extracted_name or "Parsed IR Plan",
            description="Playbook generated from IR plan using keyword extraction",
            version="1.0.0",
            author=author,
            created=now,
            modified=now,
            enabled=True,
            trigger=PlaybookTrigger(
                trigger_type=PlaybookTriggerType.ALERT,
                conditions={
                    "severity": ["high", "critical"],
                }
            ),
            steps=steps,
            tags=["auto-generated", "ir-plan", "keyword-parsed"],
        )

        return playbook

    def _extract_steps_from_text(self, text: str) -> List[Dict[str, Any]]:
        """Extract steps from plain text or markdown.

        Args:
            text: IR plan text

        Returns:
            List of step dictionaries
        """
        steps = []

        # Split into lines and look for step patterns
        lines = text.split("\n")

        # Patterns for step detection
        patterns = [
            r'^\s*(\d+)[.)\]]\s*(.+)$',  # Numbered list: 1. Step
            r'^\s*[-*]\s*(.+)$',  # Bullet list: - Step
            r'^\s*\[[ x]\]\s*(.+)$',  # Checkbox: [ ] Step
            r'^\s*Step\s*\d*[:.]\s*(.+)$',  # Step N: description
        ]

        step_num = 0
        for line in lines:
            line = line.strip()
            if not line:
                continue

            step_text = None

            # Try each pattern
            for pattern in patterns:
                match = re.match(pattern, line, re.IGNORECASE)
                if match:
                    # Get the step text (last group)
                    step_text = match.group(match.lastindex)
                    break

            if step_text:
                step_num += 1
                action_type = self._determine_action_type(step_text)

                step_dict = {
                    "id": f"step_{step_num}",
                    "name": step_text[:100],  # Truncate long names
                    "action_type": action_type.value,
                    "provider": "auto",
                    "parameters": {},
                }

                steps.append(step_dict)

        # Add error handler if we have steps
        if steps:
            steps.append({
                "id": "error_notify",
                "name": "Error Notification",
                "action_type": "notify",
                "provider": "slack",
                "parameters": {
                    "channel": "#security-alerts",
                    "message": "Playbook error: {{ error }}"
                }
            })

        return steps

    def _extract_name_from_text(self, text: str) -> Optional[str]:
        """Extract playbook name from text headers.

        Args:
            text: IR plan text

        Returns:
            Extracted name or None
        """
        # Look for markdown headers
        header_patterns = [
            r'^#\s+(.+)$',  # # Header
            r'^##\s+(.+)$',  # ## Header
            r'^(.+)\n[=-]+$',  # Underlined header
        ]

        for pattern in header_patterns:
            match = re.search(pattern, text, re.MULTILINE)
            if match:
                return match.group(1).strip()

        return None

    def parse_markdown(self, markdown_text: str) -> Playbook:
        """Parse markdown-formatted IR plan.

        Handles:
        - Headers for playbook name
        - Numbered and bullet lists for steps
        - Checkboxes for tasks
        - YAML front matter for metadata

        Args:
            markdown_text: Markdown IR plan

        Returns:
            Parsed Playbook
        """
        # Extract YAML front matter if present
        metadata = {}
        if markdown_text.startswith("---"):
            parts = markdown_text.split("---", 2)
            if len(parts) >= 3:
                import yaml
                try:
                    metadata = yaml.safe_load(parts[1])
                    markdown_text = parts[2]
                except Exception:
                    pass

        return self.parse(
            markdown_text,
            plan_name=metadata.get("name") or metadata.get("title"),
            author=metadata.get("author", "IR Plan Parser")
        )

    def parse_text(self, plain_text: str) -> Playbook:
        """Parse plain text IR plan.

        More lenient parsing for unstructured text.

        Args:
            plain_text: Plain text IR plan

        Returns:
            Parsed Playbook
        """
        return self.parse(plain_text)


def parse_ir_plan(
    plan_text: str,
    llm_provider=None,
    plan_name: Optional[str] = None
) -> Playbook:
    """Convenience function to parse an IR plan.

    Args:
        plan_text: IR plan in markdown or plain text
        llm_provider: Optional LLM provider
        plan_name: Optional playbook name

    Returns:
        Parsed Playbook
    """
    parser = IRPlanParser(llm_provider=llm_provider)
    return parser.parse(plan_text, plan_name=plan_name)
