"""Playbook Code Generator.

This module converts Playbook objects into executable Python Lambda code.
The generated code is designed to be safe, auditable, and follows security
best practices.

Key features:
- Generates Python code from playbook definitions
- Validates generated code for syntax and security
- Supports all action types defined in ActionType
- Includes proper error handling and logging
- Generates code that integrates with existing provider actions
"""

import ast
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from .action_templates import (
    ACTION_TEMPLATES,
    FILE_HEADER_TEMPLATE,
    GET_PROVIDER_CLIENT_FUNCTION,
    LAMBDA_HANDLER_TEMPLATE,
    RENDER_TEMPLATE_FUNCTION,
)
from .playbook import ActionType, Playbook, PlaybookStep

logger = logging.getLogger(__name__)


# Dangerous patterns to check in generated code
DANGEROUS_PATTERNS = [
    (r'\beval\s*\(', "eval() is not allowed"),
    (r'\bexec\s*\(', "exec() is not allowed"),
    (r'\bcompile\s*\(', "compile() is not allowed"),
    (r'\b__import__\s*\(', "__import__() is not allowed"),
    (r'\bos\.system\s*\(', "os.system() is not allowed"),
    (r'\bsubprocess\..*shell\s*=\s*True', "subprocess with shell=True is not allowed"),
    (r'\bopen\s*\([^)]*["\']w["\']', "File writing is restricted"),
    (r'\bpickle\.loads?\s*\(', "pickle is not allowed for security"),
    (r'\byaml\.load\s*\([^)]*Loader\s*=\s*None', "yaml.load without safe_load is not allowed"),
]


class PlaybookCodeGenerator:
    """Generates executable Python code from Playbook definitions.

    The generator creates Lambda-compatible Python code that:
    - Executes playbook steps in order
    - Handles success/failure branching
    - Renders Jinja2 templates for dynamic parameters
    - Integrates with identity provider action implementations
    - Includes comprehensive logging and error handling

    Attributes:
        llm_provider: Optional LLM provider for custom action generation
    """

    def __init__(self, llm_provider=None):
        """Initialize the code generator.

        Args:
            llm_provider: Optional LLM provider for generating custom action code
        """
        self.llm_provider = llm_provider

    def generate_imports(self, playbook: Playbook) -> str:
        """Generate import statements based on playbook steps.

        Analyzes the playbook steps to determine which imports are needed.

        Args:
            playbook: The playbook to analyze

        Returns:
            String containing import statements
        """
        # Base imports are always included via FILE_HEADER_TEMPLATE
        # This method could be extended to add conditional imports
        return ""

    def generate_step_function(self, step: PlaybookStep) -> str:
        """Generate a Python function for a playbook step.

        Args:
            step: The step to generate code for

        Returns:
            String containing the step function code
        """
        template = ACTION_TEMPLATES.get(step.action_type)
        if not template:
            logger.warning(f"No template for action type: {step.action_type}")
            template = ACTION_TEMPLATES[ActionType.CUSTOM]

        # Extract parameters from step
        params = step.parameters

        # Build template parameters based on action type
        template_params = {
            "step_id": self._sanitize_identifier(step.id),
            "step_name": step.name,
            "provider": step.provider or "auto",
            "on_success": step.on_success or "None",
            "on_failure": step.on_failure or "None",
        }

        # Action-specific parameters
        if step.action_type in [
            ActionType.TERMINATE_SESSIONS,
            ActionType.DISABLE_ACCOUNT,
            ActionType.ENABLE_ACCOUNT,
            ActionType.FORCE_PASSWORD_RESET,
            ActionType.REVOKE_TOKENS,
        ]:
            template_params["user_id_template"] = params.get(
                "user_email",
                params.get("user_id", "{{ alert.metadata.user_email }}")
            )
            template_params["reason_template"] = params.get(
                "reason", "Security incident"
            )

        if step.action_type == ActionType.FORCE_PASSWORD_RESET:
            template_params["notify_user"] = str(params.get("notify_user", True))
            template_params["message_template"] = params.get(
                "message", "Your password has been reset due to a security incident."
            )

        if step.action_type in [ActionType.BLOCK_IP, ActionType.UNBLOCK_IP]:
            template_params["ip_address_template"] = params.get(
                "ip_address", "{{ alert.metadata.source_ip }}"
            )
            template_params["duration"] = params.get("duration", "30d")
            template_params["reason_template"] = params.get("reason", "Security incident")

        if step.action_type in [ActionType.ISOLATE_HOST, ActionType.UNISOLATE_HOST]:
            template_params["host_id_template"] = params.get(
                "host_id", "{{ alert.metadata.host_id }}"
            )
            template_params["hostname_template"] = params.get(
                "hostname", "{{ alert.metadata.hostname }}"
            )
            template_params["reason_template"] = params.get("reason", "Security incident")

        if step.action_type == ActionType.NOTIFY:
            template_params["channel_template"] = params.get(
                "channel", params.get("email", "#security-alerts")
            )
            template_params["message_template"] = params.get("message", "Alert notification")

        if step.action_type == ActionType.CREATE_TICKET:
            template_params["project_template"] = params.get("project", "SEC")
            template_params["issue_type_template"] = params.get("issue_type", "Incident")
            template_params["summary_template"] = params.get("summary", "Security Incident")
            template_params["description_template"] = params.get("description", "")
            template_params["priority_template"] = params.get("priority", "High")
            template_params["labels"] = repr(params.get("labels", []))
            template_params["assignee_template"] = params.get("assignee", "")

        if step.action_type == ActionType.RUN_QUERY:
            template_params["query_template"] = params.get(
                "query", params.get("query_template", "")
            )
            template_params["query_type"] = params.get("query_type", "athena")
            template_params["time_range"] = params.get("time_range", "24h")

        if step.action_type == ActionType.WEBHOOK:
            template_params["url_template"] = params.get("url", "")
            template_params["method"] = params.get("method", "POST")
            template_params["headers"] = repr(params.get("headers", {"Content-Type": "application/json"}))
            template_params["body_template"] = params.get("body", "")

        # Apply template parameters
        try:
            code = template.format(**template_params)
        except KeyError as e:
            logger.error(f"Missing template parameter: {e}")
            code = self._generate_fallback_step(step)

        return code

    def _generate_fallback_step(self, step: PlaybookStep) -> str:
        """Generate a fallback step function when template rendering fails.

        Args:
            step: The step to generate code for

        Returns:
            String containing a safe fallback function
        """
        step_id = self._sanitize_identifier(step.id)
        return f'''
def step_{step_id}(context: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
    """Step: {step.name}

    Action: {step.action_type.value}
    Note: Fallback implementation - template rendering failed.
    """
    logger.warning(f"Step {step_id} using fallback implementation")
    return {{
        "success": False,
        "error": "Step implementation unavailable",
        "next_step_id": "{step.on_failure or 'None'}"
    }}
'''

    def generate_main_handler(self, playbook: Playbook) -> str:
        """Generate the main Lambda handler function.

        Args:
            playbook: The playbook to generate handler for

        Returns:
            String containing the handler function code
        """
        # Build step function map
        step_map_lines = []
        for step in playbook.steps:
            step_id = self._sanitize_identifier(step.id)
            step_map_lines.append(f'        "{step.id}": step_{step_id},')

        step_function_map = "\n".join(step_map_lines)

        # Get first step
        first_step = playbook.get_first_step()
        first_step_id = first_step.id if first_step else "None"

        # Format handler template
        handler_code = LAMBDA_HANDLER_TEMPLATE.format(
            playbook_name=playbook.name,
            playbook_id=playbook.id,
            playbook_version=playbook.version,
            first_step_id=first_step_id,
            step_function_map=step_function_map,
        )

        return handler_code

    def generate_lambda_code(self, playbook: Playbook) -> str:
        """Generate complete Lambda function code for a playbook.

        Combines all generated code into a single Python module:
        - File header with metadata
        - Import statements
        - Helper functions
        - Step functions
        - Main Lambda handler

        Args:
            playbook: The playbook to generate code for

        Returns:
            Complete Python source code as a string
        """
        # Validate playbook first
        is_valid, errors = playbook.validate()
        if not is_valid:
            raise ValueError(f"Invalid playbook: {', '.join(errors)}")

        # Generate code sections
        sections = []

        # 1. File header
        header = FILE_HEADER_TEMPLATE.format(
            playbook_name=playbook.name,
            playbook_id=playbook.id,
            playbook_version=playbook.version,
            author=playbook.author,
            generated_at=datetime.now(timezone.utc).isoformat(),
            description=playbook.description.replace("\n", "\n    "),
        )
        sections.append(header)

        # 2. Helper functions
        sections.append(RENDER_TEMPLATE_FUNCTION)
        sections.append(GET_PROVIDER_CLIENT_FUNCTION)

        # 3. Step functions
        for step in playbook.steps:
            step_code = self.generate_step_function(step)
            sections.append(step_code)

        # 4. Main handler
        handler_code = self.generate_main_handler(playbook)
        sections.append(handler_code)

        # Combine all sections
        full_code = "\n".join(sections)

        # Try to format with black if available
        try:
            import black
            mode = black.Mode(line_length=100)
            full_code = black.format_str(full_code, mode=mode)
        except ImportError:
            pass  # black not available, skip formatting
        except Exception as e:
            logger.warning(f"Code formatting failed: {e}")

        return full_code

    def validate_generated_code(self, code: str) -> Tuple[bool, List[str]]:
        """Validate generated code for syntax and security.

        Checks:
        - Python syntax is valid (using ast.parse)
        - No dangerous patterns are present
        - No unsafe function calls

        Args:
            code: Python code to validate

        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []

        # Check syntax
        try:
            ast.parse(code)
        except SyntaxError as e:
            issues.append(f"Syntax error at line {e.lineno}: {e.msg}")
            return False, issues

        # Check for dangerous patterns
        for pattern, message in DANGEROUS_PATTERNS:
            if re.search(pattern, code):
                issues.append(f"Security issue: {message}")

        # Additional AST-based checks
        try:
            tree = ast.parse(code)
            visitor = SecurityVisitor()
            visitor.visit(tree)
            issues.extend(visitor.issues)
        except Exception as e:
            logger.warning(f"AST security check failed: {e}")

        return len(issues) == 0, issues

    def generate_custom_action(self, step: PlaybookStep) -> str:
        """Generate code for a custom action using LLM.

        For CUSTOM action types, uses the LLM provider to generate
        appropriate code based on the step parameters.

        Args:
            step: The custom step to generate code for

        Returns:
            Generated Python function code
        """
        if not self.llm_provider:
            logger.warning("No LLM provider configured for custom action generation")
            return self._generate_fallback_step(step)

        # Build prompt for LLM
        prompt = f"""Generate a Python function for a security automation step.

Step Name: {step.name}
Action Type: Custom
Parameters: {step.parameters}

Requirements:
1. Function signature: def step_{self._sanitize_identifier(step.id)}(context: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]
2. Must return a dict with keys: success (bool), output (dict), error (optional str), next_step_id (optional str)
3. Must handle dry_run mode (log but don't execute)
4. Include proper error handling with try/except
5. Use logger for all logging (already imported)
6. Do NOT use eval, exec, subprocess with shell=True, or other unsafe functions

Return only the function code, no markdown or explanations.
"""

        try:
            response = self.llm_provider.generate(prompt)
            generated_code = response.strip()

            # Validate the generated code
            is_valid, issues = self.validate_generated_code(generated_code)
            if not is_valid:
                logger.error(f"Generated custom action code failed validation: {issues}")
                return self._generate_fallback_step(step)

            return generated_code
        except Exception as e:
            logger.error(f"Custom action generation failed: {e}")
            return self._generate_fallback_step(step)

    def _sanitize_identifier(self, identifier: str) -> str:
        """Sanitize a string to be a valid Python identifier.

        Args:
            identifier: String to sanitize

        Returns:
            Valid Python identifier
        """
        # Replace non-alphanumeric characters with underscores
        sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', identifier)
        # Ensure it doesn't start with a number
        if sanitized and sanitized[0].isdigit():
            sanitized = '_' + sanitized
        # Ensure it's not empty
        if not sanitized:
            sanitized = '_unnamed'
        return sanitized


class SecurityVisitor(ast.NodeVisitor):
    """AST visitor to check for security issues in generated code."""

    def __init__(self):
        self.issues: List[str] = []
        self._dangerous_calls: Set[str] = {
            'eval', 'exec', 'compile', '__import__',
            'getattr', 'setattr', 'delattr',
        }
        self._dangerous_modules: Set[str] = {
            'subprocess', 'os', 'sys', 'pickle', 'marshal',
        }

    def visit_Call(self, node: ast.Call) -> Any:
        """Check function calls for dangerous patterns."""
        # Check direct function calls
        if isinstance(node.func, ast.Name):
            if node.func.id in self._dangerous_calls:
                self.issues.append(f"Dangerous function call: {node.func.id}()")

        # Check module.function calls
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                module = node.func.value.id
                if module in self._dangerous_modules:
                    # Allow certain safe patterns
                    if module == 'os' and node.func.attr in ['path', 'environ']:
                        pass  # os.path and os.environ are generally safe
                    elif module == 'subprocess' and node.func.attr == 'run':
                        # Check if shell=True
                        for keyword in node.keywords:
                            if keyword.arg == 'shell':
                                if isinstance(keyword.value, ast.Constant) and keyword.value.value:
                                    self.issues.append("subprocess with shell=True is dangerous")
                    else:
                        self.issues.append(f"Potentially dangerous call: {module}.{node.func.attr}()")

        self.generic_visit(node)
        return node

    def visit_Import(self, node: ast.Import) -> Any:
        """Check imports for dangerous modules."""
        for alias in node.names:
            if alias.name in self._dangerous_modules:
                # Allow os for path operations
                if alias.name not in ['os', 'sys']:
                    self.issues.append(f"Import of potentially dangerous module: {alias.name}")
        self.generic_visit(node)
        return node

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        """Check from imports for dangerous patterns."""
        if node.module in self._dangerous_modules:
            if node.module not in ['os', 'sys']:
                self.issues.append(f"Import from potentially dangerous module: {node.module}")
        self.generic_visit(node)
        return node


def generate_playbook_code(playbook: Playbook, llm_provider=None) -> str:
    """Convenience function to generate Lambda code from a playbook.

    Args:
        playbook: The playbook to generate code for
        llm_provider: Optional LLM provider for custom actions

    Returns:
        Complete Python source code
    """
    generator = PlaybookCodeGenerator(llm_provider=llm_provider)
    return generator.generate_lambda_code(playbook)


def validate_playbook_code(code: str) -> Tuple[bool, List[str]]:
    """Convenience function to validate generated playbook code.

    Args:
        code: Python code to validate

    Returns:
        Tuple of (is_valid, list_of_issues)
    """
    generator = PlaybookCodeGenerator()
    return generator.validate_generated_code(code)
