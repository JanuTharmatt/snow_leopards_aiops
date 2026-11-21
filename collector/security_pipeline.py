"""
Security Pipeline Module for Privacy-First AIOps Observability Platform (Phase 1).
Inspects incoming raw application logs and telemetry, detecting and redacting sensitive data:
- Passwords
- API Keys
- Email Addresses
- Credit Card Numbers
- Personal Names (simple regex-based detection)
"""

from typing import Any, Dict, List, Tuple, Union
import regex as re
from pydantic import BaseModel

try:
    from .config import SecurityRegexConfig
except (ImportError, ValueError):
    from config import SecurityRegexConfig


class SecurityPipeline:
    """
    High-assurance security filter for privacy-first observability.
    Guarantees no sensitive PII or credentials leave the local perimeter.
    """

    def __init__(self):
        self.header_patterns = SecurityRegexConfig.HEADER_LINE_PATTERNS
        self.inline_patterns = SecurityRegexConfig.INLINE_PATTERNS

    def redact_text(self, text: str) -> Tuple[str, List[str]]:
        """
        Redacts sensitive data from raw log strings.
        Supports both line-level credential scrubbing and inline token masking.

        Returns:
            Tuple of (redacted_text, list_of_detections)
        """
        if not text:
            return "", []

        detections: List[str] = []
        modified = text

        # Step 1: Detect and strip dedicated sensitive header lines
        # (e.g., 'User: Manik Sharma', 'Password: abc123', 'API_KEY: abc-xyz-123')
        for category, pattern in self.header_patterns.items():
            if pattern.search(modified):
                detections.append(category)
                modified = pattern.sub("", modified)

        # Step 2: Detect and mask inline occurrences (emails, credit cards, inline keys)
        # 2a. Emails
        if self.inline_patterns["EMAIL"].search(modified):
            detections.append("EMAIL")
            modified = self.inline_patterns["EMAIL"].sub("[REDACTED_EMAIL]", modified)

        # 2b. Credit Cards (13-19 digits, hyphens/spaces allowed)
        if self.inline_patterns["CREDIT_CARD"].search(modified):
            detections.append("CREDIT_CARD")
            modified = self.inline_patterns["CREDIT_CARD"].sub("[REDACTED_CREDIT_CARD]", modified)

        # 2c. Inline API Keys
        if self.inline_patterns["API_KEY"].search(modified):
            detections.append("API_KEY")
            modified = self.inline_patterns["API_KEY"].sub(r"\g<0>".split(":")[0] + ": [REDACTED_API_KEY]", modified)

        # 2d. Inline Passwords
        if self.inline_patterns["PASSWORD"].search(modified):
            detections.append("PASSWORD")
            modified = self.inline_patterns["PASSWORD"].sub(r"\g<0>".split(":")[0] + ": [REDACTED_PASSWORD]", modified)

        # 2e. Inline Personal Names
        if self.inline_patterns["NAME"].search(modified):
            detections.append("NAME")
            modified = self.inline_patterns["NAME"].sub(r"\g<0>".split(":")[0] + ": [REDACTED_NAME]", modified)

        # Step 3: Normalize whitespace and clean up empty lines caused by line-level removals
        cleaned_lines = [line.strip() for line in modified.splitlines() if line.strip()]
        result = "\n".join(cleaned_lines)

        return result, list(set(detections))

    def redact_dict(self, data: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
        """
        Recursively inspects and redacts dictionary structures (e.g. JSON payloads).
        Redacts sensitive field names and values.
        """
        sensitive_key_fragments = (
            "password", "passwd", "pwd", "secret", "token", "api_key",
            "apikey", "credit_card", "cc", "auth", "bearer"
        )
        detections: List[str] = []
        cleaned: Dict[str, Any] = {}

        for key, value in data.items():
            key_lower = str(key).lower()
            if any(frag in key_lower for frag in sensitive_key_fragments):
                cleaned[key] = "[REDACTED]"
                detections.append(f"KEY:{key}")
            elif isinstance(value, dict):
                sub_dict, sub_detections = self.redact_dict(value)
                cleaned[key] = sub_dict
                detections.extend(sub_detections)
            elif isinstance(value, list):
                cleaned_list = []
                for item in value:
                    if isinstance(item, dict):
                        sub_dict, sub_detections = self.redact_dict(item)
                        cleaned_list.append(sub_dict)
                        detections.extend(sub_detections)
                    elif isinstance(item, str):
                        redacted_str, str_detections = self.redact_text(item)
                        cleaned_list.append(redacted_str)
                        detections.extend(str_detections)
                    else:
                        cleaned_list.append(item)
                cleaned[key] = cleaned_list
            elif isinstance(value, str):
                redacted_str, str_detections = self.redact_text(value)
                cleaned[key] = redacted_str
                detections.extend(str_detections)
            else:
                cleaned[key] = value

        return cleaned, list(set(detections))

    def process(self, raw_input: Union[str, Dict[str, Any], BaseModel]) -> Tuple[Any, List[str]]:
        """
        Unified entrypoint for the Security Pipeline.
        Handles strings, dictionaries, or Pydantic models.
        """
        if isinstance(raw_input, BaseModel):
            dict_data = raw_input.model_dump()
            return self.redact_dict(dict_data)
        elif isinstance(raw_input, dict):
            return self.redact_dict(raw_input)
        elif isinstance(raw_input, str):
            return self.redact_text(raw_input)
        else:
            return str(raw_input), []


# Singleton instance for pipeline consumption
security_pipeline = SecurityPipeline()
