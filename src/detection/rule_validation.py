"""
Detection Rule Validation Framework for ThreatSight Pipeline

Validates detection rules for syntax, performance, and quality.
Includes automated testing, false positive analysis, and rule optimization.
"""

import yaml
import json
import re
import ast
import time
import logging
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from pathlib import Path
import hashlib
from abc import ABC, abstractmethod

class ValidationSeverity(Enum):
    """Validation issue severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class RuleType(Enum):
    """Types of detection rules"""
    SIGMA = "sigma"
    YARA = "yara"
    SURICATA = "suricata"
    SNORT = "snort"
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    SENTINEL = "sentinel"

@dataclass
class ValidationIssue:
    """Validation issue details"""
    rule_id: str
    issue_type: str
    severity: ValidationSeverity
    message: str
    location: Optional[str] = None
    suggestion: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ValidationResult:
    """Rule validation result"""
    rule_id: str
    rule_type: RuleType
    is_valid: bool
    quality_score: float
    issues: List[ValidationIssue] = field(default_factory=list)
    performance_metrics: Dict[str, Any] = field(default_factory=dict)
    test_results: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class TestCase:
    """Test case for rule validation"""
    name: str
    description: str
    test_data: Any
    expected_result: bool
    test_type: str = "detection"
    metadata: Dict[str, Any] = field(default_factory=dict)

class RuleValidator(ABC):
    """Abstract base class for rule validators"""
    
    @abstractmethod
    def validate_syntax(self, rule_content: str) -> List[ValidationIssue]:
        """Validate rule syntax"""
        pass
    
    @abstractmethod
    def validate_performance(self, rule_content: str) -> Dict[str, Any]:
        """Validate rule performance characteristics"""
        pass
    
    @abstractmethod
    def generate_test_cases(self, rule_content: str) -> List[TestCase]:
        """Generate test cases for the rule"""
        pass

class SigmaValidator(RuleValidator):
    """Validator for Sigma rules"""
    
    def __init__(self):
        self.required_fields = ['title', 'id', 'description', 'logsource', 'detection']
        self.optional_fields = ['author', 'date', 'references', 'tags', 'level', 'status']
        self.valid_levels = ['low', 'medium', 'high', 'critical']
        self.valid_statuses = ['stable', 'test', 'experimental', 'deprecated']
    
    def validate_syntax(self, rule_content: str) -> List[ValidationIssue]:
        """Validate Sigma rule syntax"""
        issues = []
        
        try:
            # Parse YAML
            rule_data = yaml.safe_load(rule_content)
            if not isinstance(rule_data, dict):
                issues.append(ValidationIssue(
                    rule_id="unknown",
                    issue_type="syntax_error",
                    severity=ValidationSeverity.CRITICAL,
                    message="Rule is not a valid YAML dictionary"
                ))
                return issues
            
            rule_id = rule_data.get('id', 'unknown')
            
            # Check required fields
            for field in self.required_fields:
                if field not in rule_data:
                    issues.append(ValidationIssue(
                        rule_id=rule_id,
                        issue_type="missing_field",
                        severity=ValidationSeverity.ERROR,
                        message=f"Missing required field: {field}",
                        suggestion=f"Add {field} field to the rule"
                    ))
            
            # Validate detection logic
            if 'detection' in rule_data:
                detection_issues = self._validate_detection_logic(rule_data['detection'], rule_id)
                issues.extend(detection_issues)
            
            # Validate level
            if 'level' in rule_data:
                if rule_data['level'] not in self.valid_levels:
                    issues.append(ValidationIssue(
                        rule_id=rule_id,
                        issue_type="invalid_level",
                        severity=ValidationSeverity.WARNING,
                        message=f"Invalid level: {rule_data['level']}",
                        suggestion=f"Use one of: {', '.join(self.valid_levels)}"
                    ))
            
            # Validate status
            if 'status' in rule_data:
                if rule_data['status'] not in self.valid_statuses:
                    issues.append(ValidationIssue(
                        rule_id=rule_id,
                        issue_type="invalid_status",
                        severity=ValidationSeverity.WARNING,
                        message=f"Invalid status: {rule_data['status']}",
                        suggestion=f"Use one of: {', '.join(self.valid_statuses)}"
                    ))
            
            # Validate ID format (should be UUID)
            if 'id' in rule_data:
                id_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                if not re.match(id_pattern, rule_data['id'], re.IGNORECASE):
                    issues.append(ValidationIssue(
                        rule_id=rule_id,
                        issue_type="invalid_id_format",
                        severity=ValidationSeverity.WARNING,
                        message="Rule ID is not a valid UUID format",
                        suggestion="Use UUID format for rule ID"
                    ))
            
        except yaml.YAMLError as e:
            issues.append(ValidationIssue(
                rule_id="unknown",
                issue_type="yaml_parse_error",
                severity=ValidationSeverity.CRITICAL,
                message=f"YAML parsing error: {str(e)}"
            ))
        
        return issues
    
    def _validate_detection_logic(self, detection: Dict[str, Any], rule_id: str) -> List[ValidationIssue]:
        """Validate Sigma detection logic"""
        issues = []
        
        if 'condition' not in detection:
            issues.append(ValidationIssue(
                rule_id=rule_id,
                issue_type="missing_condition",
                severity=ValidationSeverity.ERROR,
                message="Detection is missing condition field"
            ))
            return issues
        
        condition = detection['condition']
        
        # Check for performance issues
        if condition.count('*') > 3:
            issues.append(ValidationIssue(
                rule_id=rule_id,
                issue_type="performance_warning",
                severity=ValidationSeverity.WARNING,
                message="Too many wildcards in condition may impact performance",
                suggestion="Consider using more specific patterns"
            ))
        
        # Check for overly broad conditions
        if condition.strip() in ['1 of them', 'any of them']:
            issues.append(ValidationIssue(
                rule_id=rule_id,
                issue_type="broad_condition",
                severity=ValidationSeverity.WARNING,
                message="Condition is very broad and may cause false positives",
                suggestion="Use more specific conditions"
            ))
        
        # Validate selection references in condition
        referenced_selections = re.findall(r'\\b(\\w+)\\b', condition)
        for ref in referenced_selections:
            if ref not in ['and', 'or', 'not', 'of', 'them', 'all', 'any'] and ref not in detection:
                issues.append(ValidationIssue(
                    rule_id=rule_id,
                    issue_type="undefined_selection",
                    severity=ValidationSeverity.ERROR,
                    message=f"Condition references undefined selection: {ref}",
                    suggestion=f"Define selection '{ref}' or remove from condition"
                ))
        
        return issues
    
    def validate_performance(self, rule_content: str) -> Dict[str, Any]:
        """Validate Sigma rule performance characteristics"""
        metrics = {
            'estimated_performance': 'unknown',
            'complexity_score': 0,
            'field_count': 0,
            'wildcard_count': 0,
            'performance_warnings': []
        }
        
        try:
            rule_data = yaml.safe_load(rule_content)
            detection = rule_data.get('detection', {})
            
            # Count fields and complexity
            field_count = 0
            wildcard_count = 0
            
            for key, value in detection.items():
                if key != 'condition':
                    if isinstance(value, dict):
                        field_count += len(value)
                        for field_value in value.values():
                            if isinstance(field_value, str) and '*' in field_value:
                                wildcard_count += field_value.count('*')
            
            metrics['field_count'] = field_count
            metrics['wildcard_count'] = wildcard_count
            
            # Calculate complexity score
            complexity = field_count + (wildcard_count * 2)
            metrics['complexity_score'] = complexity
            
            # Estimate performance
            if complexity < 5:
                metrics['estimated_performance'] = 'good'
            elif complexity < 10:
                metrics['estimated_performance'] = 'fair'
            else:
                metrics['estimated_performance'] = 'poor'
                metrics['performance_warnings'].append("High complexity may impact performance")
            
            # Check for performance anti-patterns
            if wildcard_count > 5:
                metrics['performance_warnings'].append("Excessive wildcards detected")
            
            condition = detection.get('condition', '')
            if re.search(r'\\b1\\s+of\\s+them\\b', condition):
                metrics['performance_warnings'].append("Very broad condition detected")
            
        except Exception as e:
            metrics['performance_warnings'].append(f"Performance analysis failed: {str(e)}")
        
        return metrics
    
    def generate_test_cases(self, rule_content: str) -> List[TestCase]:
        """Generate test cases for Sigma rule"""
        test_cases = []
        
        try:
            rule_data = yaml.safe_load(rule_content)
            rule_id = rule_data.get('id', 'unknown')
            detection = rule_data.get('detection', {})
            
            # Generate positive test cases from selections
            for selection_name, selection_data in detection.items():
                if selection_name != 'condition' and isinstance(selection_data, dict):
                    test_case = TestCase(
                        name=f"positive_test_{selection_name}",
                        description=f"Test case for selection {selection_name}",
                        test_data=selection_data,
                        expected_result=True,
                        test_type="detection",
                        metadata={'rule_id': rule_id, 'selection': selection_name}
                    )
                    test_cases.append(test_case)
            
            # Generate negative test cases
            negative_test = TestCase(
                name="negative_test_benign",
                description="Test with benign data that should not trigger",
                test_data={'ProcessName': 'notepad.exe', 'CommandLine': 'notepad.exe document.txt'},
                expected_result=False,
                test_type="false_positive_check",
                metadata={'rule_id': rule_id}
            )
            test_cases.append(negative_test)
            
        except Exception as e:
            logging.warning(f"Failed to generate test cases: {str(e)}")
        
        return test_cases

class YaraValidator(RuleValidator):
    """Validator for YARA rules"""
    
    def __init__(self):
        self.required_sections = ['rule']
        self.valid_modifiers = ['ascii', 'wide', 'nocase', 'fullword', 'private', 'global']
    
    def validate_syntax(self, rule_content: str) -> List[ValidationIssue]:
        """Validate YARA rule syntax"""
        issues = []
        
        # Extract rule name
        rule_match = re.search(r'rule\\s+(\\w+)', rule_content)
        rule_id = rule_match.group(1) if rule_match else "unknown"
        
        # Basic syntax validation
        if not re.search(r'rule\\s+\\w+\\s*\\{', rule_content):
            issues.append(ValidationIssue(
                rule_id=rule_id,
                issue_type="syntax_error",
                severity=ValidationSeverity.CRITICAL,
                message="Rule declaration not found or malformed"
            ))
        
        # Check for balanced braces
        open_braces = rule_content.count('{')
        close_braces = rule_content.count('}')
        if open_braces != close_braces:
            issues.append(ValidationIssue(
                rule_id=rule_id,
                issue_type="unbalanced_braces",
                severity=ValidationSeverity.CRITICAL,
                message="Unbalanced braces in rule"
            ))
        
        # Validate strings section
        if 'strings:' in rule_content:
            string_issues = self._validate_yara_strings(rule_content, rule_id)
            issues.extend(string_issues)
        
        # Validate condition section
        condition_match = re.search(r'condition:\\s*([^}]+)', rule_content, re.DOTALL)
        if not condition_match:
            issues.append(ValidationIssue(
                rule_id=rule_id,
                issue_type="missing_condition",
                severity=ValidationSeverity.ERROR,
                message="Rule is missing condition section"
            ))
        else:
            condition_issues = self._validate_yara_condition(condition_match.group(1), rule_id)
            issues.extend(condition_issues)
        
        return issues
    
    def _validate_yara_strings(self, rule_content: str, rule_id: str) -> List[ValidationIssue]:
        """Validate YARA strings section"""
        issues = []
        
        # Find all string definitions
        string_patterns = re.findall(r'\\$\\w+\\s*=\\s*([^\\n]+)', rule_content)
        
        for i, pattern in enumerate(string_patterns):
            # Check for overly generic strings
            if len(pattern.strip('"{}')) < 4:
                issues.append(ValidationIssue(
                    rule_id=rule_id,
                    issue_type="short_string",
                    severity=ValidationSeverity.WARNING,
                    message=f"String {i+1} is very short and may cause false positives",
                    suggestion="Use longer, more specific strings"
                ))
            
            # Check for hex string validity
            if pattern.startswith('{') and pattern.endswith('}'):
                hex_content = pattern.strip('{}').replace(' ', '')
                if not re.match(r'^[0-9a-fA-F?]+$', hex_content):
                    issues.append(ValidationIssue(
                        rule_id=rule_id,
                        issue_type="invalid_hex_string",
                        severity=ValidationSeverity.ERROR,
                        message=f"Invalid hex string: {pattern}",
                        suggestion="Use valid hexadecimal characters (0-9, A-F, ?)"
                    ))
        
        return issues
    
    def _validate_yara_condition(self, condition: str, rule_id: str) -> List[ValidationIssue]:
        """Validate YARA condition"""
        issues = []
        
        condition = condition.strip()
        
        # Check for empty condition
        if not condition:
            issues.append(ValidationIssue(
                rule_id=rule_id,
                issue_type="empty_condition",
                severity=ValidationSeverity.ERROR,
                message="Condition is empty"
            ))
            return issues
        
        # Check for overly broad conditions
        if condition.strip() in ['true', '1', 'any of them']:
            issues.append(ValidationIssue(
                rule_id=rule_id,
                issue_type="broad_condition",
                severity=ValidationSeverity.WARNING,
                message="Condition is very broad and may cause false positives",
                suggestion="Use more specific conditions"
            ))
        
        # Check for string references
        string_refs = re.findall(r'\\$\\w+', condition)
        if not string_refs and 'filesize' not in condition and 'entrypoint' not in condition:
            issues.append(ValidationIssue(
                rule_id=rule_id,
                issue_type="no_string_references",
                severity=ValidationSeverity.WARNING,
                message="Condition doesn't reference any strings",
                suggestion="Include string references in condition"
            ))
        
        return issues
    
    def validate_performance(self, rule_content: str) -> Dict[str, Any]:
        """Validate YARA rule performance characteristics"""
        metrics = {
            'estimated_performance': 'unknown',
            'string_count': 0,
            'avg_string_length': 0,
            'has_wildcards': False,
            'performance_warnings': []
        }
        
        try:
            # Count strings
            string_patterns = re.findall(r'\\$\\w+\\s*=\\s*([^\\n]+)', rule_content)
            metrics['string_count'] = len(string_patterns)
            
            # Calculate average string length
            if string_patterns:
                total_length = sum(len(s.strip('"{}')) for s in string_patterns)
                metrics['avg_string_length'] = total_length / len(string_patterns)
            
            # Check for wildcards in hex strings
            for pattern in string_patterns:
                if '?' in pattern:
                    metrics['has_wildcards'] = True
                    break
            
            # Estimate performance
            if metrics['string_count'] < 5 and metrics['avg_string_length'] > 8:
                metrics['estimated_performance'] = 'good'
            elif metrics['string_count'] < 10:
                metrics['estimated_performance'] = 'fair'
            else:
                metrics['estimated_performance'] = 'poor'
                metrics['performance_warnings'].append("Many strings may impact performance")
            
            if metrics['has_wildcards']:
                metrics['performance_warnings'].append("Wildcards in hex strings may slow matching")
            
        except Exception as e:
            metrics['performance_warnings'].append(f"Performance analysis failed: {str(e)}")
        
        return metrics
    
    def generate_test_cases(self, rule_content: str) -> List[TestCase]:
        """Generate test cases for YARA rule"""
        test_cases = []
        
        try:
            # Extract rule name
            rule_match = re.search(r'rule\\s+(\\w+)', rule_content)
            rule_id = rule_match.group(1) if rule_match else "unknown"
            
            # Generate test case for malware detection
            test_case = TestCase(
                name="malware_detection_test",
                description="Test YARA rule against sample malware",
                test_data={"file_type": "pe", "size": 100000},
                expected_result=True,
                test_type="detection",
                metadata={'rule_id': rule_id}
            )
            test_cases.append(test_case)
            
            # Generate false positive test
            fp_test = TestCase(
                name="false_positive_test",
                description="Test against benign files",
                test_data={"file_type": "pe", "size": 50000, "is_signed": True},
                expected_result=False,
                test_type="false_positive_check",
                metadata={'rule_id': rule_id}
            )
            test_cases.append(fp_test)
            
        except Exception as e:
            logging.warning(f"Failed to generate YARA test cases: {str(e)}")
        
        return test_cases

class NetworkRuleValidator(RuleValidator):
    """Validator for network rules (Suricata/Snort)"""
    
    def __init__(self):
        self.valid_actions = ['alert', 'pass', 'drop', 'reject', 'log']
        self.valid_protocols = ['tcp', 'udp', 'icmp', 'http', 'ftp', 'tls', 'ssh', 'dns']
        self.valid_directions = ['->', '<-', '<>']
    
    def validate_syntax(self, rule_content: str) -> List[ValidationIssue]:
        """Validate network rule syntax"""
        issues = []
        
        # Parse rule components
        rule_match = re.match(
            r'(\\w+)\\s+(\\w+)\\s+([\\w\\.,!]+)\\s+([\\w\\.,!]+)\\s+(<>|->|<-)\\s+([\\w\\.,!]+)\\s+([\\w\\.,!\\[\\]]+)\\s*\\((.*)\\)',
            rule_content.strip()
        )
        
        if not rule_match:
            issues.append(ValidationIssue(
                rule_id="unknown",
                issue_type="syntax_error",
                severity=ValidationSeverity.CRITICAL,
                message="Rule syntax is invalid"
            ))
            return issues
        
        action, protocol, src_ip, src_port, direction, dst_ip, dst_port, options = rule_match.groups()
        
        # Extract SID for rule identification
        sid_match = re.search(r'sid:\\s*(\\d+)', options)
        rule_id = sid_match.group(1) if sid_match else "unknown"
        
        # Validate action
        if action not in self.valid_actions:
            issues.append(ValidationIssue(
                rule_id=rule_id,
                issue_type="invalid_action",
                severity=ValidationSeverity.ERROR,
                message=f"Invalid action: {action}",
                suggestion=f"Use one of: {', '.join(self.valid_actions)}"
            ))
        
        # Validate protocol
        if protocol not in self.valid_protocols:
            issues.append(ValidationIssue(
                rule_id=rule_id,
                issue_type="invalid_protocol",
                severity=ValidationSeverity.ERROR,
                message=f"Invalid protocol: {protocol}",
                suggestion=f"Use one of: {', '.join(self.valid_protocols)}"
            ))
        
        # Validate direction
        if direction not in self.valid_directions:
            issues.append(ValidationIssue(
                rule_id=rule_id,
                issue_type="invalid_direction",
                severity=ValidationSeverity.ERROR,
                message=f"Invalid direction: {direction}",
                suggestion=f"Use one of: {', '.join(self.valid_directions)}"
            ))
        
        # Validate required options
        required_options = ['msg', 'sid']
        for opt in required_options:
            if f'{opt}:' not in options:
                issues.append(ValidationIssue(
                    rule_id=rule_id,
                    issue_type="missing_option",
                    severity=ValidationSeverity.ERROR,
                    message=f"Missing required option: {opt}"
                ))
        
        return issues
    
    def validate_performance(self, rule_content: str) -> Dict[str, Any]:
        """Validate network rule performance characteristics"""
        metrics = {
            'estimated_performance': 'good',
            'content_matches': 0,
            'pcre_patterns': 0,
            'performance_warnings': []
        }
        
        # Count content matches and PCRE patterns
        metrics['content_matches'] = rule_content.count('content:')
        metrics['pcre_patterns'] = rule_content.count('pcre:')
        
        # Performance warnings
        if metrics['content_matches'] > 5:
            metrics['performance_warnings'].append("Many content matches may impact performance")
            metrics['estimated_performance'] = 'fair'
        
        if metrics['pcre_patterns'] > 2:
            metrics['performance_warnings'].append("Multiple PCRE patterns may be slow")
            metrics['estimated_performance'] = 'poor'
        
        return metrics
    
    def generate_test_cases(self, rule_content: str) -> List[TestCase]:
        """Generate test cases for network rule"""
        test_cases = []
        
        # Extract SID
        sid_match = re.search(r'sid:\\s*(\\d+)', rule_content)
        rule_id = sid_match.group(1) if sid_match else "unknown"
        
        # Generate positive test case
        test_case = TestCase(
            name="network_detection_test",
            description="Test network rule detection",
            test_data={"packet_type": "tcp", "payload": "malicious_string"},
            expected_result=True,
            test_type="detection",
            metadata={'rule_id': rule_id}
        )
        test_cases.append(test_case)
        
        return test_cases

class RuleValidationFramework:
    """Main rule validation framework"""
    
    def __init__(self):
        self.validators = {
            RuleType.SIGMA: SigmaValidator(),
            RuleType.YARA: YaraValidator(),
            RuleType.SURICATA: NetworkRuleValidator(),
            RuleType.SNORT: NetworkRuleValidator()
        }
        self.logger = logging.getLogger(__name__)
    
    def validate_rule(self, rule_content: str, rule_type: RuleType, 
                     rule_id: Optional[str] = None) -> ValidationResult:
        """Validate a detection rule"""
        try:
            if rule_type not in self.validators:
                return ValidationResult(
                    rule_id=rule_id or "unknown",
                    rule_type=rule_type,
                    is_valid=False,
                    quality_score=0.0,
                    issues=[ValidationIssue(
                        rule_id=rule_id or "unknown",
                        issue_type="unsupported_type",
                        severity=ValidationSeverity.CRITICAL,
                        message=f"Unsupported rule type: {rule_type.value}"
                    )]
                )
            
            validator = self.validators[rule_type]
            
            # Perform syntax validation
            syntax_issues = validator.validate_syntax(rule_content)
            
            # Perform performance validation
            performance_metrics = validator.validate_performance(rule_content)
            
            # Generate test cases
            test_cases = validator.generate_test_cases(rule_content)
            
            # Calculate quality score
            quality_score = self._calculate_quality_score(syntax_issues, performance_metrics)
            
            # Determine if rule is valid
            critical_errors = [i for i in syntax_issues if i.severity == ValidationSeverity.CRITICAL]
            errors = [i for i in syntax_issues if i.severity == ValidationSeverity.ERROR]
            is_valid = len(critical_errors) == 0 and len(errors) == 0
            
            # Extract rule ID if not provided
            if not rule_id:
                rule_id = self._extract_rule_id(rule_content, rule_type)
            
            return ValidationResult(
                rule_id=rule_id,
                rule_type=rule_type,
                is_valid=is_valid,
                quality_score=quality_score,
                issues=syntax_issues,
                performance_metrics=performance_metrics,
                test_results={'test_cases': [tc.__dict__ for tc in test_cases]},
                metadata={
                    'validation_timestamp': datetime.now().isoformat(),
                    'validator_version': '1.0'
                }
            )
            
        except Exception as e:
            self.logger.error(f"Validation error: {str(e)}")
            return ValidationResult(
                rule_id=rule_id or "unknown",
                rule_type=rule_type,
                is_valid=False,
                quality_score=0.0,
                issues=[ValidationIssue(
                    rule_id=rule_id or "unknown",
                    issue_type="validation_error",
                    severity=ValidationSeverity.CRITICAL,
                    message=f"Validation failed: {str(e)}"
                )]
            )
    
    def _extract_rule_id(self, rule_content: str, rule_type: RuleType) -> str:
        """Extract rule ID from rule content"""
        if rule_type == RuleType.SIGMA:
            try:
                rule_data = yaml.safe_load(rule_content)
                return rule_data.get('id', 'unknown')
            except:
                return 'unknown'
        
        elif rule_type == RuleType.YARA:
            rule_match = re.search(r'rule\\s+(\\w+)', rule_content)
            return rule_match.group(1) if rule_match else 'unknown'
        
        elif rule_type in [RuleType.SURICATA, RuleType.SNORT]:
            sid_match = re.search(r'sid:\\s*(\\d+)', rule_content)
            return sid_match.group(1) if sid_match else 'unknown'
        
        return 'unknown'
    
    def _calculate_quality_score(self, issues: List[ValidationIssue], 
                                performance_metrics: Dict[str, Any]) -> float:
        """Calculate rule quality score"""
        base_score = 100.0
        
        # Deduct points for issues
        for issue in issues:
            if issue.severity == ValidationSeverity.CRITICAL:
                base_score -= 30
            elif issue.severity == ValidationSeverity.ERROR:
                base_score -= 20
            elif issue.severity == ValidationSeverity.WARNING:
                base_score -= 10
            elif issue.severity == ValidationSeverity.INFO:
                base_score -= 5
        
        # Adjust for performance
        performance = performance_metrics.get('estimated_performance', 'unknown')
        if performance == 'poor':
            base_score -= 15
        elif performance == 'fair':
            base_score -= 5
        
        # Performance warnings
        warning_count = len(performance_metrics.get('performance_warnings', []))
        base_score -= warning_count * 3
        
        return max(0.0, min(100.0, base_score))
    
    def validate_batch_rules(self, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate multiple rules"""
        results = {
            'validation_results': [],
            'statistics': {
                'total_rules': len(rules),
                'valid_rules': 0,
                'invalid_rules': 0,
                'average_quality_score': 0.0,
                'by_type': {},
                'by_severity': {
                    'critical': 0,
                    'error': 0,
                    'warning': 0,
                    'info': 0
                }
            }
        }
        
        total_quality = 0.0
        
        for rule_info in rules:
            rule_content = rule_info.get('content', '')
            rule_type = RuleType(rule_info.get('type', 'sigma'))
            rule_id = rule_info.get('id')
            
            validation_result = self.validate_rule(rule_content, rule_type, rule_id)
            results['validation_results'].append(validation_result)
            
            # Update statistics
            if validation_result.is_valid:
                results['statistics']['valid_rules'] += 1
            else:
                results['statistics']['invalid_rules'] += 1
            
            total_quality += validation_result.quality_score
            
            # Count by type
            type_name = rule_type.value
            results['statistics']['by_type'][type_name] = \
                results['statistics']['by_type'].get(type_name, 0) + 1
            
            # Count by severity
            for issue in validation_result.issues:
                results['statistics']['by_severity'][issue.severity.value] += 1
        
        # Calculate average quality score
        if len(rules) > 0:
            results['statistics']['average_quality_score'] = total_quality / len(rules)
        
        return results
    
    def export_validation_report(self, validation_results: Dict[str, Any], 
                                output_path: str = "validation_report.json") -> bool:
        """Export validation report to file"""
        try:
            # Convert dataclass objects to dictionaries for JSON serialization
            serializable_results = {
                'validation_results': [],
                'statistics': validation_results['statistics'],
                'generated_at': datetime.now().isoformat()
            }
            
            for result in validation_results['validation_results']:
                if isinstance(result, ValidationResult):
                    result_dict = {
                        'rule_id': result.rule_id,
                        'rule_type': result.rule_type.value,
                        'is_valid': result.is_valid,
                        'quality_score': result.quality_score,
                        'issues': [
                            {
                                'rule_id': issue.rule_id,
                                'issue_type': issue.issue_type,
                                'severity': issue.severity.value,
                                'message': issue.message,
                                'location': issue.location,
                                'suggestion': issue.suggestion,
                                'metadata': issue.metadata
                            }
                            for issue in result.issues
                        ],
                        'performance_metrics': result.performance_metrics,
                        'test_results': result.test_results,
                        'metadata': result.metadata
                    }
                else:
                    result_dict = result
                
                serializable_results['validation_results'].append(result_dict)
            
            with open(output_path, 'w') as f:
                json.dump(serializable_results, f, indent=2)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export validation report: {str(e)}")
            return False

# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Sample Sigma rule for testing
    sample_sigma_rule = """
title: Malicious PowerShell Execution
id: 12345678-1234-1234-1234-123456789012
description: Detects suspicious PowerShell command execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\powershell.exe'
        CommandLine|contains: 'DownloadString'
    condition: selection
level: high
status: experimental
"""
    
    # Initialize validation framework
    validator = RuleValidationFramework()
    
    # Validate the rule
    result = validator.validate_rule(sample_sigma_rule, RuleType.SIGMA)
    
    print(f"Rule ID: {result.rule_id}")
    print(f"Is Valid: {result.is_valid}")
    print(f"Quality Score: {result.quality_score:.1f}")
    print(f"Issues Found: {len(result.issues)}")
    
    for issue in result.issues:
        print(f"  - {issue.severity.value}: {issue.message}")
    
    print(f"Performance: {result.performance_metrics.get('estimated_performance', 'unknown')}")