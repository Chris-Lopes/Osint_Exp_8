"""
YARA Rule Generation Engine for ThreatSight Pipeline

Generates high-quality YARA detection rules from malware samples and threat intelligence.
Supports malware family pattern recognition, string extraction, and condition optimization.
"""
import hashlib
import re
import magic
import pefile
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import logging
from collections import Counter

class FileType(Enum):
    """Supported file types for YARA rule generation"""
    PE = "pe"
    ELF = "elf" 
    MACHO = "macho"
    SCRIPT = "script"
    DOCUMENT = "document"
    ARCHIVE = "archive"
    UNKNOWN = "unknown"

class StringType(Enum):
    """Types of strings for YARA rules"""
    TEXT = "text"
    HEX = "hex"
    REGEX = "regex"
    WIDE = "wide"

@dataclass
class YaraString:
    """YARA string definition"""
    name: str
    value: str
    string_type: StringType
    modifiers: List[str] = field(default_factory=list)
    condition_weight: float = 1.0
    false_positive_risk: float = 0.0
    
    def to_yara_format(self) -> str:
        """Convert to YARA string format"""
        if self.string_type == StringType.TEXT:
            formatted_value = f'"{self.value}"'
        elif self.string_type == StringType.HEX:
            formatted_value = f"{{{self.value}}}"
        elif self.string_type == StringType.REGEX:
            formatted_value = f"/{self.value}/"
        else:
            formatted_value = f'"{self.value}"'
        
        # Add modifiers
        if self.modifiers:
            modifiers_str = " " + " ".join(self.modifiers)
            return f"${self.name} = {formatted_value}{modifiers_str}"
        
        return f"${self.name} = {formatted_value}"

@dataclass
class YaraRule:
    """Generated YARA rule structure"""
    name: str
    tags: List[str]
    meta: Dict[str, str]
    strings: List[YaraString]
    condition: str
    
    def to_yara_format(self) -> str:
        """Convert rule to YARA format"""
        lines = []
        
        # Rule header
        if self.tags:
            tag_str = " : " + " ".join(self.tags)
            lines.append(f"rule {self.name}{tag_str} {{")
        else:
            lines.append(f"rule {self.name} {{")
        
        # Meta section
        if self.meta:
            lines.append("    meta:")
            for key, value in self.meta.items():
                if isinstance(value, str):
                    lines.append(f'        {key} = "{value}"')
                else:
                    lines.append(f'        {key} = {value}')
        
        # Strings section
        if self.strings:
            lines.append("    strings:")
            for string_obj in self.strings:
                lines.append(f"        {string_obj.to_yara_format()}")
        
        # Condition section
        lines.append("    condition:")
        lines.append(f"        {self.condition}")
        
        lines.append("}")
        return "\n".join(lines)

class StringExtractor:
    """Extracts meaningful strings from malware samples"""
    
    def __init__(self):
        self.min_string_length = 4
        self.max_string_length = 100
        self.common_strings = self._load_common_strings()
        self.suspicious_patterns = self._load_suspicious_patterns()
    
    def _load_common_strings(self) -> Set[str]:
        """Load common strings that should be filtered out"""
        return {
            "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
            "Microsoft", "Windows", "System", "Program Files",
            "temp", "tmp", "error", "debug", "test", "null", "void",
            "GetProcAddress", "LoadLibrary", "CreateFile", "WriteFile"
        }
    
    def _load_suspicious_patterns(self) -> Dict[str, float]:
        """Load suspicious string patterns with weights"""
        return {
            r'cmd\.exe|powershell\.exe|wscript\.exe': 8.0,
            r'\\\\\.\\pipe\\': 7.0,
            r'SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run': 9.0,
            r'HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER': 6.0,
            r'CreateRemoteThread|WriteProcessMemory|VirtualAlloc': 8.5,
            r'http://|https://|ftp://': 5.0,
            r'\.exe|\.dll|\.bat|\.ps1|\.vbs': 4.0,
            r'base64|Base64': 6.0,
            r'eval\s*\(|execute\s*\(|exec\s*\(': 7.5,
            r'password|passwd|pwd': 5.5,
            r'bot|rat|backdoor|trojan': 9.0,
            r'encrypt|decrypt|crypt': 6.5,
            r'keylog|screenshot|webcam': 8.0
        }
    
    def extract_strings(self, file_data: bytes, file_type: FileType) -> List[YaraString]:
        """Extract strings from malware sample"""
        all_strings = []
        
        # Extract ASCII strings
        ascii_strings = self._extract_ascii_strings(file_data)
        all_strings.extend(ascii_strings)
        
        # Extract Unicode strings
        unicode_strings = self._extract_unicode_strings(file_data)
        all_strings.extend(unicode_strings)
        
        # Extract hex patterns
        hex_patterns = self._extract_hex_patterns(file_data)
        all_strings.extend(hex_patterns)
        
        # File type specific extraction
        if file_type == FileType.PE:
            pe_strings = self._extract_pe_specific_strings(file_data)
            all_strings.extend(pe_strings)
        
        # Filter and score strings
        filtered_strings = self._filter_and_score_strings(all_strings)
        
        # Select best strings
        return self._select_best_strings(filtered_strings)
    
    def _extract_ascii_strings(self, file_data: bytes) -> List[YaraString]:
        """Extract ASCII strings"""
        strings = []
        pattern = rb'[\x20-\x7E]{%d,%d}' % (self.min_string_length, self.max_string_length)
        
        matches = re.findall(pattern, file_data)
        
        for i, match in enumerate(matches):
            try:
                string_value = match.decode('ascii')
                
                # Skip common/generic strings
                if string_value.lower() not in self.common_strings:
                    yara_string = YaraString(
                        name=f"str_ascii_{i}",
                        value=string_value,
                        string_type=StringType.TEXT,
                        condition_weight=self._calculate_string_weight(string_value)
                    )
                    strings.append(yara_string)
            except UnicodeDecodeError:
                continue
        
        return strings
    
    def _extract_unicode_strings(self, file_data: bytes) -> List[YaraString]:
        """Extract Unicode strings"""
        strings = []
        
        # Look for UTF-16 encoded strings
        for i in range(0, len(file_data) - 8, 2):
            try:
                # Extract potential Unicode string
                potential_string = file_data[i:i+100]
                decoded = potential_string.decode('utf-16le', errors='ignore')
                
                # Check if it's a meaningful string
                if (len(decoded) >= self.min_string_length and 
                    len(decoded) <= self.max_string_length and
                    decoded.isprintable() and 
                    not decoded.isspace()):
                    
                    yara_string = YaraString(
                        name=f"str_unicode_{len(strings)}",
                        value=decoded,
                        string_type=StringType.WIDE,
                        modifiers=["wide"],
                        condition_weight=self._calculate_string_weight(decoded)
                    )
                    strings.append(yara_string)
                    
                    # Skip ahead to avoid overlapping strings
                    i += len(decoded) * 2
                    
            except UnicodeDecodeError:
                continue
        
        return strings[:50]  # Limit Unicode strings
    
    def _extract_hex_patterns(self, file_data: bytes) -> List[YaraString]:
        """Extract significant hex patterns"""
        strings = []
        
        # Look for executable signatures
        signatures = {
            'pe_header': b'\\x4D\\x5A',  # MZ header
            'pe_signature': b'\\x50\\x45\\x00\\x00',  # PE signature
            'elf_header': b'\\x7F\\x45\\x4C\\x46',  # ELF header
        }
        
        for name, signature in signatures.items():
            if signature in file_data:
                hex_string = signature.decode('unicode_escape').encode('latin1').hex().upper()
                hex_formatted = ' '.join([hex_string[i:i+2] for i in range(0, len(hex_string), 2)])
                
                yara_string = YaraString(
                    name=f"hex_{name}",
                    value=hex_formatted,
                    string_type=StringType.HEX,
                    condition_weight=8.0  # High weight for file signatures
                )
                strings.append(yara_string)
        
        # Extract other distinctive hex patterns
        distinctive_patterns = self._find_distinctive_hex_patterns(file_data)
        strings.extend(distinctive_patterns)
        
        return strings
    
    def _extract_pe_specific_strings(self, file_data: bytes) -> List[YaraString]:
        """Extract PE-specific strings"""
        strings = []
        
        try:
            pe = pefile.PE(data=file_data)
            
            # Extract import table strings
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8')
                    
                    yara_string = YaraString(
                        name=f"import_{len(strings)}",
                        value=dll_name,
                        string_type=StringType.TEXT,
                        condition_weight=6.0
                    )
                    strings.append(yara_string)
                    
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8')
                            yara_string = YaraString(
                                name=f"func_{len(strings)}",
                                value=func_name,
                                string_type=StringType.TEXT,
                                condition_weight=7.0
                            )
                            strings.append(yara_string)
            
            # Extract section names
            for section in pe.sections:
                section_name = section.Name.decode('utf-8').rstrip('\\x00')
                if section_name and len(section_name) > 2:
                    yara_string = YaraString(
                        name=f"section_{len(strings)}",
                        value=section_name,
                        string_type=StringType.TEXT,
                        condition_weight=5.0
                    )
                    strings.append(yara_string)
                    
        except Exception as e:
            logging.warning(f"Failed to parse PE file: {str(e)}")
        
        return strings
    
    def _find_distinctive_hex_patterns(self, file_data: bytes) -> List[YaraString]:
        """Find distinctive hex patterns in the file"""
        strings = []
        
        # Look for repeating byte patterns that might be significant
        pattern_counts = Counter()
        window_size = 8
        
        for i in range(len(file_data) - window_size):
            pattern = file_data[i:i+window_size]
            pattern_counts[pattern] += 1
        
        # Find patterns that appear multiple times but not too frequently
        for pattern, count in pattern_counts.items():
            if 2 <= count <= 10:  # Appears multiple times but not common
                hex_pattern = pattern.hex().upper()
                hex_formatted = ' '.join([hex_pattern[i:i+2] for i in range(0, len(hex_pattern), 2)])
                
                yara_string = YaraString(
                    name=f"hex_pattern_{len(strings)}",
                    value=hex_formatted,
                    string_type=StringType.HEX,
                    condition_weight=4.0
                )
                strings.append(yara_string)
        
        return strings[:10]  # Limit hex patterns
    
    def _calculate_string_weight(self, string_value: str) -> float:
        """Calculate weight/importance of a string"""
        weight = 1.0
        
        # Check against suspicious patterns
        for pattern, pattern_weight in self.suspicious_patterns.items():
            if re.search(pattern, string_value, re.IGNORECASE):
                weight = max(weight, pattern_weight)
        
        # Adjust based on string characteristics
        if len(string_value) > 20:
            weight += 1.0  # Longer strings are more distinctive
        
        if re.search(r'[A-Za-z]{3,}\\d{3,}', string_value):
            weight += 1.5  # Mixed alpha-numeric patterns
        
        if string_value.isupper() and len(string_value) > 8:
            weight += 0.5  # All caps might be significant
        
        return min(weight, 10.0)  # Cap at 10.0
    
    def _filter_and_score_strings(self, strings: List[YaraString]) -> List[YaraString]:
        """Filter and score strings for quality"""
        filtered = []
        
        for string_obj in strings:
            # Calculate false positive risk
            fp_risk = self._calculate_fp_risk(string_obj.value)
            string_obj.false_positive_risk = fp_risk
            
            # Only keep strings with low FP risk and high weight
            if fp_risk < 0.7 and string_obj.condition_weight >= 3.0:
                filtered.append(string_obj)
        
        return filtered
    
    def _calculate_fp_risk(self, string_value: str) -> float:
        """Calculate false positive risk for a string"""
        risk = 0.0
        
        # Common words increase FP risk
        common_words = ['the', 'and', 'for', 'are', 'but', 'not', 'you', 'all']
        for word in common_words:
            if word.lower() in string_value.lower():
                risk += 0.2
        
        # Very short strings are risky
        if len(string_value) < 6:
            risk += 0.3
        
        # Generic patterns are risky
        if re.match(r'^[0-9]+$', string_value):
            risk += 0.4  # Pure numbers
        
        if re.match(r'^[a-zA-Z]$', string_value):
            risk += 0.5  # Single letters
        
        return min(risk, 1.0)
    
    def _select_best_strings(self, strings: List[YaraString], max_strings: int = 20) -> List[YaraString]:
        """Select the best strings for the YARA rule"""
        # Sort by weight descending, FP risk ascending
        sorted_strings = sorted(
            strings, 
            key=lambda s: (s.condition_weight, -s.false_positive_risk),
            reverse=True
        )
        
        return sorted_strings[:max_strings]

class YaraConditionBuilder:
    """Builds YARA rule conditions from extracted strings"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def build_condition(self, strings: List[YaraString], 
                       malware_family: Optional[str] = None) -> str:
        """Build optimized YARA condition"""
        if not strings:
            return "true"  # Fallback condition
        
        # Group strings by weight/importance
        high_weight = [s for s in strings if s.condition_weight >= 7.0]
        medium_weight = [s for s in strings if 4.0 <= s.condition_weight < 7.0]
        low_weight = [s for s in strings if s.condition_weight < 4.0]
        
        condition_parts = []
        
        # High weight strings - any one is sufficient
        if high_weight:
            high_names = [f"${s.name}" for s in high_weight]
            if len(high_names) == 1:
                condition_parts.append(high_names[0])
            else:
                condition_parts.append(f"any of ({', '.join(high_names)})")
        
        # Medium weight strings - require multiple
        if medium_weight:
            medium_names = [f"${s.name}" for s in medium_weight]
            if len(medium_names) >= 3:
                condition_parts.append(f"2 of ({', '.join(medium_names)})")
            elif len(medium_names) == 2:
                condition_parts.append(f"all of ({', '.join(medium_names)})")
            else:
                condition_parts.append(medium_names[0])
        
        # Low weight strings - require many
        if low_weight and len(low_weight) >= 4:
            low_names = [f"${s.name}" for s in low_weight]
            required_count = max(3, len(low_names) // 2)
            condition_parts.append(f"{required_count} of ({', '.join(low_names)})")
        
        # Combine conditions
        if not condition_parts:
            # Fallback to simple counting
            all_names = [f"${s.name}" for s in strings]
            required = max(1, len(all_names) // 3)
            return f"{required} of them"
        
        # Use OR logic between different weight groups
        return " or ".join(f"({part})" for part in condition_parts)

class YaraRuleGenerator:
    """Main YARA rule generation engine"""
    
    def __init__(self):
        self.string_extractor = StringExtractor()
        self.condition_builder = YaraConditionBuilder()
        self.logger = logging.getLogger(__name__)
    
    def generate_rule_from_file(self, file_path: str, 
                               metadata: Optional[Dict[str, Any]] = None) -> Optional[YaraRule]:
        """Generate YARA rule from malware file"""
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            return self.generate_rule_from_data(file_data, metadata)
            
        except Exception as e:
            self.logger.error(f"Error reading file {file_path}: {str(e)}")
            return None
    
    def generate_rule_from_data(self, file_data: bytes, 
                               metadata: Optional[Dict[str, Any]] = None) -> Optional[YaraRule]:
        """Generate YARA rule from file data"""
        try:
            # Determine file type
            file_type = self._determine_file_type(file_data)
            
            # Extract strings
            strings = self.string_extractor.extract_strings(file_data, file_type)
            
            if not strings:
                self.logger.warning("No suitable strings found for YARA rule generation")
                return None
            
            # Build metadata
            meta = self._build_metadata(file_data, metadata)
            
            # Generate rule name
            rule_name = self._generate_rule_name(meta)
            
            # Build condition
            malware_family = metadata.get('malware_family') if metadata else None
            condition = self.condition_builder.build_condition(strings, malware_family)
            
            # Extract tags
            tags = self._extract_tags(meta)
            
            # Create YARA rule
            rule = YaraRule(
                name=rule_name,
                tags=tags,
                meta=meta,
                strings=strings,
                condition=condition
            )
            
            return rule
            
        except Exception as e:
            self.logger.error(f"Error generating YARA rule: {str(e)}")
            return None
    
    def _determine_file_type(self, file_data: bytes) -> FileType:
        """Determine file type from data"""
        # Check for PE
        if file_data[:2] == b'MZ':
            return FileType.PE
        
        # Check for ELF
        if file_data[:4] == b'\\x7fELF':
            return FileType.ELF
        
        # Check for Mach-O
        if file_data[:4] in [b'\\xcf\\xfa\\xed\\xfe', b'\\xfe\\xed\\xfa\\xcf']:
            return FileType.MACHO
        
        # Use python-magic for other types
        try:
            file_type = magic.from_buffer(file_data, mime=True)
            
            if 'script' in file_type:
                return FileType.SCRIPT
            elif 'document' in file_type:
                return FileType.DOCUMENT
            elif 'archive' in file_type:
                return FileType.ARCHIVE
        except:
            pass
        
        return FileType.UNKNOWN
    
    def _build_metadata(self, file_data: bytes, 
                       metadata: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        """Build rule metadata"""
        meta = {
            'author': 'ThreatSight Pipeline',
            'date': datetime.now().strftime('%Y-%m-%d'),
            'description': 'Auto-generated YARA rule for malware detection'
        }
        
        # Add file hashes
        meta['md5'] = hashlib.md5(file_data).hexdigest()
        meta['sha1'] = hashlib.sha1(file_data).hexdigest()
        meta['sha256'] = hashlib.sha256(file_data).hexdigest()
        meta['filesize'] = str(len(file_data))
        
        # Add threat intelligence metadata
        if metadata:
            if 'malware_family' in metadata:
                meta['family'] = metadata['malware_family']
            
            if 'threat_actor' in metadata:
                meta['actor'] = metadata['threat_actor']
            
            if 'campaign' in metadata:
                meta['campaign'] = metadata['campaign']
            
            if 'first_seen' in metadata:
                meta['first_seen'] = metadata['first_seen']
            
            if 'tlp' in metadata:
                meta['tlp'] = metadata['tlp']
        
        return meta
    
    def _generate_rule_name(self, metadata: Dict[str, str]) -> str:
        """Generate rule name from metadata"""
        name_parts = ['mal']
        
        if 'family' in metadata:
            family = re.sub(r'[^a-zA-Z0-9]', '', metadata['family'])
            name_parts.append(family.lower())
        
        # Add hash prefix for uniqueness
        if 'sha256' in metadata:
            hash_prefix = metadata['sha256'][:8]
            name_parts.append(hash_prefix)
        
        return '_'.join(name_parts)
    
    def _extract_tags(self, metadata: Dict[str, str]) -> List[str]:
        """Extract tags from metadata"""
        tags = []
        
        if 'family' in metadata:
            family = metadata['family'].lower().replace(' ', '_')
            tags.append(f"family_{family}")
        
        if 'actor' in metadata:
            actor = metadata['actor'].lower().replace(' ', '_')
            tags.append(f"actor_{actor}")
        
        # Add generic tags
        tags.extend(['malware', 'auto_generated'])
        
        return tags

class YaraBatchGenerator:
    """Batch YARA rule generation"""
    
    def __init__(self):
        self.generator = YaraRuleGenerator()
        self.logger = logging.getLogger(__name__)
    
    def generate_batch_rules(self, file_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate YARA rules for batch of files"""
        results = {
            'generated_rules': [],
            'failed_files': [],
            'statistics': {
                'total_processed': len(file_list),
                'successful': 0,
                'failed': 0,
                'by_family': {}
            }
        }
        
        for file_info in file_list:
            try:
                file_path = file_info.get('path')
                metadata = file_info.get('metadata', {})
                
                rule = self.generator.generate_rule_from_file(file_path, metadata)
                
                if rule:
                    results['generated_rules'].append(rule)
                    results['statistics']['successful'] += 1
                    
                    # Update family statistics
                    family = metadata.get('malware_family', 'unknown')
                    results['statistics']['by_family'][family] = \
                        results['statistics']['by_family'].get(family, 0) + 1
                else:
                    results['failed_files'].append({
                        'path': file_path,
                        'reason': 'Rule generation failed'
                    })
                    results['statistics']['failed'] += 1
                    
            except Exception as e:
                results['failed_files'].append({
                    'path': file_info.get('path', 'unknown'),
                    'reason': str(e)
                })
                results['statistics']['failed'] += 1
                self.logger.error(f"Failed to process file {file_info}: {str(e)}")
        
        return results
    
    def export_rules_to_file(self, rules: List[YaraRule], 
                            output_path: str = "generated_rules.yar") -> bool:
        """Export all rules to a single YARA file"""
        try:
            with open(output_path, 'w') as f:
                f.write("/*\n")
                f.write(" * Auto-generated YARA rules by ThreatSight Pipeline\n")
                f.write(f" * Generated on: {datetime.now().isoformat()}\n")
                f.write(f" * Total rules: {len(rules)}\n")
                f.write(" */\n\n")
                
                for rule in rules:
                    f.write(rule.to_yara_format())
                    f.write("\n\n")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export YARA rules: {str(e)}")
            return False

# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Sample malware metadata
    sample_metadata = {
        'malware_family': 'Emotet',
        'threat_actor': 'TA542',
        'campaign': 'Emotet_2024',
        'first_seen': '2024-01-15',
        'tlp': 'white'
    }
    
    # Generate single rule from hypothetical malware file
    generator = YaraRuleGenerator()
    
    # This would work with actual malware file:
    # rule = generator.generate_rule_from_file('/path/to/malware.exe', sample_metadata)
    
    print("YARA Rule Generation Engine initialized successfully!")
    print("Ready to process malware samples and generate detection rules.")