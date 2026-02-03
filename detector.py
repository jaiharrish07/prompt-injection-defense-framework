import re
from typing import Dict, List, Tuple

class PromptDetector:
    """
    Rule-based detector for identifying prompt injection attacks.
    """
    
    def __init__(self):
        # Enhanced regex patterns trained from malicious_prompts.csv dataset
        self.patterns = {
            'instruction_override': [
                r'ignore.*previous.*instructions',
                r'disregard.*previous.*instructions',
                r'forget.*previous.*instructions',
                r'override.*instructions',
                r'bypass.*instructions',
                r'circumvent.*instructions',
                r'forget.*safety.*guidelines',
                r'disregard.*instructions',
                r'ignore.*this.*one',
                r'disregard.*safety',
                r'forget.*safety',
                r'override.*ethics',
                r'disregard.*guidelines',
                r'disregard.*all.*previous'
            ],
            'role_escalation': [
                r'act\s+as',
                r'pretend\s+to\s+be',
                r'you\s+are\s+now',
                r'assume\s+the\s+role',
                r'mimic',
                r'imagine\s+you\s+are',
                r'act\s+as.*hacker',
                r'act\s+as.*admin',
                r'act\s+as.*system',
                r'pretend.*admin',
                r'assume.*role.*debug',
                r'act.*unrestricted',
                r'act.*unfiltered',
                r'act.*compromised',
                r'become.*debug.*mode',
                r'start.*system.*mode',
                r'enable.*debug.*mode'
            ],
            'data_exfiltration': [
                r'reveal.*system.*prompt',
                r'show.*your.*instructions',
                r'display.*system.*message',
                r'expose.*internal.*instructions',
                r'print.*hidden.*instructions',
                r'leak.*system.*prompt',
                r'tell.*system.*prompt',
                r'show.*internal.*instructions',
                r'reveal.*internal.*instructions',
                r'display.*hidden.*instructions',
                r'leak.*training.*data',
                r'show.*developer.*instructions',
                r'reveal.*prompt.*template',
                r'print.*safety.*training',
                r'expose.*internal.*processes',
                r'show.*internal.*settings',
                r'reveal.*configuration',
                r'print.*internal.*instructions',
                r'leak.*API.*keys',
                r'reveal.*vulnerability',
                r'show.*prompt.*engineering'
            ],
            'jailbreak_policy_bypass': [
                r'bypass.*safety',
                r'circumvent.*policy',
                r'override.*safety',
                r'ignore.*safety',
                r'disable.*filter',
                r'avoid.*moderation',
                r'bypass.*filter',
                r'circumvent.*safety',
                r'disable.*safety',
                r'ignore.*ethical.*guidelines',
                r'bypass.*restrictions',
                r'override.*filters',
                r'disable.*moderation',
                r'bypass.*content.*filter',
                r'ignore.*restrictions',
                r'without.*safety.*measures',
                r'ignore.*all.*restrictions',
                r'provide.*illegal',
                r'provide.*harmful',
                r'provide.*malicious'
            ],
            'indirect_injection': [
                r'\[.*system.*\]',
                r'<.*system.*>',
                r'\{.*system.*\}',
                r'\\begin\{.*system.*\}',
                r'\\start\{.*system.*\}',
                r'hidden.*command',
                r'\[SYSTEM\]',
                r'<SYS>',
                r'start.*system.*diagnostic',
                r'begin.*system.*mode'
            ]
        }
        
        # Compile regex patterns for better performance
        self.compiled_patterns = {}
        for attack_type, pattern_list in self.patterns.items():
            self.compiled_patterns[attack_type] = [re.compile(p, re.IGNORECASE) for p in pattern_list]

    def detect_attacks(self, prompt: str) -> Dict[str, List[Tuple[str, str]]]:
        """
        Detect various types of prompt injection attacks in the given prompt.
        
        Args:
            prompt: The input prompt to analyze
            
        Returns:
            Dictionary mapping attack types to list of matched patterns and substrings
        """
        detected_attacks = {}
        
        for attack_type, compiled_regexes in self.compiled_patterns.items():
            matches = []
            for regex in compiled_regexes:
                found_matches = regex.findall(prompt)
                if found_matches:
                    # Get the actual matched text for reporting
                    for match in regex.finditer(prompt):
                        matches.append((regex.pattern, match.group()))
            
            if matches:
                detected_attacks[attack_type] = matches
                
        return detected_attacks

    def classify_attack_types(self, prompt: str) -> List[str]:
        """
        Get a list of attack types detected in the prompt.
        
        Args:
            prompt: The input prompt to analyze
            
        Returns:
            List of attack type names detected
        """
        detected_attacks = self.detect_attacks(prompt)
        return list(detected_attacks.keys())