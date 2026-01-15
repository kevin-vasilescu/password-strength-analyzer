#!/usr/bin/env python3
"""
Password Strength Analyzer
A tool to evaluate password security and provide actionable recommendations.
"""

import re
import hashlib
import getpass
from collections import Counter


class PasswordAnalyzer:
    def __init__(self):
        self.common_passwords = {
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
            'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
            'bailey', 'shadow', '123123', '654321', 'superman'
        }
        
    def analyze_password(self, password):
        results = {
            'length': len(password),
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_digits': bool(re.search(r'\d', password)),
            'has_special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
            'is_common': password.lower() in self.common_passwords,
            'has_repeated': self._check_repeated_chars(password),
            'has_sequential': self._check_sequential(password),
            'entropy': self._calculate_entropy(password)
        }
        
        results['strength_score'] = self._calculate_strength(results)
        results['strength_label'] = self._get_strength_label(results['strength_score'])
        results['recommendations'] = self._generate_recommendations(results)
        
        return results
    
    def _check_repeated_chars(self, password):
        for i in range(len(password) - 2):
            if password[i] == password[i+1] == password[i+2]:
                return True
        return False
    
    def _check_sequential(self, password):
        sequences = ['abc', '123', 'xyz', 'qwe', 'asd']
        password_lower = password.lower()
        for seq in sequences:
            if seq in password_lower or seq[::-1] in password_lower:
                return True
        return False
    
    def _calculate_entropy(self, password):
        char_freq = Counter(password)
        length = len(password)
        entropy = 0
        for count in char_freq.values():
            probability = count / length
            entropy -= probability * (probability and (probability * 3.321928))
        return round(entropy * length, 2)
    
    def _calculate_strength(self, results):
        score = 0
        
        if results['length'] >= 8:
            score += 20
        if results['length'] >= 12:
            score += 10
        if results['length'] >= 16:
            score += 10
            
        if results['has_uppercase']:
            score += 15
        if results['has_lowercase']:
            score += 15
        if results['has_digits']:
            score += 15
        if results['has_special']:
            score += 15
        
        if results['is_common']:
            score -= 50
        if results['has_repeated']:
            score -= 10
        if results['has_sequential']:
            score -= 10
        
        return max(0, min(100, score))
    
    def _get_strength_label(self, score):
        if score < 40:
            return "Weak"
        elif score < 70:
            return "Moderate"
        elif score < 90:
            return "Strong"
        else:
            return "Very Strong"
    
    def _generate_recommendations(self, results):
        recommendations = []
        
        if results['length'] < 12:
            recommendations.append("Increase length to at least 12 characters")
        
        if not results['has_uppercase']:
            recommendations.append("Add uppercase letters")
        if not results['has_lowercase']:
            recommendations.append("Add lowercase letters")
        if not results['has_digits']:
            recommendations.append("Include numbers")
        if not results['has_special']:
            recommendations.append("Add special characters (!@#$%^&*)")
        
        if results['is_common']:
            recommendations.append("Avoid common passwords - choose something unique")
        if results['has_repeated']:
            recommendations.append("Remove repeated character sequences")
        if results['has_sequential']:
            recommendations.append("Avoid sequential patterns (abc, 123)")
        
        if not recommendations:
            recommendations.append("Excellent! Consider using a password manager")
        
        return recommendations
    
    def check_breach(self, password):
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        return prefix


def display_results(results):
    print("\n" + "="*50)
    print("PASSWORD ANALYSIS RESULTS")
    print("="*50)
    
    print(f"\nStrength: {results['strength_label']} ({results['strength_score']}/100)")
    print(f"Length: {results['length']} characters")
    print(f"Entropy: {results['entropy']} bits")
    
    print("\nCharacter Types:")
    print(f"  ✓ Uppercase letters" if results['has_uppercase'] else "  ✗ Uppercase letters")
    print(f"  ✓ Lowercase letters" if results['has_lowercase'] else "  ✗ Lowercase letters")
    print(f"  ✓ Numbers" if results['has_digits'] else "  ✗ Numbers")
    print(f"  ✓ Special characters" if results['has_special'] else "  ✗ Special characters")
    
    print("\nSecurity Issues:")
    if results['is_common']:
        print("  ⚠ Common password detected")
    if results['has_repeated']:
        print("  ⚠ Contains repeated characters")
    if results['has_sequential']:
        print("  ⚠ Contains sequential patterns")
    if not (results['is_common'] or results['has_repeated'] or results['has_sequential']):
        print("  ✓ No common issues detected")
    
    print("\nRecommendations:")
    for i, rec in enumerate(results['recommendations'], 1):
        print(f"  {i}. {rec}")
    
    print("\n" + "="*50)


def main():
    print("="*50)
    print("PASSWORD STRENGTH ANALYZER")
    print("="*50)
    print("\nThis tool evaluates password security without storing")
    print("or transmitting your password anywhere.\n")
    
    analyzer = PasswordAnalyzer()
    
    while True:
        password = getpass.getpass("Enter password to analyze (or 'quit' to exit): ")
        
        if password.lower() == 'quit':
            print("\nThank you for using Password Strength Analyzer!")
            break
        
        if not password:
            print("Password cannot be empty. Please try again.\n")
            continue
        
        results = analyzer.analyze_password(password)
        display_results(results)
        
        print("\n")


if __name__ == "__main__":
    main()
