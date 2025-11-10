import re
import pandas as pd
from typing import Dict, List

class EmailSocialEngineeringDetector:
    def __init__(self):
        self.urgency_keywords = ["urgent", "immediately", "action required", "verify now", "asap", "quick", "instant", "right away", "emergency"]
        self.authority_keywords = ["security team", "admin", "management", "official", "government", "authority", "support", "customer service", "security department"]
        self.fear_keywords = ["account suspension", "compromised", "unauthorized access", "security breach", "hacked", "locked out", "suspended", "terminated", "violation"]
        self.psychological_triggers = ["free", "gift", "reward", "limited time", "exclusive", "only you", "congratulations", "winner", "selected"]
        self.suspicious_url_patterns = [r"http://[^\s]+", r"https://[^\s]+", r"bit\.ly/\w+", r"tinyurl\.com/\w+"]
        
    def analyze_email(self, email_text: str) -> Dict:
        score = 0
        red_flags = []
        detailed_analysis = {}
        
        # Urgency detection
        urgency_matches = [word for word in self.urgency_keywords if word in email_text.lower()]
        urgency_count = len(urgency_matches)
        if urgency_count > 0:
            score += urgency_count * 10
            red_flags.append(f"Urgency language detected ({urgency_count} triggers)")
            detailed_analysis["urgency_triggers"] = urgency_matches
            
        # Authority appeal detection
        authority_matches = [word for word in self.authority_keywords if word in email_text.lower()]
        authority_count = len(authority_matches)
        if authority_count > 0:
            score += authority_count * 8
            red_flags.append(f"Authority appeal detected ({authority_count} triggers)")
            detailed_analysis["authority_triggers"] = authority_matches
            
        # Fear tactics detection
        fear_matches = [word for word in self.fear_keywords if word in email_text.lower()]
        fear_count = len(fear_matches)
        if fear_count > 0:
            score += fear_count * 12
            red_flags.append(f"Fear-based manipulation detected ({fear_count} triggers)")
            detailed_analysis["fear_triggers"] = fear_matches
            
        # Psychological triggers
        psych_matches = [word for word in self.psychological_triggers if word in email_text.lower()]
        psych_count = len(psych_matches)
        if psych_count > 0:
            score += psych_count * 6
            red_flags.append(f"Psychological triggers detected ({psych_count} triggers)")
            detailed_analysis["psychological_triggers"] = psych_matches
            
        # Suspicious URL detection
        url_matches = []
        for pattern in self.suspicious_url_patterns:
            url_matches.extend(re.findall(pattern, email_text.lower()))
        url_count = len(url_matches)
        if url_count > 0:
            score += url_count * 15
            red_flags.append(f"Suspicious URLs detected ({url_count} links)")
            detailed_analysis["suspicious_urls"] = url_matches
            
        # Determine risk level
        if score > 60:
            risk_level = "CRITICAL"
            recommendation = "🚨 CRITICAL: High probability of phishing/social engineering attack"
        elif score > 40:
            risk_level = "HIGH"
            recommendation = "🚨 HIGH: Likely social engineering attempt - investigate immediately"
        elif score > 25:
            risk_level = "MEDIUM"
            recommendation = "⚠️ MEDIUM: Suspicious elements detected - review carefully"
        else:
            risk_level = "LOW"
            recommendation = "✅ LOW: Appears legitimate"
        
        return {
            "risk_score": min(score, 100),
            "risk_level": risk_level,
            "red_flags": red_flags,
            "total_triggers": len(red_flags),
            "recommendation": recommendation,
            "detailed_analysis": detailed_analysis,
            "triggers_found": urgency_count + authority_count + fear_count + psych_count + url_count
        }
    
    def analyze_bulk_emails(self, emails: List[str]) -> List[Dict]:
        return [self.analyze_email(email) for email in emails]

# Example usage and testing
if __name__ == "__main__":
    detector = EmailSocialEngineeringDetector()
    
    # Test case 1: Phishing email
    phishing_email = """
    URGENT SECURITY ALERT!
    
    Dear User,
    
    Our security team has detected unauthorized access to your account. 
    Your account will be SUSPENDED immediately if you don't verify your identity.
    
    Click here to verify: http://fake-security-update.com/verify-now
    
    This is an emergency - act ASAP!
    
    Sincerely,
    Security Team
    """
    
    print("🔍 Analyzing Phishing Email...")
    result1 = detector.analyze_email(phishing_email)
    print("Risk Score:", result1["risk_score"])
    print("Risk Level:", result1["risk_level"])
    print("Red Flags:", result1["red_flags"])
    print("Recommendation:", result1["recommendation"])
    print()
    
    # Test case 2: Normal email
    normal_email = """
    Hi there,
    
    Just checking in to see how you're doing.
    Let me know if you need anything.
    
    Best regards,
    John
    """
    
    print("🔍 Analyzing Normal Email...")
    result2 = detector.analyze_email(normal_email)
    print("Risk Score:", result2["risk_score"])
    print("Risk Level:", result2["risk_level"])
    print("Recommendation:", result2["recommendation"])
