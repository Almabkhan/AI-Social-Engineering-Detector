import re
from typing import Dict, List

class MessageSocialEngineeringDetector:
    def __init__(self):
        self.manipulation_patterns = {
            "reciprocity": ["free", "gift", "reward", "special offer", "bonus", "complimentary"],
            "scarcity": ["limited time", "last chance", "only few left", "ending soon", "exclusive"],
            "liking": ["friend", "trusted", "recommended", "like you", "for you", "special"],
            "social_proof": ["everyone", "people", "others", "trending", "popular"],
            "authority": ["expert", "professional", "certified", "official", "verified"]
        }
        
        self.threat_keywords = ["password", "login", "verify", "account", "security", "update", "click", "link"]
    
    def analyze_message(self, message: str) -> Dict:
        analysis_result = {
            "techniques_detected": [],
            "confidence_score": 0,
            "risk_level": "LOW",
            "recommendation": "✅ Appears legitimate",
            "trigger_count": 0
        }
        
        message_lower = message.lower()
        total_triggers = 0
        
        # Detect Cialdini's principles of persuasion
        for technique, keywords in self.manipulation_patterns.items():
            matches = [kw for kw in keywords if kw in message_lower]
            if matches:
                analysis_result["techniques_detected"].append({
                    "technique": technique,
                    "triggered_keywords": matches,
                    "count": len(matches)
                })
                analysis_result["confidence_score"] += len(matches) * 8
                total_triggers += len(matches)
        
        # Detect threat keywords
        threat_matches = [kw for kw in self.threat_keywords if kw in message_lower]
        if threat_matches:
            analysis_result["confidence_score"] += len(threat_matches) * 5
            total_triggers += len(threat_matches)
            analysis_result["techniques_detected"].append({
                "technique": "suspicious_keywords",
                "triggered_keywords": threat_matches,
                "count": len(threat_matches)
            })
        
        analysis_result["trigger_count"] = total_triggers
        
        # Determine risk level
        if analysis_result["confidence_score"] > 40:
            analysis_result["risk_level"] = "HIGH"
            analysis_result["recommendation"] = "🚨 High probability of social engineering attempt"
        elif analysis_result["confidence_score"] > 20:
            analysis_result["risk_level"] = "MEDIUM" 
            analysis_result["recommendation"] = "⚠️ Possible manipulation attempt - be cautious"
        else:
            analysis_result["risk_level"] = "LOW"
            analysis_result["recommendation"] = "✅ Appears legitimate"
            
        return analysis_result

    def analyze_bulk_messages(self, messages: List[str]) -> List[Dict]:
        return [self.analyze_message(msg) for msg in messages]

# Example usage
if __name__ == "__main__":
    detector = MessageSocialEngineeringDetector()
    
    test_message = "Hi friend! I have a special limited-time offer just for you. Free gift if you verify your account now!"
    result = detector.analyze_message(test_message)
    
    print("Message Analysis Result:")
    for key, value in result.items():
        print(f"{key}: {value}")
