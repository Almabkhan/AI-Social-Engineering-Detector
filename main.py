from models.email_analyzer import EmailSocialEngineeringDetector
from models.message_scanner import MessageSocialEngineeringDetector
import json

def main():
    print("🤖 AI Social Engineering Detector")
    print("=" * 50)
    
    # Initialize detectors
    email_detector = EmailSocialEngineeringDetector()
    message_detector = MessageSocialEngineeringDetector()
    
    print("\n🔍 Testing Email Analysis...")
    print("-" * 30)
    
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
    
    print("📧 Sample Phishing Email Analysis:")
    email_result = email_detector.analyze_email(phishing_email)
    print(f"Risk Score: {email_result['risk_score']}%")
    print(f"Risk Level: {email_result['risk_level']}")
    print(f"Recommendation: {email_result['recommendation']}")
    print("Red Flags:")
    for flag in email_result['red_flags']:
        print(f"  - {flag}")
    
    print("\n" + "=" * 50)
    print("💬 Testing Message Analysis...")
    print("-" * 30)
    
    # Test case 2: Suspicious message
    suspicious_message = "Hi friend! I have a special limited-time offer just for you. Free gift if you verify your account now! Click here: bit.ly/special-offer"
    
    print("Sample Suspicious Message Analysis:")
    message_result = message_detector.analyze_message(suspicious_message)
    print(f"Confidence Score: {message_result['confidence_score']}%")
    print(f"Risk Level: {message_result['risk_level']}")
    print(f"Recommendation: {message_result['recommendation']}")
    print("Techniques Detected:")
    for technique in message_result['techniques_detected']:
        print(f"  - {technique['technique']}: {technique['triggered_keywords']}")
    
    print("\n" + "=" * 50)
    print("✅ Demo Completed Successfully!")
    print("\n🚀 Features Demonstrated:")
    print("  - Email social engineering detection")
    print("  - Message manipulation analysis")
    print("  - Psychological trigger identification")
    print("  - Real-time risk assessment")

if __name__ == "__main__":
    main()
