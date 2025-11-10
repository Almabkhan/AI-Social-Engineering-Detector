# 🤖 AI Social Engineering Detector

AI-powered tool to detect social engineering attacks in emails and messages.

## Quick Start
```python
from models.email_analyzer import EmailSocialEngineeringDetector

detector = EmailSocialEngineeringDetector()
result = detector.analyze_email("Your urgent attention required...")
print(f"Risk: {result['risk_score']}%")
