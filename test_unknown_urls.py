# Save as test_unknown_urls.py
import sys, os
sys.path.insert(0, '.')

from src.ml_pipeline.prediction import URLPredictor

predictor = URLPredictor()  # No ML model - pure rule-based

# Completely new URLs never seen before
test_urls = [
    # Real phishing URLs (from PhishTank)
    "https://steamcommunity.com/giftcard/verify",
    "http://netflix-verify.com/login.php",
    "https://paypai.com/login",  # Typo-squatting
    
    # Real benign URLs
    "https://www.nytimes.com/2024/01/15/technology",
    "https://www.bbc.com/news/world-asia-68012345",
    "https://medium.com/swlh/python-tips-and-tricks",
    
    # Mixed/unknown
    "https://bit.ly/3xYZ123",
    "http://192.168.1.1/admin",
    "https://docs.google.com/spreadsheets/d/abc123",
    "https://zoom.us/j/123456789",
    
    # Suspicious
    "http://free-iphone-win.xyz/claim",
    "https://secure-banking-login.tk/verify",
]

print(f"\n{'='*80}")
print("TESTING COMPLETELY UNKNOWN URLs (Rule-Based Only)")
print(f"{'='*80}\n")

for url in test_urls:
    result = predictor.predict_url(url)
    
    if result['prediction'] == 'malicious':
        emoji = "🔴"
    elif result['prediction'] == 'suspicious':
        emoji = "🟡"
    else:
        emoji = "🟢"
    
    print(f"{emoji} [{result['prediction']:<12}] ({result['confidence']:.0%}) {url[:60]}")