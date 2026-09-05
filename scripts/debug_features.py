# Save as scripts/debug_features.py
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ml_pipeline.prediction import find_latest_model, URLPredictor
import json

model_path = find_latest_model('random_forest')
predictor = URLPredictor(model_path)

# Test URLs
test_urls = [
    "https://www.google.com",
    "https://www.github.com",
    "http://suspicious-login.xyz/verify/account.php",
]

for url in test_urls:
    print(f"\n{'='*60}")
    print(f"URL: {url}")
    print(f"{'='*60}")
    
    features = predictor.extract_features(url)
    
    # Show key features
    key_features = ['is_https', 'url_length', 'domain_length', 'dot_count', 
                    'slash_count', 'special_char_count', 'entropy', 'subdomain_count',
                    'suspicious_tld', 'suspicious_keywords_count', 'has_ip_address',
                    'letter_count', 'digit_count', 'digit_ratio']
    
    for feat in key_features:
        if feat in features:
            print(f"  {feat:<30}: {features[feat]}")
    
    # Show actual prediction probabilities
    import numpy as np
    arr = np.array([features.get(f,0) for f in predictor.selected_features]).reshape(1,-1)
    if predictor.scaler and predictor.scaler.n_features_in_ == arr.shape[1]:
        arr = predictor.scaler.transform(arr)
    proba = predictor.model.predict_proba(arr)[0]
    print(f"\n  Benign prob:    {proba[0]:.4f}")
    print(f"  Malicious prob: {proba[1]:.4f}")