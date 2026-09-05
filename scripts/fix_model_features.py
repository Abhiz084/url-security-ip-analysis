# Save this as scripts/fix_model_features.py
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json

# Load the feature importance file to get selected features
with open('models/feature_importance.json', 'r') as f:
    importance = json.load(f)

# Get features from Random Forest importance
rf_features = [f[0] for f in importance['random_forest'] if f[1] >= 0.01]
print(f"Selected features: {len(rf_features)}")

# Find latest model directory
import glob
model_dirs = sorted(glob.glob('models/model_versions/v_*'))
if model_dirs:
    latest_dir = model_dirs[-1]
    
    # Save selected features
    features_path = os.path.join(latest_dir, 'selected_features.json')
    with open(features_path, 'w') as f:
        json.dump({'selected_features': rf_features}, f, indent=2)
    
    print(f"Saved to: {features_path}")
else:
    print("No model directory found!")