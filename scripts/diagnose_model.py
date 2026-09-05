# Save as scripts/diagnose_model.py
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pickle
import json
import glob
import numpy as np

# Find latest model
model_files = glob.glob('models/model_versions/v_*/random_forest.pkl')
if not model_files:
    model_files = glob.glob('models/model_versions/v_*/*.pkl')

if not model_files:
    print("No models found!")
    exit()

model_path = sorted(model_files)[-1]
print(f"Model: {model_path}")

# Load model
with open(model_path, 'rb') as f:
    model = pickle.load(f)

# Check what features the model expects
print(f"\nModel type: {type(model).__name__}")

if hasattr(model, 'feature_names_in_'):
    features = list(model.feature_names_in_)
    print(f"Model expects {len(features)} features:")
    for i, f in enumerate(features):
        print(f"  {i+1}. {f}")
else:
    print("Model does NOT have feature_names_in_ attribute")
    print(f"Model expects {model.n_features_in_} features (unknown names)")

# Check selected_features.json
model_dir = os.path.dirname(model_path)
features_file = os.path.join(model_dir, 'selected_features.json')

if os.path.exists(features_file):
    with open(features_file, 'r') as f:
        data = json.load(f)
    selected = data.get('selected_features', [])
    print(f"\nselected_features.json has {len(selected)} features")
else:
    print(f"\n❌ No selected_features.json found in {model_dir}")