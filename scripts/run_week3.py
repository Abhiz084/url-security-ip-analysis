#!/usr/bin/env python3
"""
Week 3 Complete Runner
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.train_model import main as train_main

if __name__ == "__main__":
    train_main()