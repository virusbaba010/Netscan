#!/usr/bin/env python3
import sys
import os

# Check if PyQt6 is installed before attempting to start UI
try:
    from PyQt6.QtWidgets import QApplication
except ImportError:
    print("Error: PyQt6 is not installed. Please run 'pip install -r requirements.txt'")
    sys.exit(1)

from ui.app import main

if __name__ == "__main__":
    main()
