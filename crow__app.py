#!/usr/bin/env python3

import os
import sys

# نضيف مسار المكتبة يدوياً
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crow.cli import app

app()
