"""
Entry point for running CA Insight as a module with 'python -m caInsight'
"""

import sys
from .main import main

if __name__ == '__main__':
    sys.exit(main())
