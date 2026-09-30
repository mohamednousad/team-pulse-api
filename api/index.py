import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from teampulse.main import app  # noqa: E402,F401  (Vercel serves this ASGI app)
