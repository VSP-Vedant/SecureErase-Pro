"""
Root conftest.py — adds project root to sys.path so both desktop and portal
tests can be collected and run from the repository root with:
    python -m pytest desktop/tests/ portal/backend/tests/
"""
import sys
import os

# Insert the repo root so 'desktop.modules.*' and 'portal.backend.modules.*'
# are importable regardless of where pytest is invoked from.
repo_root = os.path.dirname(__file__)
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
