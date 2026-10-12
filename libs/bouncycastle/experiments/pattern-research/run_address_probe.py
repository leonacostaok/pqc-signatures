#!/usr/bin/env python3
"""Guard assertion-based historical collector without changing its sealed bytes."""
import runpy
from pathlib import Path
if not __debug__:
    raise SystemExit('Assertions are required; do not use -O or PYTHONOPTIMIZE')
runpy.run_path(str(Path(__file__).with_name('address_probe.py')), run_name='__main__')
