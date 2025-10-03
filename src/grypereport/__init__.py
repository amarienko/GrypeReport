# -*- coding: utf-8 -*-
"""Grype vulnerability scanner report builder and CSV exporter."""

import sys
from .report import build
from .__version__ import version as __version__


if sys.version_info < (3, 10):
    print("Python version 3.10+ is required!")
    sys.exit(1)


__all__ = ["build", "__version__"]
