# -*- coding: utf-8 -*-
"""Grype custom report."""
from .report import build_report
from .__version__ import version as __version__

__all__ = ["build_report", "__version__"]
