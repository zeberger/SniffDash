"""Analysis layer: FrameRepository → AnalysisReport (metrics, timeline, HTTP transactions)."""

from sniffdash.analysis.base import (
    AnalysisContext, AnalysisOptions, Analyzer, AnalyzerRegistry, analyzer_registry,
)
from sniffdash.analysis.engine import AnalysisEngine

__all__ = [
    "AnalysisContext", "AnalysisEngine", "AnalysisOptions", "Analyzer", "AnalyzerRegistry",
    "analyzer_registry",
]
