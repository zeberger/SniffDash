"""Built-in analyzers. Every module here is imported automatically by the registry.

To add an analysis: create a module (or subpackage whose ``__init__`` imports its
analyzer), subclass ``Analyzer``, and decorate it with ``@register_analyzer``.
"""
