"""Central registry for all language analyzers."""

from typing import Dict, Type, List, Optional
from janitor.analyzers.base import BaseAnalyzer

ANALYZER_REGISTRY: Dict[str, Type[BaseAnalyzer]] = {}


def register_analyzer(language: str):
    """Decorator to register an analyzer class for a specific language."""
    def decorator(cls: Type[BaseAnalyzer]) -> Type[BaseAnalyzer]:
        ANALYZER_REGISTRY[language] = cls
        return cls
    return decorator


def get_analyzer(language: str) -> Optional[Type[BaseAnalyzer]]:
    """Get analyzer class for a language, or None if not available."""
    return ANALYZER_REGISTRY.get(language)


def get_registered_languages() -> List[str]:
    """Return list of languages with registered analyzers."""
    return list(ANALYZER_REGISTRY.keys())


def get_analyzer_for_file(file_path, registry: Dict[str, Type[BaseAnalyzer]] = None) -> Optional[BaseAnalyzer]:
    """Get an analyzer instance that can handle the given file."""
    registry = registry or ANALYZER_REGISTRY
    for lang, analyzer_cls in registry.items():
        instance = analyzer_cls()
        if instance.can_analyze(file_path):
            return instance
    return None


from janitor.analyzers.python import PythonAnalyzer
from janitor.analyzers.javascript import JavaScriptAnalyzer
from janitor.analyzers.typescript import TypeScriptAnalyzer
from janitor.analyzers.kotlin import KotlinAnalyzer
from janitor.analyzers.java import JavaAnalyzer
from janitor.analyzers.go import GoAnalyzer
from janitor.analyzers.csharp import CSharpAnalyzer
from janitor.analyzers.php import PHPAnalyzer

ANALYZER_REGISTRY["python"] = PythonAnalyzer
ANALYZER_REGISTRY["javascript"] = JavaScriptAnalyzer
ANALYZER_REGISTRY["typescript"] = TypeScriptAnalyzer
ANALYZER_REGISTRY["kotlin"] = KotlinAnalyzer
ANALYZER_REGISTRY["java"] = JavaAnalyzer
ANALYZER_REGISTRY["go"] = GoAnalyzer
ANALYZER_REGISTRY["csharp"] = CSharpAnalyzer
ANALYZER_REGISTRY["php"] = PHPAnalyzer
