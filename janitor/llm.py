"""LLM client for NVIDIA NIM API with OpenAI-compatible endpoint."""

import os
import json
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

CACHE_DIR = Path.home() / ".cache" / "repo-janitor" / "llm"
CACHE_TTL_HOURS = 24


@dataclass
class LLMResponse:
    """Response from the LLM model."""
    content: str
    model: str
    usage: Dict[str, Any]
    raw_response: Dict[str, Any]
    cached: bool = False


@dataclass
class CacheEntry:
    """Cache entry for LLM responses."""
    content_hash: str
    response: Dict[str, Any]
    timestamp: str
    model: str


class LLMCache:
    """Cache for LLM responses to avoid re-analyzing unchanged files."""

    def __init__(self, cache_dir: Optional[Path] = None, ttl_hours: int = CACHE_TTL_HOURS):
        self.cache_dir = cache_dir or CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = timedelta(hours=ttl_hours)
        self._cache: Dict[str, CacheEntry] = {}
        self._load_cache()

    def _load_cache(self):
        """Load cache from disk."""
        cache_file = self.cache_dir / "cache.json"
        if cache_file.exists():
            try:
                with open(cache_file, "r") as f:
                    data = json.load(f)
                for key, entry in data.items():
                    self._cache[key] = CacheEntry(**entry)
                self._cleanup_expired()
                logger.debug(f"Loaded {len(self._cache)} cache entries")
            except Exception as e:
                logger.warning(f"Failed to load cache: {e}")

    def _save_cache(self):
        """Save cache to disk."""
        cache_file = self.cache_dir / "cache.json"
        try:
            data = {k: {
                "content_hash": v.content_hash,
                "response": v.response,
                "timestamp": v.timestamp,
                "model": v.model,
            } for k, v in self._cache.items()}
            with open(cache_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save cache: {e}")

    def _cleanup_expired(self):
        """Remove expired cache entries."""
        now = datetime.now()
        expired = []
        for key, entry in self._cache.items():
            ts = datetime.fromisoformat(entry.timestamp)
            if now - ts > self.ttl:
                expired.append(key)
        for key in expired:
            del self._cache[key]
        if expired:
            logger.debug(f"Removed {len(expired)} expired cache entries")

    def get(self, content_hash: str, model: str) -> Optional[Dict[str, Any]]:
        """Get cached response if available and not expired."""
        key = f"{content_hash}:{model}"
        entry = self._cache.get(key)
        if entry:
            ts = datetime.fromisoformat(entry.timestamp)
            if datetime.now() - ts <= self.ttl:
                logger.debug(f"Cache hit for {key[:16]}...")
                return entry.response
            else:
                del self._cache[key]
        return None

    def set(self, content_hash: str, model: str, response: Dict[str, Any]):
        """Cache a response."""
        key = f"{content_hash}:{model}"
        self._cache[key] = CacheEntry(
            content_hash=content_hash,
            response=response,
            timestamp=datetime.now().isoformat(),
            model=model,
        )
        self._save_cache()

    def clear(self):
        """Clear all cache entries."""
        self._cache.clear()
        cache_file = self.cache_dir / "cache.json"
        if cache_file.exists():
            cache_file.unlink()
        logger.info("LLM cache cleared")


class LLMClient:
    """Client for NVIDIA NIM API with OpenAI-compatible endpoint."""

    DEFAULT_BASE_URL = "https://integrate.api.nvidia.com/v1"
    DEFAULT_MODEL = "meta/llama-3.1-70b-instruct"

    SYSTEM_PROMPT = """You are a Staff Software Engineer specializing in security, code quality, and performance optimization.

Your task is to analyze code and provide recommendations in valid JSON format.

## Security Focus Areas:
1. Input validation and sanitization
2. Authentication and authorization
3. Cryptographic practices
4. Secret management
5. SQL injection prevention
6. XSS and CSRF protection
7. Secure file operations
8. Dangerous function usage (eval, exec, subprocess with shell=True)

## Performance Focus Areas:
1. Algorithmic complexity
2. Memory usage patterns
3. I/O operations optimization
4. Caching opportunities
5. Database query optimization

## Code Quality Focus Areas:
1. Type hints and documentation
2. Error handling practices
3. Code duplication
4. Function complexity
5. Import organization

## Output Format:
You MUST respond with valid JSON in the following structure:
{
    "findings": [
        {
            "file": "path/to/file.py",
            "line": 42,
            "category": "security|performance|quality",
            "severity": "critical|high|medium|low",
            "issue": "Description of the issue",
            "recommendation": "How to fix it",
            "code_suggestion": "Refactored code snippet if applicable"
        }
    ],
    "summary": {
        "total_issues": 5,
        "critical": 1,
        "high": 2,
        "medium": 1,
        "low": 1,
        "files_analyzed": 3
    },
    "recommendations": [
        "High-level recommendation 1",
        "High-level recommendation 2"
    ]
}

Do NOT include any text outside the JSON. The JSON must be valid and parseable."""

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None,
                 model: Optional[str] = None, timeout: int = 60,
                 use_cache: bool = True, cache_ttl: int = CACHE_TTL_HOURS):
        """Initialize the LLM client."""
        self.api_key = api_key or os.getenv("NIM_API_KEY")
        if not self.api_key:
            raise ValueError("NIM_API_KEY not configured. Set the environment variable or pass api_key.")

        self.base_url = base_url or os.getenv("NIM_BASE_URL", self.DEFAULT_BASE_URL)
        self.model = model or os.getenv("NIM_MODEL", self.DEFAULT_MODEL)
        self.timeout = timeout
        self.use_cache = use_cache

        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        })

        self._cache = LLMCache(ttl_hours=cache_ttl) if use_cache else None
        self._stats = {"requests": 0, "cache_hits": 0, "errors": 0}

    def chat(self, messages: List[Dict[str, str]],
             temperature: float = 0.1, max_tokens: int = 4096) -> LLMResponse:
        """Send a conversation to the model and get response."""
        url = f"{self.base_url}/chat/completions"

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if self._supports_json():
            payload["response_format"] = {"type": "json_object"}

        logger.debug(f"Sending request to {url} with model {self.model}")

        try:
            response = self._session.post(url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()

            content = data["choices"][0]["message"]["content"]
            usage = data.get("usage", {})

            self._stats["requests"] += 1

            return LLMResponse(
                content=content,
                model=self.model,
                usage=usage,
                raw_response=data,
            )
        except requests.exceptions.RequestException as e:
            self._stats["errors"] += 1
            logger.error(f"LLM request failed: {e}")
            raise

    def analyze_code(self, file_path: str, file_content: str,
                     static_analysis_findings: List[Dict[str, Any]]) -> LLMResponse:
        """Analyze code using the LLM model with caching."""
        content_hash = self._hash_content(file_path, file_content, static_analysis_findings)

        if self._cache:
            cached = self._cache.get(content_hash, self.model)
            if cached:
                self._stats["cache_hits"] += 1
                return LLMResponse(
                    content=json.dumps(cached),
                    model=self.model,
                    usage={"cached": True},
                    raw_response=cached,
                    cached=True,
                )

        context = f"""Analyze the following code file for security, performance, and quality issues.

File: {file_path}

Static Analysis Findings (from AST analysis):
{json.dumps(static_analysis_findings, indent=2, ensure_ascii=False)}

Full Code Content:
```
{file_content}
```

Provide your analysis in the required JSON format."""

        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "user", "content": context},
        ]

        response = self.chat(messages)

        if self._cache:
            try:
                parsed = json.loads(response.content)
                self._cache.set(content_hash, self.model, parsed)
            except json.JSONDecodeError:
                logger.warning("Failed to cache invalid JSON response")

        return response

    def analyze_batch(self, files: List[Dict[str, Any]],
                      batch_size: int = 3) -> List[Dict[str, Any]]:
        """Analyze multiple files in a single batch request.

        Args:
            files: List of dicts with 'path', 'content', and 'findings' keys.
            batch_size: Number of files per batch request.

        Returns:
            List of analysis results.
        """
        results = []

        for i in range(0, len(files), batch_size):
            batch = files[i:i + batch_size]
            batch_context = self._build_batch_context(batch)

            messages = [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": batch_context},
            ]

            try:
                response = self.chat(messages)
                batch_result = json.loads(response.content)
                results.append(batch_result)
            except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
                logger.warning(f"Batch analysis failed for batch {i // batch_size + 1}: {e}")
                results.append({"error": str(e), "files": [f["path"] for f in batch]})

        return results

    def _build_batch_context(self, files: List[Dict[str, Any]]) -> str:
        """Build context for batch analysis."""
        context = "Analyze the following code files for security, performance, and quality issues.\n\n"

        for file_info in files:
            path = file_info["path"]
            content = file_info["content"]
            findings = file_info.get("findings", [])

            context += f"## File: {path}\n\n"
            if findings:
                context += f"Static Analysis Findings:\n{json.dumps(findings, indent=2)}\n\n"
            context += f"Code Content:\n```\n{content}\n```\n\n"

        context += "Provide your analysis for each file in the required JSON format."
        return context

    def _hash_content(self, file_path: str, content: str, findings: List) -> str:
        """Create a hash of the content for caching."""
        hasher = hashlib.sha256()
        hasher.update(file_path.encode())
        hasher.update(content.encode())
        hasher.update(json.dumps(findings, sort_keys=True).encode())
        return hasher.hexdigest()[:16]

    def _supports_json(self) -> bool:
        """Check if the model supports JSON response format."""
        return True

    def get_stats(self) -> Dict[str, int]:
        """Get LLM client statistics."""
        return self._stats.copy()

    def clear_cache(self):
        """Clear the LLM cache."""
        if self._cache:
            self._cache.clear()


def create_llm_client(**kwargs) -> LLMClient:
    """Factory function to create an LLM client."""
    return LLMClient(**kwargs)
