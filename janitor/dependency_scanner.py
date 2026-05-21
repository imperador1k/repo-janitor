"""Dependency vulnerability scanner with OSV.dev API, SQLite cache, multi-ecosystem."""

import json
import logging
import os
import re
import sqlite3
import time
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Generator

from janitor.types import Finding, RiskLevel

logger = logging.getLogger(__name__)

OSV_API_BATCH = "https://api.osv.dev/v1/query-batch"
OSV_API_QUERY = "https://api.osv.dev/v1/query"
CACHE_DIR_NAME = ".repo-janitor"
CACHE_DB_NAME = "vuln_cache.db"
CACHE_TTL_HOURS = 24


@dataclass
class Dependency:
    """A single dependency with exact version."""
    name: str
    version: str
    ecosystem: str
    file_path: str
    line_number: int
    source_line: str = ""


@dataclass
class Vulnerability:
    """A vulnerability from OSV.dev."""
    id: str
    summary: str
    severity: str
    cvss_score: Optional[float]
    aliases: List[str]
    fixed_version: Optional[str]
    ecosystem: str
    package_name: str
    affected_versions: List[str]
    references: List[str] = field(default_factory=list)


class VulnCache:
    """SQLite-based cache for OSV vulnerability data."""

    def __init__(self, repo_path: Path):
        cache_dir = repo_path / CACHE_DIR_NAME
        cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = cache_dir / CACHE_DB_NAME
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vuln_cache (
                    package_name TEXT NOT NULL,
                    ecosystem TEXT NOT NULL,
                    version TEXT NOT NULL,
                    response TEXT NOT NULL,
                    queried_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (package_name, ecosystem, version)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vuln_details (
                    vuln_id TEXT PRIMARY KEY,
                    details TEXT NOT NULL,
                    queried_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rate_limit (
                    id INTEGER PRIMARY KEY,
                    last_query TIMESTAMP,
                    queries_remaining INTEGER DEFAULT 30
                )
            """)

    def close(self):
        """Close any open connections."""
        pass  # Using context managers, no persistent conn

    def __del__(self):
        self.close()

    def get_cached(self, package_name: str, ecosystem: str, version: str) -> Optional[List[dict]]:
        """Get cached vulnerability response if fresh."""
        cutoff = (datetime.now() - timedelta(hours=CACHE_TTL_HOURS)).isoformat()
        with sqlite3.connect(str(self.db_path)) as conn:
            row = conn.execute(
                "SELECT response, queried_at FROM vuln_cache WHERE package_name=? AND ecosystem=? AND version=?",
                (package_name, ecosystem, version)
            ).fetchone()
            if row:
                response, queried = row
                if queried >= cutoff:
                    data = json.loads(response)
                    return data.get("vulns", [])
        return None

    def set_cached(self, package_name: str, ecosystem: str, version: str, vulns: List[dict]):
        """Cache vulnerability response."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO vuln_cache (package_name, ecosystem, version, response, queried_at) VALUES (?, ?, ?, ?, ?)",
                (package_name, ecosystem, version, json.dumps({"vulns": vulns}), datetime.now().isoformat())
            )

    def get_vuln_detail(self, vuln_id: str) -> Optional[dict]:
        with sqlite3.connect(str(self.db_path)) as conn:
            row = conn.execute(
                "SELECT details FROM vuln_details WHERE vuln_id=?", (vuln_id,)
            ).fetchone()
            if row:
                return json.loads(row[0])
        return None

    def set_vuln_detail(self, vuln_id: str, details: dict):
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO vuln_details (vuln_id, details, queried_at) VALUES (?, ?, ?)",
                (vuln_id, json.dumps(details), datetime.now().isoformat())
            )


class DependencyParser:
    """Parse dependency files for each ecosystem."""

    NPM_LOCK_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
    PIP_LOCK_FILES = {"poetry.lock", "Pipfile.lock"}
    COMPOSER_LOCK = "composer.lock"
    CARGO_LOCK = "Cargo.lock"
    GEMFILE_LOCK = "Gemfile.lock"
    GO_MOD = "go.mod"

    def find_dep_files(self, root_path: Path) -> List[Path]:
        """Find all dependency files in repository."""
        found = []
        for dirpath, dirnames, filenames in os.walk(root_path):
            dirpath_p = Path(dirpath)
            # Skip common ignore dirs
            parts = set(dirpath_p.relative_to(root_path).parts) if dirpath_p != root_path else set()
            ignored_dirs = {'.git', 'node_modules', 'venv', '.venv', '__pycache__',
                           '.mypy_cache', '.pytest_cache', 'dist', 'build', 'target'}
            if parts & ignored_dirs:
                continue

            for fname in filenames:
                fpath = dirpath_p / fname
                if fname in self.NPM_LOCK_FILES or fname in self.PIP_LOCK_FILES:
                    found.append(fpath)
                elif fname in {self.COMPOSER_LOCK, self.CARGO_LOCK, self.GEMFILE_LOCK, self.GO_MOD}:
                    found.append(fpath)
                elif fname == "package.json":
                    found.append(fpath)
                elif fname == "requirements.txt":
                    found.append(fpath)
                elif fname == "Pipfile":
                    found.append(fpath)
                elif fname == "composer.json":
                    found.append(fpath)
                elif fname == "Cargo.toml":
                    found.append(fpath)
                elif fname == "Gemfile":
                    found.append(fpath)
                elif fname == "go.sum":
                    found.append(fpath)
                elif fname == "pom.xml":
                    found.append(fpath)
                elif fname.endswith(".csproj") or fname == "packages.config":
                    found.append(fpath)
                elif fname == "build.gradle" or fname == "build.gradle.kts":
                    found.append(fpath)
        return found

    def parse_file(self, file_path: Path) -> Generator[Dependency, None, None]:
        """Parse a dependency file and yield Dependencies."""
        fname = file_path.name
        try:
            if fname == "package-lock.json":
                yield from self._parse_npm_lock(file_path)
            elif fname == "yarn.lock":
                yield from self._parse_yarn_lock(file_path)
            elif fname == "package.json":
                yield from self._parse_package_json(file_path)
            elif fname in self.PIP_LOCK_FILES:
                yield from self._parse_toml_lock(file_path, "PyPI")
            elif fname == "requirements.txt":
                yield from self._parse_requirements_txt(file_path)
            elif fname == "Pipfile":
                yield from self._parse_pipfile(file_path)
            elif fname == self.COMPOSER_LOCK:
                yield from self._parse_composer_lock(file_path)
            elif fname == "composer.json":
                yield from self._parse_composer_json(file_path)
            elif fname == self.CARGO_LOCK:
                yield from self._parse_cargo_lock(file_path)
            elif fname == "Cargo.toml":
                yield from self._parse_cargo_toml(file_path)
            elif fname == self.GEMFILE_LOCK:
                yield from self._parse_gemfile_lock(file_path)
            elif fname == "Gemfile":
                yield from self._parse_gemfile(file_path)
            elif fname == self.GO_MOD:
                yield from self._parse_go_mod(file_path)
            elif fname == "pom.xml":
                yield from self._parse_pom_xml(file_path)
            elif fname.endswith(".csproj"):
                yield from self._parse_csproj(file_path)
            elif fname == "packages.config":
                yield from self._parse_packages_config(file_path)
            elif fname == "build.gradle" or fname == "build.gradle.kts":
                yield from self._parse_gradle(file_path)
        except Exception as e:
            logger.warning(f"Failed to parse {file_path}: {e}")

    def _parse_npm_lock(self, file_path: Path) -> Generator[Dependency, None, None]:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        packages = data.get("packages", data.get("dependencies", {}))
        for name, info in packages.items():
            if name and isinstance(info, dict):
                ver = info.get("version", "")
                if ver:
                    # Strip workspace protocol
                    ver = ver.replace("workspace:", "")
                    yield Dependency(
                        name=name.lstrip("@"),
                        version=ver.lstrip("^~>=<"),
                        ecosystem="npm",
                        file_path=str(file_path.relative_to(self._root) if hasattr(self, '_root') else file_path),
                        line_number=0,
                    )

    def _parse_yarn_lock(self, file_path: Path) -> Generator[Dependency, None, None]:
        seen: Set[str] = set()
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        for match in re.finditer(r'^"?(.+?)@[^,]*?:\n\s+version\s+"(\S+)"', content, re.MULTILINE):
            name = match.group(1).split("@")[0].strip('"')
            ver = match.group(2)
            key = f"{name}@{ver}"
            if key not in seen and name and ver:
                seen.add(key)
                yield Dependency(
                    name=name,
                    version=ver,
                    ecosystem="npm",
                    file_path=str(file_path.relative_to(self._root) if hasattr(self, '_root') else file_path),
                    line_number=0,
                )

    def _parse_package_json(self, file_path: Path) -> Generator[Dependency, None, None]:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            deps = data.get(section, {})
            for name, ver in deps.items():
                if isinstance(ver, str):
                    # Extract exact version from range
                    exact = re.sub(r'^[~^>=<]*', '', ver).split('<')[0].split('||')[0].strip()
                    if exact and re.match(r'^\d+\.\d+', exact):
                        yield Dependency(
                            name=name,
                            version=exact,
                            ecosystem="npm",
                            file_path=str(file_path.relative_to(self._root) if hasattr(self, '_root') else file_path),
                            line_number=0,
                        )

    def _parse_requirements_txt(self, file_path: Path) -> Generator[Dependency, None, None]:
        with open(file_path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith(('#', '-', '--')):
                    continue
                # Strip environment markers (after ;)
                line = line.split(';')[0].strip()
                parts = re.split(r'\s*(===?|>=?|<=?|~=|!=)\s*', line, maxsplit=1)
                name = parts[0].strip().lower()
                if len(parts) >= 3:
                    ver = parts[2].strip().rstrip(',').split(',')[0].strip()
                    if ver and re.match(r'^\d', ver):
                        yield Dependency(
                            name=name, version=ver, ecosystem="PyPI",
                            file_path=str(file_path), line_number=i, source_line=line,
                        )
                elif name and not name.startswith(('#', '-')):
                    # No version constraint — still yield to check latest
                    pass

    def _parse_pipfile(self, file_path: Path) -> Generator[Dependency, None, None]:
        yield from self._parse_toml_generic(file_path, "PyPI", ("packages", "dev-packages"))

    def _parse_toml_lock(self, file_path: Path, ecosystem: str) -> Generator[Dependency, None, None]:
        yield from self._parse_toml_generic(file_path, ecosystem)

    def _parse_toml_generic(self, file_path: Path, ecosystem: str, sections: Tuple[str, ...] = ()) -> Generator[Dependency, None, None]:
        import tomllib
        with open(file_path, "rb") as f:
            data = tomllib.load(f)
        to_check = sections if sections else data.keys()
        for section in to_check:
            pkgs = data.get(section, {})
            if isinstance(pkgs, dict):
                for name, info in pkgs.items():
                    if isinstance(info, dict):
                        ver = info.get("version", "")
                        if ver:
                            yield Dependency(
                                name=name, version=ver.lstrip("^~>=<"),
                                ecosystem=ecosystem,
                                file_path=str(file_path), line_number=0,
                            )

    def _parse_composer_lock(self, file_path: Path) -> Generator[Dependency, None, None]:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for pkg in data.get("packages", data.get("packages-dev", [])):
            name = pkg.get("name", "")
            ver = pkg.get("version", "").lstrip("v")
            if name and ver:
                yield Dependency(
                    name=name, version=ver, ecosystem="Packagist",
                    file_path=str(file_path), line_number=0,
                )

    def _parse_composer_json(self, file_path: Path) -> Generator[Dependency, None, None]:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for section in ("require", "require-dev"):
            deps = data.get(section, {})
            for name, ver in deps.items():
                exact = re.sub(r'[~^>=<*]', '', ver).strip()
                if exact and re.match(r'^\d', exact):
                    yield Dependency(
                        name=name, version=exact, ecosystem="Packagist",
                        file_path=str(file_path), line_number=0,
                    )

    def _parse_cargo_lock(self, file_path: Path) -> Generator[Dependency, None, None]:
        import tomllib
        with open(file_path, "rb") as f:
            data = tomllib.load(f)
        for pkg in data.get("package", []):
            name = pkg.get("name", "")
            ver = pkg.get("version", "")
            if name and ver:
                yield Dependency(
                    name=name, version=ver, ecosystem="crates.io",
                    file_path=str(file_path), line_number=0,
                )

    def _parse_cargo_toml(self, file_path: Path) -> Generator[Dependency, None, None]:
        import tomllib
        with open(file_path, "rb") as f:
            data = tomllib.load(f)
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            deps = data.get(section, {})
            if isinstance(deps, dict):
                for name, info in deps.items():
                    if isinstance(info, str):
                        exact = re.sub(r'[~^>=<*]', '', info).strip()
                        if exact and re.match(r'^\d', exact):
                            yield Dependency(name=name, version=exact, ecosystem="crates.io", file_path=str(file_path), line_number=0)
                    elif isinstance(info, dict):
                        ver = info.get("version", "")
                        if ver:
                            yield Dependency(name=name, version=ver.lstrip("^~>=<"), ecosystem="crates.io", file_path=str(file_path), line_number=0)

    def _parse_gemfile_lock(self, file_path: Path) -> Generator[Dependency, None, None]:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        current_name = None
        for line in content.split("\n"):
            m = re.match(r'^\s{4}(\S+)', line)
            if m:
                current_name = m.group(1)
            m_ver = re.match(r'^\s{8}(\S+)', line)
            if m_ver and current_name:
                yield Dependency(name=current_name, version=m_ver.group(1), ecosystem="RubyGems", file_path=str(file_path), line_number=0)
                current_name = None

    def _parse_gemfile(self, file_path: Path) -> Generator[Dependency, None, None]:
        with open(file_path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                m = re.match(r'^\s*gem\s+["\']([^"\']+)["\'][,\s]*["\']([^"\']+)["\']', line)
                if m:
                    ver = m.group(2).lstrip("~> =<")
                    if ver and re.match(r'^\d', ver):
                        yield Dependency(name=m.group(1), version=ver, ecosystem="RubyGems", file_path=str(file_path), line_number=i)

    def _parse_go_mod(self, file_path: Path) -> Generator[Dependency, None, None]:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        for m in re.finditer(r'^\s+(\S+)\s+v(\d+\.\d+\.\d+)', content, re.MULTILINE):
            name = m.group(1)
            ver = "v" + m.group(2)
            if name and "/" in name:
                yield Dependency(name=name, version=ver, ecosystem="Go", file_path=str(file_path), line_number=0)

    def _parse_pom_xml(self, file_path: Path) -> Generator[Dependency, None, None]:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        # Parse parent
        parent = re.search(r'<parent>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>', content, re.DOTALL)
        if parent:
            yield Dependency(name=f"{parent.group(1)}:{parent.group(2)}", version=parent.group(3), ecosystem="Maven", file_path=str(file_path), line_number=0)
        # Parse dependencies
        dep_pattern = re.compile(
            r'<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>',
            re.DOTALL
        )
        for m in dep_pattern.finditer(content):
            gid = m.group(1).strip()
            aid = m.group(2).strip()
            ver = m.group(3).strip()
            # Resolve properties
            ver = self._resolve_properties(ver, content)
            if ver and re.match(r'^\d', ver):
                yield Dependency(name=f"{gid}:{aid}", version=ver, ecosystem="Maven", file_path=str(file_path), line_number=0)

    def _resolve_properties(self, value: str, content: str) -> str:
        prop_m = re.match(r'\$\{(.+)\}', value)
        if prop_m:
            prop_name = prop_m.group(1)
            prop_v = re.search(rf'<{prop_name}>(.*?)</{prop_name}>', content)
            if prop_v:
                return prop_v.group(1).strip()
        return value

    def _parse_csproj(self, file_path: Path) -> Generator[Dependency, None, None]:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        for m in re.finditer(r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"', content):
            yield Dependency(name=m.group(1), version=m.group(2), ecosystem="NuGet", file_path=str(file_path), line_number=0)
        for m in re.finditer(r'<PackageReference Include="([^"]+)"[^>]*>\s*<Version>([^<]+)</Version>', content):
            yield Dependency(name=m.group(1), version=m.group(2).strip(), ecosystem="NuGet", file_path=str(file_path), line_number=0)

    def _parse_packages_config(self, file_path: Path) -> Generator[Dependency, None, None]:
        with open(file_path, "r", encoding="utf-8") as f:
            for m in re.finditer(r'<package\s+id="([^"]+)"\s+version="([^"]+)"', f.read()):
                yield Dependency(name=m.group(1), version=m.group(2), ecosystem="NuGet", file_path=str(file_path), line_number=0)

    def _parse_gradle(self, file_path: Path) -> Generator[Dependency, None, None]:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        for m in re.finditer(r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]", content):
            yield Dependency(name=f"{m.group(1)}:{m.group(2)}", version=m.group(3), ecosystem="Maven", file_path=str(file_path), line_number=0)


class OSVClient:
    """Client for OSV.dev vulnerability API with caching and rate limiting."""

    def __init__(self, repo_path: Path):
        self.cache = VulnCache(repo_path)
        self._last_request = 0.0
        self._rate_remaining = 30
        self._rate_reset = time.time() + 60
        self.stats: Dict[str, int] = {"requests": 0, "cache_hits": 0, "errors": 0, "vulns_found": 0}

    def _respect_rate_limit(self):
        now = time.time()
        if now < self._rate_reset and self._rate_remaining <= 0:
            sleep_time = self._rate_reset - now + 1
            logger.debug(f"Rate limited, sleeping {sleep_time:.1f}s")
            time.sleep(sleep_time)
        if now >= self._rate_reset:
            self._rate_remaining = 30
            self._rate_reset = now + 60

    def _osv_ecosystem(self, eco: str) -> str:
        mapping = {
            "npm": "npm", "PyPI": "PyPI", "Maven": "Maven",
            "NuGet": "NuGet", "Packagist": "Packagist", "Go": "Go",
            "crates.io": "crates.io", "RubyGems": "RubyGems",
        }
        return mapping.get(eco, eco)

    def query_package(self, dep: Dependency) -> List[dict]:
        """Query OSV.dev for a single package version. Returns list of vuln dicts."""
        eco = self._osv_ecosystem(dep.ecosystem)
        ver = dep.version.lstrip("v")

        # Check cache
        cached = self.cache.get_cached(dep.name, eco, ver)
        if cached is not None:
            self.stats["cache_hits"] += 1
            return cached

        self._respect_rate_limit()
        payload = {
            "package": {"name": dep.name, "ecosystem": eco},
            "version": ver,
        }
        try:
            req = urllib.request.Request(
                OSV_API_QUERY,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
            )
            self._last_request = time.time()
            self.stats["requests"] += 1
            self._rate_remaining -= 1

            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
                vulns = data.get("vulns", [])

            self.cache.set_cached(dep.name, eco, ver, vulns)
            return vulns
        except urllib.error.HTTPError as e:
            self.stats["errors"] += 1
            if e.code == 404:
                self.cache.set_cached(dep.name, eco, ver, [])
                return []
            logger.debug(f"OSV HTTP {e.code} for {dep.name}@{ver}")
            return []
        except Exception as e:
            self.stats["errors"] += 1
            logger.debug(f"OSV error for {dep.name}@{ver}: {e}")
            return []

    def query_batch(self, deps: List[Dependency]) -> List[Tuple[Dependency, List[dict]]]:
        """Query multiple packages. Returns list of (dep, vulns) tuples."""
        results: List[Tuple[Dependency, List[dict]]] = []
        # Try cache first for all
        uncached: List[Dependency] = []
        eco_map: Dict[str, Dependency] = {}

        for dep in deps:
            eco = self._osv_ecosystem(dep.ecosystem)
            ver = dep.version.lstrip("v")
            cached = self.cache.get_cached(dep.name, eco, ver)
            if cached is not None:
                self.stats["cache_hits"] += 1
                results.append((dep, cached))
            else:
                uncached.append(dep)
                eco_map[f"{dep.name}@{dep.ecosystem}"] = dep

        # Batch query uncached deps (up to 1000 per batch)
        if uncached:
            self._respect_rate_limit()
            queries = []
            for dep in uncached:
                eco = self._osv_ecosystem(dep.ecosystem)
                ver = dep.version.lstrip("v")
                queries.append({"package": {"name": dep.name, "ecosystem": eco}, "version": ver})

            try:
                # OSV batch is limited; if too many, split
                batch_size = 500
                for i in range(0, len(queries), batch_size):
                    batch = queries[i:i + batch_size]
                    payload = {"queries": batch}
                    req = urllib.request.Request(
                        OSV_API_BATCH,
                        data=json.dumps(payload).encode(),
                        headers={"Content-Type": "application/json"},
                    )
                    self.stats["requests"] += 1
                    self._rate_remaining -= 1
                    with urllib.request.urlopen(req, timeout=30) as resp:
                        resp_data = json.loads(resp.read().decode())
                    raw_results = resp_data.get("results", [])
                    for j, result in enumerate(raw_results):
                        if i + j < len(uncached):
                            dep = uncached[i + j]
                            vulns = result.get("vulns", [])
                            self.cache.set_cached(dep.name, self._osv_ecosystem(dep.ecosystem),
                                                  dep.version.lstrip("v"), vulns)
                            results.append((dep, vulns))
            except Exception as e:
                logger.debug(f"Batch query error: {e}")
                self.stats["errors"] += 1
                # Fall back to individual queries for remaining
                for dep in uncached:
                    vulns = self.query_package(dep)
                    results.append((dep, vulns))

        return results


class DependencyScanner:
    """Scans repository for dependency files and queries OSV for vulnerabilities."""

    ECOSYSTEM_NAMES = {
        "npm": "npm (Node.js/JavaScript/TypeScript)",
        "PyPI": "PyPI (Python)",
        "Maven": "Maven (Java/Kotlin)",
        "NuGet": "NuGet (.NET/C#)",
        "Packagist": "Packagist (PHP)",
        "Go": "Go",
        "crates.io": "crates.io (Rust)",
        "RubyGems": "RubyGems (Ruby)",
    }

    def __init__(self, root_path: Path):
        self.root_path = root_path
        self.parser = DependencyParser()
        self.parser._root = root_path
        self.client = OSVClient(root_path)

    def scan(self) -> Tuple[List[Finding], Dict]:
        """Run full dependency vulnerability scan. Returns (findings, stats)."""
        dep_files = self.parser.find_dep_files(self.root_path)
        logger.info(f"Found {len(dep_files)} dependency files")

        all_deps: List[Dependency] = []
        by_ecosystem: Dict[str, int] = {}

        for fpath in dep_files:
            try:
                for dep in self.parser.parse_file(fpath):
                    all_deps.append(dep)
                    by_ecosystem[dep.ecosystem] = by_ecosystem.get(dep.ecosystem, 0) + 1
            except Exception as e:
                logger.warning(f"Error parsing {fpath}: {e}")

        # Deduplicate by (name, ecosystem, version)
        seen: Set[str] = set()
        unique_deps: List[Dependency] = []
        for dep in all_deps:
            key = f"{dep.name}@{dep.ecosystem}@{dep.version}"
            if key not in seen:
                seen.add(key)
                unique_deps.append(dep)

        logger.info(f"Found {len(unique_deps)} unique dependencies across {len(by_ecosystem)} ecosystems")

        findings: List[Finding] = []
        vulns_found = 0

        # Query batch
        results = self.client.query_batch(unique_deps)
        for dep, vulns in results:
            if vulns:
                vulns_found += len(vulns)
                self._add_vuln_findings(findings, dep, vulns)

        stats = {
            "dep_files_found": len(dep_files),
            "dep_files_parsed": len(all_deps),
            "dependencies_tracked": len(unique_deps),
            "vulnerabilities_found": vulns_found,
            "by_ecosystem": by_ecosystem,
            "api_requests": self.client.stats["requests"],
            "cache_hits": self.client.stats["cache_hits"],
            "api_errors": self.client.stats["errors"],
        }

        return findings, stats

    def _add_vuln_findings(self, findings: List[Finding], dep: Dependency, vulns: List[dict]):
        """Convert OSV vulnerabilities to Finding objects."""
        severity_map = {
            "CRITICAL": RiskLevel.CRITICAL,
            "HIGH": RiskLevel.HIGH,
            "MEDIUM": RiskLevel.MEDIUM,
            "LOW": RiskLevel.LOW,
        }
        seen_ids: Set[str] = set()

        for vuln in vulns:
            vuln_id = vuln.get("id", "UNKNOWN")
            if vuln_id in seen_ids:
                continue
            seen_ids.add(vuln_id)

            aliases = vuln.get("aliases", [])
            cve = next((a for a in aliases if a.startswith("CVE-")), vuln_id)

            # Determine severity
            severity_str = vuln.get("database_specific", {}).get("severity", "")
            if not severity_str:
                severity_str = vuln.get("severity", [{}])[0].get("type", "") if isinstance(vuln.get("severity"), list) else ""
            if not severity_str or severity_str == "UNSPECIFIED":
                severity_str = "HIGH"  # Default to high if unknown

            risk = severity_map.get(severity_str.upper(), RiskLevel.HIGH)

            summary = vuln.get("summary", vuln.get("details", "No description"))
            if len(summary) > 200:
                summary = summary[:197] + "..."

            # Determine fixed version
            fixed = None
            for affected in vuln.get("affected", []):
                for ranges in affected.get("ranges", []):
                    if ranges.get("type") == "SEMVER" or ranges.get("type") == "ECOSYSTEM":
                        for event in ranges.get("events", []):
                            if "fixed" in event:
                                fixed = event["fixed"]
                                break

            finding = Finding(
                file=dep.file_path,
                line=dep.line_number,
                column=0,
                issue_type=f"DEP-{cve}",
                message=f"[{severity_str}] {dep.name}@{dep.version} - {summary}",
                risk_level=risk,
                code_snippet=dep.source_line or f"{dep.name}=={dep.version}",
                suggestion=f"Upgrade {dep.name} to version {fixed}" if fixed else f"Review advisory {vuln_id} for {dep.name}",
            )
            findings.append(finding)

    def print_summary(self, findings: List[Finding], stats: Dict):
        """Print a summary of dependency findings."""
        eco_names = self.ECOSYSTEM_NAMES
        print(f"\n{'='*60}")
        print(f"  DEPENDENCY VULNERABILITY SCAN")
        print(f"{'='*60}")
        print(f"  Dependency files found: {stats['dep_files_found']}")
        print(f"  Dependencies tracked:   {stats['dependencies_tracked']}")
        print(f"  Vulnerabilities found:  {stats['vulnerabilities_found']}")
        print(f"  API requests:           {stats['api_requests']}")
        print(f"  Cache hits:             {stats['cache_hits']}")
        print()
        if stats.get("by_ecosystem"):
            print(f"  Ecosystems:")
            for eco, count in sorted(stats["by_ecosystem"].items(), key=lambda x: -x[1]):
                name = eco_names.get(eco, eco)
                print(f"    {name}: {count} dependencies")
        print()

        if findings:
            sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for f in findings:
                for sev in sev_counts:
                    if f.risk_level.value.upper() == sev or f.risk_level.name.upper() == sev:
                        sev_counts[sev] = sev_counts.get(sev, 0) + 1
                        break
            print(f"  By severity:")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if sev_counts[sev]:
                    print(f"    {sev}: {sev_counts[sev]}")
            print()
