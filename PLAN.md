# 🏗️ **repo-janitor: Plano Arquitetural — Nível Google**

> Documento confidencial. Versão 2.0.
> Objectivo: Transformar repo-janitor numa ferramenta de segurança enterprise-level
> que uma big tech como a Google pagaria para usar.

---

## Índice

1. [Diagnóstico Zero — Onde Estamos Hoje](#1-diagnóstico-zero)
2. [Visão Arquitetural — O Destino](#2-visão-arquitetural)
3. [Fase 1 — Fundação Enterprise](#3-fase-1--fundação-enterprise)
4. [Fase 2 — Cobertura Total de Linguagens](#4-fase-2--cobertura-total-de-linguagens)
5. [Fase 3 — Engine AST/IR (O Game-Changer)](#5-fase-3--engine-astir-o-game-changer)
6. [Fase 4 — Dataflow Inter-Procedural](#6-fase-4--dataflow-inter-procedural)
7. [Fase 5 — IaC + Cloud + Container](#7-fase-5--iac--cloud--container)
8. [Fase 6 — Dependency Scanner 2.0](#8-fase-6--dependency-scanner-20)
9. [Fase 7 — AI Profunda (Auto-Remediation)](#9-fase-7--ai-profunda-auto-remediation)
10. [Fase 8 — Enterprise + CI/CD](#10-fase-8--enterprise--cicd)
11. [Fase 9 — Monetização / Go-to-Market](#11-fase-9--monetização--go-to-market)
12. [O Problema do Contexto (A Tua Obsessão)](#12-o-problema-do-contexto-a-tua-obsessão)
13. [Roadmap Temporal](#13-roadmap-temporal)
14. [Resposta à Pergunta Final](#14-resposta-à-pergunta-final)

---

## 1. Diagnóstico Zero — Onde Estamos Hoje

### ✅ Forças

| Dimensão | Nota | Detalhe |
|---|---|---|
| Cobertura linguagens | 7/10 | 8 linguagens com análises elite (50-66 checks) |
| Profundidade dos checks | 8/10 | CWE + OWASP + MITRE mapping |
| Dependency scanner | 6/10 | OSV.dev c/ cache SQLite, 8 ecossistemas |
| CLI | 6/10 | `--json`, `--deps`, `--min-severity`, rich tables |
| Arquitetura (registry pattern) | 7/10 | Fácil adicionar novas linguagens |
| LLM integration | 5/10 | NVIDIA NIM, batch, cache 24h |

### ❌ Fraquezas Críticas

| Problema | Gravidade | Impacto |
|---|---|---|
| **100% regex** — sem AST/IR parsing | 🔴 Crítico | Falsos positivos, não deteta padrões complexos |
| **Intra-file only** — sem call graph | 🔴 Crítico | Perde dataflow entre ficheiros |
| **Sem Rust / Ruby / C++ / Dart / Swift** | 🟡 Alto | 40%+ dos projetos ficam de fora |
| **Sem IaC / Docker / K8s / Terraform** | 🟡 Alto | 50% da superfície de ataque moderna |
| **Sem CI/CD nativo (GitHub Actions)** | 🟡 Alto | Adoção limitada |
| **Sem SARIF output** | 🟡 Médio | Não integra com GitHub Security Tab |
| **Legacy files (`core.py`, `js_analyzer.py`, `manager.py`)** | 🟢 Baixo | Código morto, import errors potenciais |
| **Versão inconsistente (0.1.0 vs 1.0.0)** | 🟢 Baixo | `pyproject.toml` diz 0.1.0, `__init__.py` diz 1.0.0 |
| **`pydantic` missing from pyproject.toml** | 🟢 Baixo | `requirements.txt` tem, `pyproject.toml` não |
| **24 testes apenas** | 🟡 Médio | Testing coverage insuficiente |

### 🎯 Rating Geral Atual: **4.5 / 10**

---

## 2. Visão Arquitetural — O Destino

```
┌─────────────────────────────────────────────────────────────────┐
│                    repo-janitor ENGINE 2.0                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    ORCHESTRATOR                          │    │
│  │  (CLI / API / GitHub Action / VS Code Extension)        │    │
│  └──────────────────────┬──────────────────────────────────┘    │
│                         │                                       │
│  ┌──────────────────────▼──────────────────────────────────┐    │
│  │              PIPELINE MANAGER                            │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  │    │
│  │  │ Language │  │  SAST    │  │ Dataflow │  │  Deps  │  │    │
│  │  │ Detector │  │  Engine  │  │ Analyzer │  │ Scanner│  │    │
│  │  └──────────┘  └──────────┘  └──────────┘  └────────┘  │    │
│  └──────────────────────┬──────────────────────────────────┘    │
│                         │                                       │
│  ┌──────────────────────▼──────────────────────────────────┐    │
│  │                ANALYSIS LAYER                            │    │
│  │                                                          │    │
│  │  ┌──────────────────────────────────────────────────┐    │    │
│  │  │          AST/IR ENGINE (tree-sitter)              │    │    │
│  │  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐   │    │    │
│  │  │  │Python│ │  JS  │ │Java │ │Rust │ │ ...  │   │    │    │
│  │  │  │ AST  │ │ AST  │ │ AST  │ │ AST  │ │ AST  │   │    │    │
│  │  │  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘   │    │    │
│  │  └──────────────────────────────────────────────────┘    │    │
│  │                                                          │    │
│  │  ┌──────────────────────────────────────────────────┐    │    │
│  │  │        SYMBOLIC EXECUTION ENGINE                  │    │    │
│  │  │  (Path exploration, constraint solving)           │    │    │
│  │  └──────────────────────────────────────────────────┘    │    │
│  │                                                          │    │
│  │  ┌──────────────────────────────────────────────────┐    │    │
│  │  │        TAINT ENGINE (Inter-Procedural)            │    │    │
│  │  │  Sources → Propagators → Sinks (with sanitizers) │    │    │
│  │  └──────────────────────────────────────────────────┘    │    │
│  │                                                          │    │
│  │  ┌──────────────────────────────────────────────────┐    │    │
│  │  │     IaC / CLOUD / CONTAINER ANALYZER             │    │    │
│  │  │  Docker, K8s, Terraform, CloudFormation, Helm    │    │    │
│  │  └──────────────────────────────────────────────────┘    │    │
│  │                                                          │    │
│  │  ┌──────────────────────────────────────────────────┐    │    │
│  │  │     DEPENDENCY SCANNER 2.0                        │    │    │
│  │  │  OSV.dev + NVD + GitHub Advisory + EPSS + PoC    │    │    │
│  │  └──────────────────────────────────────────────────┘    │    │
│  │                                                          │    │
│  │  ┌──────────────────────────────────────────────────┐    │    │
│  │  │     AI ENGINE (Auto-Remediation)                  │    │    │
│  │  │  Fix generation + PR creation + False positive    │    │    │
│  │  │  learning + Context memory                        │    │    │
│  │  └──────────────────────────────────────────────────┘    │    │
│  └──────────────────────┬──────────────────────────────────┘    │
│                         │                                       │
│  ┌──────────────────────▼──────────────────────────────────┐    │
│  │              OUTPUT LAYER                               │    │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐ │    │
│  │  │  SARIF   │ │  JSON    │ │  HTML    │ │ SECURITY   │ │    │
│  │  │          │ │  (CI/CD) │ │ Dashboard│ │ _AUDIT.md  │ │    │
│  │  └──────────┘ └──────────┘ └──────────┘ └────────────┘ │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Fase 1 — Fundação Enterprise

*(Duração: Semanas 1-2)*

### 3.1 Fix Bugs Existentes

| Problema | Ficheiro | Ação |
|---|---|---|
| Versão inconsistente | `pyproject.toml:7` + `janitor/__init__.py:1` | Unificar para `0.1.0` (dev) |
| `core.py` importa `PythonAnalysisResult` de `analyzer.py` (não existe) | `core.py:4` | Atualizar para `types.py` |
| `core.py` importa `JSAnalyzer` de `js_analyzer.py` (legacy) | `core.py:5` | Remover ou redirecionar para `analyzers.javascript` |
| `pydantic` ausente do `pyproject.toml` | `pyproject.toml:28` | Adicionar `pydantic>=2.5.0` |
| `js_analyzer.py` (legacy, não integrado) | Ficheiro raiz | Mover para `analyzers/_legacy` ou remover |

### 3.2 Renovação da Arquitetura Base

```
janitor/
├── __init__.py          # versão única
├── types.py             # Finding, RiskLevel + novos tipos
├── scanner.py           # melhorado (mais extensões, perf)
├── language_detector.py # melhorado (mais linguagens)
├── cli.py               # CLI refatorada (modular)
├── llm.py               # + modelos (OpenAI, Anthropic, Ollama)
├── dependency_scanner/  # era ficheiro único, agora pacote
│   ├── __init__.py
│   ├── client.py        # OSV + NVD + GitHub Advisory
│   ├── parsers.py       # parsers de ficheiros de dependências
│   ├── cache.py         # SQLite cache
│   └── models.py        # Dependency, Vulnerability
├── engine/              # NOVO — motor de análise
│   ├── __init__.py
│   ├── registry.py      # registo de checks
│   ├── ast/             # AST parsing (tree-sitter)
│   ├── dataflow/        # taint tracking inter-procedural
│   └── ir/              # intermediate representation
├── analyzers/           # pacote existente, expandido
│   ├── __init__.py      # registry com 13+ analisadores
│   ├── base.py          # BaseAnalyzer melhorado
│   ├── python.py        # elite (60+ checks)
│   ├── javascript.py    # elite (50+ checks)
│   ├── typescript.py    # elite (59 checks)
│   ├── kotlin.py        # elite (57 checks)
│   ├── java.py          # elite (66 checks)
│   ├── go.py            # elite (50+ checks)
│   ├── csharp.py        # elite (59 checks)
│   ├── php.py           # elite (51 checks)
│   ├── rust.py          # NOVO — 50+ checks
│   ├── ruby.py          # NOVO — 50+ checks
│   ├── dart.py          # NOVO — Flutter/Dart
│   ├── c_cpp.py         # NOVO — C/C++ (buffer overflow, etc)
│   └── swift.py         # NOVO — Swift/iOS
├── iac/                 # NOVO — IaC scanning
│   ├── __init__.py
│   ├── docker.py        # Dockerfile analyzer
│   ├── kubernetes.py    # K8s manifests analyzer
│   ├── terraform.py     # Terraform/HCL analyzer
│   └── cloudformation.py# CloudFormation analyzer
├── context/             # NOVO — motor de contexto
│   ├── __init__.py
│   ├── project_graph.py # grafo de dependências do projeto
│   ├── file_summarizer.py    # resumo de cada ficheiro
│   └── project_context.py    # contexto completo do projeto
├── remediation/         # NOVO — auto-fix
│   ├── __init__.py
│   ├── dep_fixer.py     # auto-upgrade dependências
│   ├── code_fixer.py    # auto-fix código (com AI)
│   └── pr_creator.py    # GitHub PR automation
├── outputs/             # NOVO — output processors
│   ├── __init__.py
│   ├── sarif.py         # SARIF output
│   ├── html.py          # HTML dashboard
│   └── json.py          # JSON output (melhorado)
├── integrations/        # NOVO — CI/CD integrations
│   ├── __init__.py
│   └── github_actions.py # GitHub Action
├── tests/
│   ├── test_*.py        # expandir para 100+ testes
│   ├── fixtures/        # projetos exemplo para testar
│   └── benchmarks/      # benchmark contra OWASP Benchmark
└── legacy/              # código antigo movido
    ├── core.py
    ├── js_analyzer.py
    └── manager.py
```

### 3.3 Testes: de 24 → 100+

```
tests/
├── test_python_analyzer.py    # 15 testes
├── test_javascript_analyzer.py # 10 testes
├── test_typescript_analyzer.py # 10 testes
├── test_kotlin_analyzer.py     # 10 testes
├── test_java_analyzer.py       # 10 testes
├── test_go_analyzer.py         # 10 testes
├── test_csharp_analyzer.py     # 10 testes
├── test_php_analyzer.py        # 10 testes
├── test_rust_analyzer.py       # 10 testes (novo)
├── test_dep_scanner.py         # 15 testes
├── test_scanner.py             # 5 testes
├── test_cli.py                 # 10 testes
├── test_language_detector.py   # 5 testes
├── test_llm.py                 # 5 testes (mock)
├── test_engine.py              # 10 testes (dataflow)
├── test_iac.py                 # 10 testes (docker/k8s/tf)
├── test_outputs.py             # 5 testes (SARIF, JSON)
├── test_remediation.py         # 5 testes
├── benchmarks/
│   ├── owasp_benchmark.py      # benchmark contra OWASP Benchmark
│   └── juice_shop.py           # benchmark contra OWASP Juice Shop
└── fixtures/
    ├── vulnerable_project/     # projeto propositadamente vulnerável
    └── secure_project/         # projeto seguro (testar FPs)
```

**Objectivo:** 100+ testes, code coverage > 85%, FP/FN rate documented.

---

## 4. Fase 2 — Cobertura Total de Linguagens

*(Duração: Semanas 3-6)*

### 4.1 Rust Analyzer — 50+ Checks

**Ficheiro:** `janitor/analyzers/rust.py`

| Categoria | Checks | Exemplos |
|---|---|---|
| **Memory Safety** | 8 | `unsafe` blocks, raw pointer dereference, `transmute`, `transmute_copy`, `core::mem::zeroed`, uninitialized, `MaybeUninit` misuse, `forget` |
| **Concurrency** | 5 | `Send`/`Sync` violations, `Mutex` poisoning, `Arc` misuse, `static mut`, `thread::spawn` sem JoinHandle |
| **Command Injection** | 3 | `std::process::Command` com shell, `format!` em shell args, `open` com user input |
| **SQL Injection** | 3 | `diesel::sql_query` concat, `sqlx::query` format string, `rusqlite` raw query |
| **Path Traversal** | 2 | `Path::new` + user input sem canonicalize, `File::open` com input |
| **Crypto** | 4 | MD5/SHA1 hardcoded, `rand::thread_rng` para crypto, hardcoded keys, `secret` exposto |
| **Network** | 3 | HTTP sem TLS (`http://`), `Incoming` sem TLS, `accept` sem auth |
| **Deserialization** | 3 | `serde::Deserialize` sem validação, `serde_json::from_str` com input, `pickle` (se existir) |
| **Code Quality** | 8 | `.unwrap()` sem tratamento, `panic!()`, `todo!()`, `unreachable!()`, `let _ =`, `.expect()` com msg genérica, nécto uso de `*` em wildcards, falta de doc |
| **Auth/Secrets** | 4 | Hardcoded API keys, JWT hardcoded, credenciais em env expostas, `dotenv` sem `.env.example` |
| **FFI** | 3 | `extern "C"` sem unsafe bounds, `std::ffi::CString` sem verificação, FFI callback sem safety |
| **Error Handling** | 3 | `Result` ignorado, `panic!` em library code, `unwrap` em produção |
| **Input Validation** | 4 | Missing bounds check, integer overflow, division by zero, `parse` sem error handling |

**Total:** 53 checks — com CWE, OWASP, MITRE mapping, taint analysis, cross-line, false positive filters.

### 4.2 Ruby Analyzer — 50+ Checks

**Ficheiro:** `janitor/analyzers/ruby.py`

| Categoria | Checks | Exemplos |
|---|---|---|
| **Rails-specific** | 8 | Mass assignment (`params.permit` vs `attr_accessible`), SQL injection via ActiveRecord (`where("name = '#{input}'")`), unsafe `render` (XSS), `redirect_to` com user input (open redirect), `send_file` com path traversal, `params` sem strong_parameters, `serialize` unsafe YAML, `eval` de params |
| **Command Injection** | 3 | `system("cmd #{input}")`, `` `cmd #{input}` ``, `IO.popen` com shell |
| **SQL Injection** | 4 | ActiveRecord `where("name='#{input}'")`, `find_by_sql`, `execute` raw, `Arel` sem sanitização |
| **Code Injection** | 3 | `eval(input)`, `instance_eval`, `class_eval` |
| **Deserialization** | 2 | `YAML.load(input)`, `Marshal.load(input)` |
| **Path Traversal** | 2 | `File.open(input)`, `File.read(input)` |
| **SSRF** | 2 | `open(input)`, `Net::HTTP` com user input |
| **XSS** | 3 | `raw()` sem escape, `html_safe`, `<%= input.html_safe %>` |
| **Secrets** | 3 | Hardcoded secrets, `config/secrets.yml` exposto, JWT hardcoded |
| **Auth** | 3 | `skip_before_action :authenticate`, `allow(nil)` em devise, CSRF skip |
| **Crypto** | 3 | MD5/SHA1, `Digest::MD5`, low iteration count |
| **File Upload** | 2 | Unrestricted upload, symlink follow |
| **Code Quality** | 8 | `nil` sem `&.`, `unless` aninhado, método > 15 linhas, `TODO`/`FIXME`, `eval` em produção, `return nil` desnecessário, sem comentários de documentação, variáveis não usadas |

**Total:** 50 checks.

### 4.3 Dart/Flutter Analyzer — 50+ Checks

**Ficheiro:** `janitor/analyzers/dart.py`

| Categoria | Checks | Exemplos |
|---|---|---|
| **Flutter-specific** | 8 | `Platform` channel sem validação, `MethodChannel` sem auth, insecure `http` em vez de `https`, local storage sem encryption, `sqflite` raw query injection, `WebView` sem JS disable, `Firebase` rules insegura, `SharedPreferences` para dados sensíveis |
| **Command Injection** | 2 | `Process.run` com input do utilizador, `Process.start` com shell |
| **SQL Injection** | 3 | `database.rawQuery('SELECT * FROM users WHERE id = $id')`, `sqflite` concat, `moor` raw |
| **Path Traversal** | 2 | `File(input).readAsString()`, `Directory(input).list()` |
| **Code Injection** | 2 | `dart:mirrors` reflect sem validação, `eval` style (Isolate) |
| **Secrets** | 4 | API keys hardcoded, JWT exposed, Firebase API key, `android:exported="true"` |
| **Crypto** | 3 | Custom crypto, MD5/SHA1, hardcoded IV/key |
| **Network** | 3 | HTTP sem TLS, `WebSocket` sem WSS, `HttpClient` sem certificate pinning |
| **Storage** | 3 | `SharedPreferences` para tokens, local file sem encryption, SQLite sem encryption |
| **Code Quality** | 8 | `!` sem null check, `late` sem initialization, `dynamic` excessivo, `print()` em produção, `TODO`/`FIXME`, método > 20 linhas, `as` casting sem check, `forEach` vs `for-in` |
| **Android-specific** | 5 | `android:allowBackup="true"`, `android:debuggable="true"`, `WebView` com JS, `Intent` sem validação, exported activities |

**Total:** 50 checks.

### 4.4 C/C++ Analyzer — 50+ Checks

**Ficheiro:** `janitor/analyzers/c_cpp.py`

| Categoria | Checks | Exemplos |
|---|---|---|
| **Buffer Overflow** | 8 | `strcpy`, `strcat`, `sprintf`, `gets`, `scanf("%s")`, `memcpy` sem size check, `fread` sem size, `wcscpy` |
| **Format String** | 3 | `printf(user_input)`, `fprintf(user_input)`, `syslog(user_input)` |
| **Memory Safety** | 6 | `free()` duplo, `use-after-free`, `malloc` sem `free`, `realloc` sem check, `alloca` em loop, `new`/`delete` mismatch |
| **Command Injection** | 3 | `system(user_input)`, `popen(user_input)`, `exec*` com input |
| **Path Traversal** | 2 | `fopen(user_input)`, `open(user_input)` |
| **SQL Injection** | 2 | `mysql_query` com concat, `sqlite3_exec` com concat |
| **Integer Issues** | 4 | Integer overflow, signed/unsigned mismatch, truncation, division by zero |
| **Race Conditions** | 3 | `TOCTOU`, `fopen` + `fwrite` sem lock, signal handler unsafe |
| **Crypto** | 3 | MD5/SHA1 hardcoded, `rand()` para crypto, hardcoded keys |
| **Network** | 3 | HTTP sem TLS, `recv` sem size check, `connect` sem timeout |
| **Code Quality** | 8 | `goto`, `setjmp`/`longjmp`, `#define` macros perigosos, `inline assembly`, `volatile` em shared memory, sem `const` correctness, `NULL` vs `nullptr`, sem RAII |
| **Secrets** | 3 | Hardcoded passwords, API keys em source, private key exposure |
| **Misc** | 4 | `alloca()` perigoso, `setuid`/`setgid` sem drop, `signal()` inseguro, `tmpfile()` inseguro |

**Total:** 52 checks.

### 4.5 Swift Analyzer — 50+ Checks

**Ficheiro:** `janitor/analyzers/swift.py`

| Categoria | Checks | Exemplos |
|---|---|---|
| **iOS-specific** | 8 | `UserDefaults` para dados sensíveis, `Keychain` inseguro, `UIWebView` (deprecated), `WKWebView` com JS enabled, `NSURLConnection` sem TLS, `NSKeyedUnarchiver`, `Codable` sem validação, `URLScheme` handler |
| **Force Unwrapping** | 4 | `!` em optionals, `try!`, `as!`, `ImplicitlyUnwrappedOptional` |
| **Command Injection** | 2 | `Process` com input, `bash` via `sh -c` |
| **SQL Injection** | 3 | `sqlite3_exec` concat, `CoreData` predicate injection, `GRDB` raw query |
| **Path Traversal** | 2 | `FileManager` com input, `Data(contentsOf:)` com URL |
| **SSRF** | 2 | `URLSession` com user URL, `Data(contentsOf:)` com input |
| **Secrets** | 4 | API keys hardcoded, JWT exposto, `Info.plist` secrets, Firebase plist |
| **Crypto** | 3 | `CommonCrypto` hardcoded key, MD5/SHA1, `SecRandom` mal usado |
| **Code Quality** | 8 | `fatalError()`, `preconditionFailure()`, `TODO`/`FIXME`, `NSLog` em produção, `defer` misuse, sem `guard let`, `try?` sem handle, sem doc comments |
| **Memory** | 3 | Retain cycle (`[weak self]`), `unowned` sem safety, `@escaping` closure sem weak |

**Total:** 50 checks.

### 4.6 Registar Todos no Registry

```python
# janitor/analyzers/__init__.py
from janitor.analyzers.rust import RustAnalyzer
from janitor.analyzers.ruby import RubyAnalyzer
from janitor.analyzers.dart import DartAnalyzer
from janitor.analyzers.c_cpp import CppAnalyzer
from janitor.analyzers.swift import SwiftAnalyzer

ANALYZER_REGISTRY["rust"] = RustAnalyzer
ANALYZER_REGISTRY["ruby"] = RubyAnalyzer
ANALYZER_REGISTRY["dart"] = DartAnalyzer
ANALYZER_REGISTRY["cpp"] = CppAnalyzer
ANALYZER_REGISTRY["swift"] = SwiftAnalyzer
```

### 4.7 Mapa de Extensões — Scanner + Language Detector

```python
SUPPORTED_EXTENSIONS = {
    '.py', '.pyi',                        # Python
    '.js', '.jsx', '.mjs', '.cjs',        # JavaScript
    '.ts', '.tsx',                         # TypeScript
    '.kt', '.kts', '.ktm',                # Kotlin
    '.java',                               # Java
    '.cs', '.csx',                         # C#
    '.go',                                 # Go
    '.rs',                                 # Rust
    '.rb', '.rbw', '.rake',               # Ruby
    '.dart',                               # Dart/Flutter
    '.cpp', '.cxx', '.cc', '.c',          # C/C++
    '.hpp', '.hxx', '.hh', '.h',          # C/C++ headers
    '.swift',                              # Swift
    '.php', '.phtml',                      # PHP
    '.tf', '.tfvars', '.hcl',             # Terraform/HCL
    '.yaml', '.yml',                       # YAML
    '.json',                               # JSON
    '.toml',                               # TOML
    '.md', '.mdx',                         # Markdown
    '.html', '.htm',                       # HTML
    '.css', '.scss', '.sass', '.less',    # CSS
    '.sql',                                # SQL
    '.sh', '.bash', '.zsh', '.fish',      # Shell
    '.dockerfile',                         # Dockerfile (exato)
    '.Dockerfile',                         # Dockerfile (exato)
}
```

---

## 5. Fase 3 — Engine AST/IR (O Game-Changer)

*(Duração: Semanas 7-10)*

Este é o passo que separa ferramentas de *brinquedo* de ferramentas *enterprise*.

### 5.1 Porquê AST?

```
Código:  user_input = request.GET['q']
         query = "SELECT * FROM items WHERE name = '" + user_input + "'"
         db.execute(query)

Regex:   ✗ DETETA "SQL injection" ✓
         ✗ Mas NÃO SABE se user_input vem do utilizador ou de uma constante
         ✗ NÃO SABE se query.execute é realmente uma query SQL ou outro método

AST:     ✓ Sabe que user_input vem de request.GET (source tainted)
         ✓ Sabe que query é concatenação com string tainted
         ✓ Sabe que db.execute(query) é um sink SQL
         ✓ Pode follow o dataflow mesmo se passar por 10 funções
```

### 5.2 tree-sitter Integration

**tree-sitter** é a melhor escolha porque:
- Suporta **40+ linguagens** (Python, JS, TS, Java, Go, Rust, Ruby, C, C++, Kotlin, Swift, etc.)
- **Blazing fast** (C library, parsing em microsegundos)
- **Erro-tolerant** — consegue parse código mesmo com erros de sintaxe
- **Query-based** — podes fazer queries tipo "encontra todas as funções que chamam `exec`"

```python
# janitor/engine/ast/parser.py
import tree_sitter
from pathlib import Path
from typing import Dict, Any, Optional

class ASTParser:
    """Multi-language AST parser using tree-sitter."""

    _LANGUAGE_MAP = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".java": "java",
        ".go": "go",
        ".rs": "rust",
        ".rb": "ruby",
        ".dart": "dart",
        ".cpp": "cpp",
        ".c": "c",
        ".swift": "swift",
        ".kt": "kotlin",
        ".cs": "c_sharp",
        ".php": "php",
    }

    def __init__(self):
        self._languages: Dict[str, Any] = {}

    def parse(self, file_path: Path, content: str) -> Optional[Any]:
        """Parse file content into AST."""
        ext = file_path.suffix.lower()
        lang_name = self._LANGUAGE_MAP.get(ext)
        if not lang_name:
            return None
        lang = self._get_language(lang_name)
        parser = tree_sitter.Parser()
        parser.set_language(lang)
        return parser.parse(bytes(content, "utf-8"))

    def query(self, ast, query_string: str) -> list:
        """Run a tree-sitter query on the AST."""
        ...
```

### 5.3 Query Language para Vulnerabilidades

```python
# Exemplo de queries tree-sitter para Python
PY_SQL_INJECTION = """
(
  (call
    function: (attribute
      object: (identifier) @obj
      attribute: (identifier) @method
      (#eq? @method "execute"))
    arguments: (argument_list
      (string) @query
      (#match? @query "SELECT|INSERT|UPDATE|DELETE")))
  (#eq? @obj "cursor")
)
"""

PY_EVAL = """
(
  (call
    function: (identifier) @func
    (#eq? @func "eval"))
  (argument_list
    (identifier) @arg)
) @call
"""
```

### 5.4 Unified Vulnerability Query Language (UVQL)

Para não teres de escrever queries tree-sitter para cada linguagem, crias uma **DSL própria**:

```yaml
# checks/python/sql_injection.yaml
id: PY-SQL-001
name: SQL Injection via String Concatenation
severity: critical
languages: [python, javascript, typescript, java, kotlin, go, rust, csharp, php, ruby, dart, cpp, swift]
pattern:
  type: taint
  sources:
    - { type: identifier, name: ["request", "input", "params", "body", "query", "data", "form"] }
    - { type: call, method: ["get", "post", "put", "delete", "input", "param"] }
  sinks:
    - { type: call, method: ["execute", "query", "run", "raw"] }
    - { type: concat, contains: ["SELECT", "INSERT", "UPDATE", "DELETE"] }
  sanitizers:
    - { type: call, method: ["escape_string", "sanitize", "validate", "parameterize"] }
    - { type: call, module: ["sqlalchemy", "django.db", "psycopg2"] }
metadata:
  cwe: "CWE-89"
  owasp: "A1: Injection"
  mitre: "T1190"
  remediation: "Use parameterized queries instead of string concatenation"
  example: |
    # Bad: cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    # Good: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

Isto permite que **qualquer pessoa contribua com checks** sem saber Python nem tree-sitter.

### 5.5 Symbolic Execution Engine (Limitado)

Para caminhos críticos (auth bypass, access control), implementar symbolic execution básica:

```python
class SymbolicExecutor:
    """
    Explora caminhos de execução simbolicamente.
    Não precisas de um Z3 solver completo —
    basta follow de if/else com constraints básicas.

    Exemplo:
        if user.role == 'admin':    # path 1: user.role == 'admin'
            allow_access()           # ✓ autorizado
        else:                        # path 2: user.role != 'admin'
            deny_access()            # ✓ negado
            # MAS se houver:
            if user.is_owner:        # bypass!
                allow_access()       # ✗ vulnerabilidade!
    """
    ...
```

---

## 6. Fase 4 — Dataflow Inter-Procedural

*(Duração: Semanas 11-13)*

### 6.1 Call Graph Construction

```python
# janitor/engine/dataflow/call_graph.py
class CallGraph:
    """
    Constrói o grafo de chamadas do projeto inteiro.

    Exemplo:
        app/
        ├── controller.py    # user_input = request.get('id')
        ├── service.py       # result = db.find_user(user_input)
        └── repository.py    # cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

    CallGraph detecta:
        controller.get_user()
          └─> service.find_user()
               └─> repository.query_user()
                    └─> SQL injection via cursor.execute()

    Isto é IMPOSSÍVEL com regex-only.
    """

    def build(self, files: List[Path]) -> DiGraph:
        """Build call graph from project files."""

    def find_paths(self, source: str, sink: str) -> List[Path]:
        """Find all paths from source to sink."""

    def is_tainted_path(self, source: str, sink: str, sanitizers: List[str]) -> bool:
        """Check if there's a tainted path from source to sink without sanitizer."""
```

### 6.2 Taint Tracking Engine

```python
# janitor/engine/dataflow/taint.py
@dataclass
class TaintValue:
    """A tainted value with propagation chain."""
    is_tainted: bool
    source: Optional[str]        # "controller.py:15"
    type: Optional[str]          # "user_input", "sql_query", "html_output"
    propagated_through: List[str] = field(default_factory=list)

class TaintEngine:
    """
    Taint tracking inter-procedural completo.

    Sources predefinidos (por linguagem):
        - HTTP request params
        - Headers, cookies
        - File uploads
        - Environment variables
        - Database results
        - External API responses

    Propagators:
        - String concatenation
        - String formatting (f-strings, %, .format)
        - Template rendering
        - JSON/YAML/XML parsing

    Sinks:
        - SQL queries
        - Command execution
        - File operations
        - Network requests
        - HTML output
        - Deserialization
        - eval/exec

    Sanitizers:
        - Input validation
        - Escaping/encoding
        - Parameterized queries
        - Type casting
        - Allowlist checks
    """

    def analyze(self, call_graph: CallGraph) -> List[TaintFlow]:
        """Run inter-procedural taint analysis."""
        ...
```

### 6.3 Exemplo: Deteção Real de SQL Injection Cross-File

```
controller.py:12    user_input = request.args.get('id')
                         ↓ (taint propagates)
service.py:25       query = f"SELECT * FROM users WHERE id = {user_input}"
                         ↓ (taint propagates)
repository.py:8     cursor.execute(query)
                         ↓ (SINK — SQL Injection!)

RESULT: CRITICAL — SQL Injection (CWE-89)
Path: controller.py:12 → service.py:25 → repository.py:8
Attack Vector: Attacker sends ?id=1' OR '1'='1
```

Isto é **impossível** com regex. Só com AST + call graph + taint tracking.

---

## 7. Fase 5 — IaC + Cloud + Container

*(Duração: Semanas 14-16)*

### 7.1 Dockerfile Analyzer

```
Checks de segurança para Dockerfiles:

DOCKER-001  🔴 CRITICAL  Uso de `latest` tag — sem rastreabilidade
DOCKER-002  🔴 CRITICAL  `ADD` em vez de `COPY` — permite URL injection
DOCKER-003  🔴 HIGH      `USER root` — container executa como root
DOCKER-004  🔴 HIGH      `apt-get upgrade` sem fixar versões
DOCKER-005  🔴 HIGH      `--no-install-recommends` ausente
DOCKER-006  🟡 MEDIUM    `EXPOSE 22` — SSH exposto
DOCKER-007  🟡 MEDIUM    `ENV` com secrets
DOCKER-008  🟡 MEDIUM    `WORKDIR` inseguro
DOCKER-009  🟡 MEDIUM    Multi-stage build não usado
DOCKER-010  🟢 LOW       Sem HEALTHCHECK
DOCKER-011  🟢 LOW       Sem `.dockerignore`
```

### 7.2 Kubernetes Analyzer

```
K8S-001  🔴 CRITICAL  `privileged: true` — container em modo privilegiado
K8S-002  🔴 CRITICAL  `hostNetwork: true` — acesso à rede do host
K8S-003  🔴 CRITICAL  `runAsUser: 0` — container como root
K8S-004  🔴 HIGH      `readOnlyRootFilesystem: false`
K8S-005  🔴 HIGH      `CAP_ADD` com capacidades perigosas (SYS_ADMIN, NET_ADMIN)
K8S-006  🔴 HIGH      Secrets em env vars (em vez de volume mounts)
K8S-007  🟡 MEDIUM    `imagePullPolicy: Always` ausente
K8S-008  🟡 MEDIUM    `resources.limits` não definidos (DoS)
K8S-009  🟡 MEDIUM    `serviceAccountName` ausente (default SA)
K8S-010  🟡 MEDIUM    `automountServiceAccountToken: true` quando não necessário
K8S-011  🟢 LOW       Sem NetworkPolicy
K8S-012  🟢 LOW       Sem PodDisruptionBudget
```

### 7.3 Terraform Analyzer

```
TF-001  🔴 CRITICAL  S3 bucket público (acl = "public-read")
TF-002  🔴 CRITICAL  Security group com 0.0.0.0/0 para SSH (22)
TF-003  🔴 CRITICAL  IAM policy com "*" no Resource
TF-004  🔴 HIGH      RDS sem encryption at rest
TF-005  🔴 HIGH      S3 sem encryption at rest
TF-006  🔴 HIGH      CloudTrail desativado
TF-007  🟡 MEDIUM    Secrets hardcoded em variáveis
TF-008  🟡 MEDIUM    VPC sem flow logs
TF-009  🟡 MEDIUM    ECR sem image scanning
TF-010  🟡 MEDIUM    KMS key sem rotation
TF-011  🟢 LOW       Tags de ambiente ausentes
TF-012  🟢 LOW       Provider version não fixado
```

### 7.4 Integração com o Scanner

```python
# O scanner deteta automaticamente ficheiros IaC
IAC_EXTENSIONS = {
    "Dockerfile": "iac/docker.py",
    "*.yaml": "iac/kubernetes.py",    # se tiver apiVersion: apps/v1
    "*.tf": "iac/terraform.py",
    "*.tfvars": "iac/terraform.py",
    "*.hcl": "iac/terraform.py",
    "*.json": "iac/cloudformation.py", # se tiver AWSTemplateFormatVersion
}
```

---

## 8. Fase 6 — Dependency Scanner 2.0

*(Duração: Semanas 17-18)*

### 8.1 Arquitetura Atual (OSV.dev apenas) vs Futura

| Funcionalidade | Hoje | Amanhã |
|---|---|---|
| API | OSV.dev only | OSV.dev + NVD + GitHub Advisory + exploit-db |
| Scoring | Severity string | **CVSS 3.1 + EPSS + KEV + PoC exists** |
| Cache | SQLite, 24h TTL | SQLite + Redis opcional, configurável |
| Fix suggestion | "Upgrade X to Y" | **Auto-PR com upgrade confirmado** |
| License compliance | ❌ | **✅ Detecta licenças incompatíveis (GPL em projeto MIT)** |
| Transitive deps | ❌ | **Varre dependências transitivas** |
| Alertas prioritários | ❌ | **Se existe PoC público → CRITICAL** |

### 8.2 Auto-Remediation de Dependências

```
─── SIM, DEVE TER AI PARA RESOLVER DEPENDÊNCIAS ───

Como funciona:

1. Dependency Scanner deteta:  requests@2.31.0 tem CVE-2024-12345
2. OSV.dev diz: fixed in 2.32.0
3. AI Engine verifica:
   * "requests@2.32.0 é compatível com o resto do projeto?"
   * "Há breaking changes no Changelog?"
   * "Os testes passam com a versão nova?"
4. Se seguro → cria PR automático:
   ```
   title: "fix: upgrade requests from 2.31.0 to 2.32.0 (CVE-2024-12345)"
   body: |
     ## Security Vulnerability Fixed
     - **Package:** requests
     - **From:** 2.31.0 → 2.32.0
     - **CVE:** CVE-2024-12345 (CVSS 7.5 HIGH)
     - **Summary:** HTTP response smuggling vulnerability
     - **Auto-remediated by repo-janitor
   changes:
     - requirements.txt: s/requests==2.31.0/requests==2.32.0/
   ```
5. Se houver breaking changes → AI analisa o código e adapta!

─── Isto é o que FAZ UMA BIG TECH PAGAR ───
```

### 8.3 NVD + GitHub Advisory + EPSS Integration

```python
class VulnSource(ABC):
    """Abstract base for vulnerability data sources."""

    @abstractmethod
    def query(self, name: str, version: str, ecosystem: str) -> List[Vulnerability]:
        ...

class OSVClient(VulnSource):
    """Google OSV.dev — free, comprehensive."""

class NVDClient(VulnSource):
    """NVD API 2.0 — CVSS 3.1 scores, CWE mapping."""
    API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

class GitHubAdvisoryClient(VulnSource):
    """GitHub Advisory Database — GHSA IDs, ecosystem-specific."""
    API_BASE = "https://api.github.com/advisories"

class ExploitDBClient(VulnSource):
    """Check if PoC exists for this CVE."""

# Priority scoring:
def calculate_priority(cvss: float, epss: float, has_poc: bool, in_kev: bool) -> str:
    """
    CVSS 3.1 + EPSS (exploit probability) + PoC + KEV

    EPSS > 0.9 + PoC exists + in KEV → CRITICAL (fix within 24h)
    CVSS >= 9.0 → CRITICAL
    CVSS >= 7.0 + EPSS > 0.5 → HIGH
    CVSS >= 4.0 → MEDIUM
    else → LOW
    """
    if in_kev and has_poc:
        return "critical"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0 and epss > 0.5:
        return "high"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"
```

---

## 9. Fase 7 — AI Profunda (Auto-Remediation)

*(Duração: Semanas 19-22)*

### 9.1 Arquitetura AI

```
┌─────────────────────────────────────────────────────────────┐
│                     AI ENGINE                                │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐  │
│  │  Fix Generator  │  │  Dep Upgrader   │  │   Context   │  │
│  │  (Código)       │  │  (Dependencies) │  │   Analyzer  │  │
│  └────────┬────────┘  └────────┬────────┘  └──────┬──────┘  │
│           │                    │                   │         │
│  ┌────────▼────────────────────▼───────────────────▼──────┐  │
│  │                 LLM ORCHESTRATOR                        │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │  │
│  │  │ NVIDIA   │ │ OpenAI   │ │ Anthropic│ │  Ollama  │  │  │
│  │  │ NIM      │ │ GPT-4o   │ │ Claude 4 │ │  Local   │  │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │            CACHE & MEMORY LAYER                         │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────────────────┐    │ │
│  │  │ 24h TTL │ │ Semantic │ │ Project Graph        │    │ │
│  │  │ SQLite   │ │ Cache    │ │ (whole codebase)     │    │ │
│  │  └──────────┘ └──────────┘ └──────────────────────┘    │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 9.2 Fix Generator

```python
class FixGenerator:
    """
    Gera automaticamente correções para vulnerabilidades.

    Exemplo 1: SQL Injection
        ANTES:  cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
        DEPOIS: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

    Exemplo 2: Command Injection
        ANTES:  subprocess.run(f"grep {pattern} file.txt", shell=True)
        DEPOIS: subprocess.run(["grep", pattern, "file.txt"])

    Exemplo 3: Hardcoded Secret
        ANTES:  API_KEY = "sk-1234567890abcdef"
        DEPOIS: API_KEY = os.getenv("API_KEY")

    Como funciona:
    1. Static analysis deteta vulnerabilidade
    2. AST localiza o nó exato
    3. AI Engine gera 3 propostas de correção
    4. Análise de impacto (quebra testes? afeta outras funções?)
    5. A melhor proposta é selecionada
    6. --apply aplica a mudança
    7. PR é criado com descrição detalhada
    """

    def generate_fix(self, finding: Finding, ast: ASTNode) -> List[FixProposal]:
        ...

    def validate_fix(self, proposal: FixProposal, project: Project) -> ValidationResult:
        """Run tests, check imports, verify no breaking changes."""
        ...

@dataclass
class FixProposal:
    finding_id: str
    original_code: str
    fixed_code: str
    diff: str
    confidence: float  # 0.0 - 1.0
    explanation: str
    risk: str  # "safe", "needs_review", "high_risk"
```

### 9.3 Dep Upgrader (Auto-PR)

```python
class DepUpgrader:
    """
    Atualiza dependências vulneráveis automaticamente.

    Pipeline:
    1. Deteta CVE em dependência
    2. Consulta OSV + NVD para fix version
    3. Verifica compatibilidade:
       - Changelog: há breaking changes?
       - Testes do projeto passam com a nova versão?
       - Dependências transitivas mudaram?
    4. Se seguro → cria PR
    5. Se tem breaking changes:
       - AI analisa o código que usa esta dependência
       - Tenta adaptar automaticamente
       - Se não conseguir → reporta com docs de migração

    Exemplo com requests@2.31.0 → 2.32.0:
      ✅ Changelog: bugfixes only
      ✅ Tests: pass
      ✅ Breaking changes: none
      → PR criado automaticamente

    Exemplo com django@3.2 → 4.0:
      ❌ Changelog: várias breaking changes
      → AI analisa settings.py, urls.py, models.py
      → Tenta migrar automaticamente
      → Se falhar: reporta com guia de migração
    """

    def auto_upgrade(self, vuln: Vulnerability, project: Project) -> Optional[PR]:
        ...
```

### 9.4 False Positive Learning

```python
class FPLearning:
    """
    Aprende com falsos positivos reportados pelo utilizador.

    Mecanismo:
    1. Utilizador marca finding como "false positive"
    2. Sistema guarda o contexto:
       - Código exacto
       - Padrão que ativou o alerta
       - Razão (se fornecida)
    3. Próxima vez que encontrar padrão similar:
       - Context check verifica base de conhecimento de FPs
       - Se match → suprime o alerta
       - Se não → alerta normalmente

    Isto é CRÍTICO para reduzir fadiga de alertas.
    """

    FP_DB = Path.home() / ".repo-janitor" / "fp_learning.json"

    def report_false_positive(self, finding: Finding, reason: str):
        """Store FP context for future suppression."""

    def is_false_positive(self, finding: Finding, project: Project) -> bool:
        """Check if this finding matches known FP patterns."""
```

---

## 10. Fase 8 — Enterprise + CI/CD

*(Duração: Semanas 23-25)*

### 10.1 GitHub Action

```yaml
# .github/actions/repo-janitor/action.yaml
name: 'repo-janitor Security Audit'
description: 'Automated security scanning for your repository'
inputs:
  min-severity:
    description: 'Minimum severity to report'
    default: 'medium'
  scan-deps:
    description: 'Scan dependencies for CVEs'
    default: 'true'
  output-format:
    description: 'Output format (sarif, json, markdown)'
    default: 'sarif'
runs:
  using: 'docker'
  image: 'Dockerfile'
  args:
    - ${{ inputs.min-severity }}
    - ${{ inputs.scan-deps }}
```

```yaml
# Exemplo de workflow que comenta em PRs
name: Security Audit
on: [pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/repo-janitor
        with:
          min-severity: high
      - uses: repo-janitor/comment-pr@v1
        if: failure()
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

### 10.2 SARIF Output

```python
class SARIFOutput:
    """
    Gera SARIF (Static Analysis Results Interchange Format).

    Formato standard da Microsoft/OASIS usado por:
    - GitHub Security Tab (Code Scanning)
    - VS Code (Problems panel)
    - Azure DevOps

    Com SARIF, as vulnerabilidades aparecem diretamente no
    Security Tab do GitHub, com código destacado.
    """

    def generate(self, findings: List[Finding]) -> Dict[str, Any]:
        """Generate SARIF 2.1.0 compliant output."""
        ...
```

### 10.3 HTML Dashboard

```python
class HTMLDashboard:
    """
    Gera um dashboard HTML interativo com:

    - Summary cards (total, critical, high, medium, low)
    - Gráfico de severidade (Chart.js)
    - Tabela de findings (sortable, filterable)
    - Breakdown por linguagem
    - Dependency scan results
    - Trend graph (se histórico disponível)
    - Export para PDF
    """
    ...
```

### 10.4 Dockerfile

```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -e .

# tree-sitter languages
RUN pip install tree-sitter-python tree-sitter-javascript \
    tree-sitter-typescript tree-sitter-java tree-sitter-go \
    tree-sitter-rust tree-sitter-ruby tree-sitter-cpp

ENTRYPOINT ["repo-janitor"]
```

### 10.5 Pre-commit Hook

```yaml
# .pre-commit-hooks.yaml
- id: repo-janitor
  name: repo-janitor security audit
  description: Run security audit on staged files
  entry: repo-janitor
  language: python
  types: [python, javascript, typescript, java, kotlin, go, rust]
  args: [--min-severity, high, --json]
```

---

## 11. Fase 9 — Monetização / Go-to-Market

*(Duração: Semanas 26-28)*

### 11.1 Modelo de Negócio

```
  🆓 Open Source (Community)
  ├── 13+ language analyzers (SAST)
  ├── Dependency scanner (OSV.dev)
  ├── CLI + JSON output
  ├── SECURITY_AUDIT.md report
  ├── Dockerfile + IaC scanning
  └── AI auto-remediation (local Ollama)

  💼 Enterprise ($5k-20k/year)
  ├── Tudo do Community
  ├── + NVD + GitHub Advisory + EPSS + PoC (scoring real)
  ├── + GitHub Action com auto-PR
  ├── + SARIF output (GitHub Security Tab)
  ├── + HTML Dashboard + Trend Analysis
  ├── + Slack/Teams/Email notifications
  ├── + False Positive Learning DB centralizada
  ├── + Suporte prioritário (24h SLA)
  └── + On-premise deployment (air-gapped)

  🏢 Custom ($50k+/year)
  ├── Tudo do Enterprise
  ├── + Custom language analyzers
  ├── + Custom rules/checks
  ├── + Integration com SIEM (Splunk, ELK)
  ├── + SLA personalizado
  └── + Consultoria de segurança
```

### 11.2 Porquê uma Big Tech Pagaria?

| Problema | Solução repo-janitor | Concorrentes |
|---|---|---|
| **Falsos positivos** | AST + dataflow + FP learning | Semgrep (médio), CodeQL (bom), Snyk (médio) |
| **Cobertura linguagens** | 13+ linguagens + IaC | Semgrep (20+ lang), CodeQL (12 lang), Snyk (8 lang) |
| **Auto-remediation** | AI gera PRs com fix | Snyk (básico), Dependabot (só deps) |
| **Context-aware** | Call graph + project understanding | Ninguém faz bem |
| **Offline/air-gapped** | Tudo corre localmente | Snyk/Checkmarx precisam de cloud |
| **Preço** | Open source + enterprise opcional | Snyk: $50k+/ano, Checkmarx: $100k+/ano |

---

## 12. O Problema do Contexto (A Tua Obsessão)

*(Paralelo a todas as fases)*

### 12.1 Porquê o Contexto é Crítico

```
┌─────────────────────────────────────────────────────────┐
│            O PROBLEMA DO CONTEXTO NA AI                  │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  🧠 Humano: lê 5 ficheiros → entende o projeto          │
│  🤖 AI: cada chamada é do zero → perde contexto         │
│                                                          │
│  Solução: Project Context Graph                          │
│                                                          │
│  O que é:                                                │
│  Um grafo completo do projeto que a AI consulta          │
│  antes de responder.                                     │
│                                                          │
│  Como funciona:                                          │
│  1. Scanner lê TODOS os ficheiros do projeto             │
│  2. Para cada ficheiro:                                  │
│     - Extrai: imports, exports, funções, classes,        │
│                dependências, API endpoints, routes        │
│     - Gera: resumo em linguagem natural do que faz       │
│  3. Constrói grafo de relações:                          │
│     - Ficheiro A importa B → aresta                      │
│     - Controller X usa Service Y → aresta                │
│     - Rota /users chama handler Z → aresta               │
│  4. Quando AI precisa analisar um ficheiro:              │
│     - Recebe o resumo DO PROJETO INTEIRO como contexto   │
│     - "Este ficheiro é um controller Django que           │
│        recebe POST em /users/create e chama o service     │
│        UserService.create_user() que está em              │
│        services/user_service.py:42. O UserService         │
│        faz validação em validators/user_validator.py      │
│        e persiste em models/user.py."                     │
│                                                          │
│  Resultado: AI entende o projeto como um humano.         │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 12.2 Project Context Graph

```python
@dataclass
class FileNode:
    """A file in the project graph."""
    path: Path
    language: str
    summary: str                    # AI-generated summary
    imports: List[str]              # files this imports
    exported_symbols: List[str]     # functions/classes exported
    api_endpoints: List[APIEndpoint] # if web framework
    dependencies: List[str]         # package dependencies
    complexity: float               # cyclomatic complexity

@dataclass
class APIEndpoint:
    method: str     # GET, POST, PUT, DELETE
    path: str       # /users/{id}
    handler: str    # controller.get_user
    auth: bool      # requires authentication
    params: List[str]

class ProjectGraph:
    """
    Grafo completo do projeto.

    Exemplo de output para uma app To-Do:

    📁 todo_app/
    ├── 📄 main.py
    │   ├── Summary: "FastAPI application entry point with
    │   │   CORS middleware and route registration"
    │   ├── Imports: fastapi, uvicorn, routes/todos.py
    │   ├── Exports: app (FastAPI instance)
    │   └── Routes: / (GET healthcheck)
    │
    ├── 📄 models/todo.py
    │   ├── Summary: "Pydantic model for Todo entity with
    │   │   id, title, description, completed fields"
    │   ├── Imports: pydantic, datetime, uuid
    │   └── Exports: Todo, TodoCreate, TodoUpdate
    │
    ├── 📄 routes/todos.py
    │   ├── Summary: "CRUD routes for Todo management.
    │   │   Uses database/crud.py for persistence."
    │   ├── Imports: fastapi, models/todo.py, database/crud.py
    │   ├── Routes:
    │   │   ├── GET    /todos     → list_todos (public)
    │   │   ├── POST   /todos     → create_todo (auth required)
    │   │   ├── GET    /todos/{id} → get_todo (public)
    │   │   ├── PUT    /todos/{id} → update_todo (auth required)
    │   │   └── DELETE /todos/{id} → delete_todo (auth required)
    │   └── Exports: router (APIRouter)
    │
    └── 📄 database/crud.py
        ├── Summary: "SQLAlchemy CRUD operations for Todo.
        │   Uses database.py for session management."
        └── Exports: create_todo, get_todo, list_todos, ...

    📊 Project Stats:
    ├── Languages: Python (90%), YAML (5%), Markdown (5%)
    ├── Framework: FastAPI
    ├── Database: PostgreSQL (via SQLAlchemy async)
    ├── Auth: JWT (python-jose)
    ├── Tests: pytest (87% coverage)
    ├── Total files: 12
    ├── Total lines: 1,450
    └── Complexity: Low (avg 3.2 cyclomatic)
    """

    def build(self, scanner: Scanner) -> 'ProjectGraph':
        """Build full project graph."""

    def summarize(self, ai_client: LLMClient) -> Dict[str, Any]:
        """Generate AI-powered summaries for each file."""

    def get_context_for(self, file_path: Path) -> str:
        """Get full context for a specific file."""
```

### 12.3 Como Será Usado

```bash
# 1. Full project comprehension
repo-janitor context --explain
# Output: resumo completo do projeto, ficheiro a ficheiro

# 2. Context-aware security audit
repo-janitor scan --context-aware
# O analyzer sabe que este ficheiro é um controller
# e que o input vem de um request, não de uma fonte interna

# 3. AI-assisted development
repo-janitor ai "Add pagination to GET /todos endpoint"
# AI usa o Project Graph para saber:
# - Onde está o router (routes/todos.py)
# - Onde está o modelo (models/todo.py)
# - Onde está a base de dados (database/crud.py)
# - Gera código consistente com o projeto

# 4. Onboarding
repo-janitor context --markdown > PROJECT_SUMMARY.md
# Gera documentação perfeita para novos developers
```

---

## 13. Roadmap Temporal

```
Sprints (cada sprint = 1 semana)
═══════════════════════════════════════════════════════════════════

FASE 1 — FUNDAÇÃO ENTERPRISE (Semanas 1-2)
───────────────────────────────────────────
□ Sprint 1: Fix bugs, refactor legacy files, unificar versões
□ Sprint 2: Expandir test suite (24→100+), adicionar fixtures

FASE 2 — COBERTURA TOTAL DE LINGUAGENS (Semanas 3-6)
────────────────────────────────────────────────────
□ Sprint 3: Rust analyzer (50+ checks)
□ Sprint 4: Ruby analyzer (50+ checks)
□ Sprint 5: Dart/Flutter analyzer (50+ checks)
□ Sprint 6: C/C++ analyzer + Swift analyzer (50+ checks cada)

FASE 3 — ENGINE AST/IR (Semanas 7-10)
──────────────────────────────────────
□ Sprint 7: tree-sitter integration (Python + JS/TS primeiro)
□ Sprint 8: AST parsing + queries para todas as linguagens
□ Sprint 9: UVQL (Unified Vulnerability Query Language) design
□ Sprint 10: Symbolic execution básico

FASE 4 — DATAFLOW INTER-PROCEDURAL (Semanas 11-13)
───────────────────────────────────────────────────
□ Sprint 11: Call graph construction
□ Sprint 12: Taint tracking engine (intra-procedural)
□ Sprint 13: Taint tracking (inter-procedural) + cross-file SQL/CMD/XSS

FASE 5 — IaC + CLOUD + CONTAINER (Semanas 14-16)
─────────────────────────────────────────────────
□ Sprint 14: Dockerfile analyzer (12 checks)
□ Sprint 15: Kubernetes analyzer (12 checks)
□ Sprint 16: Terraform + CloudFormation analyzers (12+ checks cada)

FASE 6 — DEPENDENCY SCANNER 2.0 (Semanas 17-18)
────────────────────────────────────────────────
□ Sprint 17: NVD + GitHub Advisory + EPSS integration
□ Sprint 18: License compliance + transitive deps + auto-PR

FASE 7 — AI + AUTO-REMEDIATION (Semanas 19-22)
───────────────────────────────────────────────
□ Sprint 19: Fix Generator (code)
□ Sprint 20: Dep Upgrader (auto-PR)
□ Sprint 21: False Positive Learning
□ Sprint 22: Context Engine (Project Graph)

FASE 8 — ENTERPRISE + CI/CD (Semanas 23-25)
────────────────────────────────────────────
□ Sprint 23: GitHub Action + SARIF output
□ Sprint 24: HTML Dashboard + pre-commit hook
□ Sprint 25: Dockerfile + performance optimization

FASE 9 — GO-TO-MARKET (Semanas 26-28)
──────────────────────────────────────
□ Sprint 26: Benchmark público (OWASP Benchmark, Juice Shop)
□ Sprint 27: Documentação + website + vídeos
□ Sprint 28: Lançamento + prospeção enterprise

═══ TOTAL: ~28 SEMANAS (7 MESES) ═══
```

---

## 14. Resposta à Pergunta Final

> **"Devo integrar AI para resolver logo as dependências de segurança?"**

**SIM, ABSOLUTAMENTE.** E não é só para dependências — é para código também.

A AI é o **força-motriz** que transforma repo-janitor de:
- "Uma ferramenta que aponta problemas" (como todas as outras)
- Para: "Uma ferramenta que **RESOLVE** problemas"

### O Que a AI Torna Possível (e que ninguém mais tem bem):

| Funcionalidade | Impacto | Concorrência |
|---|---|---|
| **Auto-PR para CVEs** | Developer nem abre o terminal | Dependabot (só alerta) |
| **Auto-fix de SQLi/XSS/CMD** | Segurança resolvida automaticamente | Snyk Fix (limitado a deps) |
| **False Positive Learning** | Menos fadiga de alertas | Ninguém faz bem |
| **Context-aware scanning** | Menos FPs, mais precisão | Ninguém faz |
| **Project summarization** | Onboarding em segundos | Ninguém faz |

### Recomendação:

1. **Primeiro a AI para dependências** (Fase 6) — é mais fácil, mais previsível, e resolve 60% dos problemas de segurança reais
2. **Depois AI para código** (Fase 7) — mais complexo, mas onde está o valor real
3. **Finalmente AI para contexto** (paralelo) — a cereja no topo do bolo

---

## Conclusão Final

Para um CTO da Google pagar pelo repo-janitor:

```
Para um CTO da Google pagar:
├── AST-based analysis (não regex)    ← CRÍTICO
├── Dataflow inter-procedural          ← CRÍTICO
├── < 10% false positive rate          ← CRÍTICO
├── 13+ linguagens + IaC              ← MUITO IMPORTANTE
├── Auto-remediation (deps + code)    ← DIFERENCIADOR
├── CI/CD nativo (GitHub Actions)     ← NECESSÁRIO
├── SARIF output                      ← NECESSÁRIO
└── Context engine (project graph)    ← REVOLUCIONÁRIO
```

O que te fará **ganhar** não é ter mais checks que os outros (todos têm). É ter:
1. **Menos falsos positivos** (AST + dataflow)
2. **Auto-remediation real** (AI que resolve em vez de só reportar)
3. **Context awareness** (AI que percebe o projeto inteiro)
