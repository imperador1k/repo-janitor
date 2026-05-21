# 🧹 repo-janitor — Guia Rápido

## O que é?

O **repo-janitor** é um auditor de segurança multi-linguagem que analisa o teu código à procura de vulnerabilidades. Suporta **13 linguagens**: Python, JavaScript, TypeScript, Java, Kotlin, Go, C#, PHP, Rust, Ruby, C/C++, Dart/Flutter e Swift.

## Como usar

### 1. Correr uma análise (modo padrão — só mostra, não altera nada)

```bash
python -m janitor.cli .
```

Isto analisa o diretório atual (`.`) e mostra todas as vulnerabilidades encontradas, ordenadas por gravidade.

### 2. Analisar um projeto específico

```bash
python -m janitor.cli Caminho/para/o/teu/projeto
```

### 3. Ver apenas problemas críticos/altos

```bash
python -m janitor.cli . --min-severity high
```

### 4. Análise só de segurança (ignora code quality)

```bash
python -m janitor.cli . --category security
```

### 5. Output em JSON (para CI/CD)

```bash
python -m janitor.cli . --json
```

### 6. Relatório HTML interativo

```bash
# Gera security_report.html com gráficos e tabela filtrável
python -m janitor.cli . --html

# Nome personalizado
python -m janitor.cli . --html relatorio.html
```

Gera um relatório **self-contained** (abre no browser, 0 servidores) com:
- Score de segurança (A-F) com gráfico de severidade (doughnut)
- Gráfico de issues por linguagem e top 10 ficheiros
- Tabela interativa com pesquisa, filtro por severidade e linhas expansíveis
- Code snippets destacados e sugestões de correção
- Seção de dependências (se usado com `--deps`)
- Dark theme profissional, responsive

### 7. Escanear dependências por CVEs

```bash
python -m janitor.cli . --deps
```

Usa a API OSV.dev do Google para verificar vulnerabilidades conhecidas.

### 8. Verboso (mais detalhes)

```bash
python -m janitor.cli . -v
```

### 9. Ajuda completa

```bash
python -m janitor.cli --help
```

## O que significam as gravidades?

| Severidade | Cor       | O que significa                    |
|------------|-----------|------------------------------------|
| 🔴 Critical| Vermelho  | Execução remota de código, SQL injection, hardcoded secrets |
| ⚪ High    | Magenta   | XSS, path traversal, crypto fraca  |
| 🟡 Medium  | Amarelo   | Permissões excessivas, logging sensível |
| 🔵 Low     | Ciano     | TODO/FIXME, force unwrap, prints   |

## Modo `--dry-run` vs `--apply`

- **`--dry-run`** (padrão) — Apenas mostra os problemas, não mexe no código.
- **`--apply`** — Aplica correções automáticas (apenas para dependências por agora).

## Exemplo prático

```bash
# Varrer o projeto atual, só critical/high, formato legível
python -m janitor.cli . --min-severity high
```

O output mostra uma tabela com:
- Ficheiro e linha do problema
- Tipo e descrição da vulnerabilidade
- CWE, OWASP e MITRE identifiers
- Sugestão de remediação

## Ficheiro de relatório

Por defeito gera `SECURITY_AUDIT.md` no diretório do projeto. Podes mudar:

```bash
python -m janitor.cli . --output meu_relatorio.md
```

## Pre-commit Hook (bloqueia commits com vulnerabilidades)

```bash
# Instalar o hook (só precisas de fazer uma vez por projeto)
python -m janitor.cli --install-hooks

# Remover o hook
python -m janitor.cli --uninstall-hooks
```

O hook corre **antes de cada `git commit`** e:
- Obtém apenas os ficheiros staged (rápido — não analisa o repo inteiro)
- Verifica por vulnerabilidades **critical/high**
- Bloqueia o commit + mostra os problemas encontrados
- Para ignorar: `git commit --no-verify`

## Troubleshooting

- **"module not found"** — Corre `pip install -e .` na raiz do projeto
- **Nenhum ficheiro encontrado** — O scanner respeita `.gitignore`. Se o projeto está todo ignorado, usa `--verbose` para ver o que está a ser filtrado
- **Queres testar uma linguagem específica** — Cria um ficheiro com a extensão certa (`.py`, `.js`, `.ts`, `.dart`, `.swift`, etc.) e corre o scanner nesse diretório
