# SECURITY AUDIT REPORT

**Generated:** 2026-05-19T09:24:13.056953
**Repository:** C:\Users\User\Documents\PRECIOSO\coding\GitHub\teste\janitor
**Mode:** DRY-RUN

## SUMMARY

- **Total Issues:** 60
- **Critical:** 5
- **High:** 11
- **Medium:** 10
- **Low:** 34

## FINDINGS

### 1. potential_xss

- **File:** `analyzer.py`
- **Line:** 67
- **Risk:** HIGH
- **Message:** Potential XSS vulnerability - unescaped user input

**Suggestion:** Use proper escaping or templating with auto-escape enabled.

### 2. high_complexity

- **File:** `analyzer.py`
- **Line:** 161
- **Risk:** MEDIUM
- **Message:** Function '_check_dangerous_calls' has cyclomatic complexity of 11 (max: 10)

**Suggestion:** Consider refactoring into smaller functions.

### 3. high_complexity

- **File:** `analyzer.py`
- **Line:** 303
- **Risk:** MEDIUM
- **Message:** Function '_check_unused_imports' has cyclomatic complexity of 14 (max: 10)

**Suggestion:** Consider refactoring into smaller functions.

### 4. missing_docstring

- **File:** `analyzer.py`
- **Line:** 80
- **Risk:** LOW
- **Message:** Function '__init__' has no docstring

**Suggestion:** Add a docstring to document the purpose and usage.

### 5. unused_import

- **File:** `analyzer.py`
- **Line:** 7
- **Risk:** LOW
- **Message:** Import 'Any' is not used

**Suggestion:** Remove unused imports to keep code clean.

### 6. high_complexity

- **File:** `cli.py`
- **Line:** 102
- **Risk:** MEDIUM
- **Message:** Function 'run' has cyclomatic complexity of 21 (max: 10)

**Suggestion:** Consider refactoring into smaller functions.

### 7. high_complexity

- **File:** `cli.py`
- **Line:** 154
- **Risk:** MEDIUM
- **Message:** Function '_run_json' has cyclomatic complexity of 19 (max: 10)

**Suggestion:** Consider refactoring into smaller functions.

### 8. high_complexity

- **File:** `cli.py`
- **Line:** 235
- **Risk:** MEDIUM
- **Message:** Function '_run_llm_analysis' has cyclomatic complexity of 15 (max: 10)

**Suggestion:** Consider refactoring into smaller functions.

### 9. high_complexity

- **File:** `cli.py`
- **Line:** 338
- **Risk:** MEDIUM
- **Message:** Function '_generate_report_content' has cyclomatic complexity of 11 (max: 10)

**Suggestion:** Consider refactoring into smaller functions.

### 10. missing_docstring

- **File:** `cli.py`
- **Line:** 45
- **Risk:** LOW
- **Message:** Function '__init__' has no docstring

**Suggestion:** Add a docstring to document the purpose and usage.

### 11. unused_import

- **File:** `cli.py`
- **Line:** 17
- **Risk:** LOW
- **Message:** Import 'Progress' is not used

**Suggestion:** Remove unused imports to keep code clean.

### 12. unused_import

- **File:** `cli.py`
- **Line:** 17
- **Risk:** LOW
- **Message:** Import 'SpinnerColumn' is not used

**Suggestion:** Remove unused imports to keep code clean.

### 13. unused_import

- **File:** `cli.py`
- **Line:** 17
- **Risk:** LOW
- **Message:** Import 'TextColumn' is not used

**Suggestion:** Remove unused imports to keep code clean.

### 14. unused_import

- **File:** `cli.py`
- **Line:** 18
- **Risk:** LOW
- **Message:** Import 'Text' is not used

**Suggestion:** Remove unused imports to keep code clean.

### 15. unused_import

- **File:** `cli.py`
- **Line:** 21
- **Risk:** LOW
- **Message:** Import 'Finding' is not used

**Suggestion:** Remove unused imports to keep code clean.

### 16. unused_import

- **File:** `cli.py`
- **Line:** 21
- **Risk:** LOW
- **Message:** Import 'RiskLevel' is not used

**Suggestion:** Remove unused imports to keep code clean.

### 17. missing_docstring

- **File:** `js_analyzer.py`
- **Line:** 48
- **Risk:** LOW
- **Message:** Function '__init__' has no docstring

**Suggestion:** Add a docstring to document the purpose and usage.

### 18. unused_import

- **File:** `js_analyzer.py`
- **Line:** 6
- **Risk:** LOW
- **Message:** Import 'Dict' is not used

**Suggestion:** Remove unused imports to keep code clean.

### 19. unused_import

- **File:** `js_analyzer.py`
- **Line:** 6
- **Risk:** LOW
- **Message:** Import 'Any' is not used

**Suggestion:** Remove unused imports to keep code clean.

### 20. unused_import

- **File:** `js_analyzer.py`
- **Line:** 8
- **Risk:** LOW
- **Message:** Import 'PythonAnalysisResult' is not used

**Suggestion:** Remove unused imports to keep code clean.

### 21. hardcoded_url

- **File:** `llm.py`
- **Line:** 129
- **Risk:** HIGH
- **Message:** Hardcoded URL with potential credentials

**Suggestion:** Use environment variables for connection strings.

### 22. missing_docstring

- **File:** `llm.py`
- **Line:** 44
- **Risk:** LOW
- **Message:** Function '__init__' has no docstring

**Suggestion:** Add a docstring to document the purpose and usage.

### 23. unused_import

- **File:** `llm.py`
- **Line:** 9
- **Risk:** LOW
- **Message:** Import 'field' is not used

**Suggestion:** Remove unused imports to keep code clean.

### 24. missing_docstring

- **File:** `manager.py`
- **Line:** 212
- **Risk:** LOW
- **Message:** Function '__init__' has no docstring

**Suggestion:** Add a docstring to document the purpose and usage.

### 25. unused_import

- **File:** `manager.py`
- **Line:** 10
- **Risk:** LOW
- **Message:** Import 'field' is not used

**Suggestion:** Remove unused imports to keep code clean.

### 26. unused_import

- **File:** `manager.py`
- **Line:** 11
- **Risk:** LOW
- **Message:** Import 'json' is not used

**Suggestion:** Remove unused imports to keep code clean.

### 27. high_complexity

- **File:** `scanner.py`
- **Line:** 74
- **Risk:** MEDIUM
- **Message:** Function '_should_ignore' has cyclomatic complexity of 15 (max: 10)

**Suggestion:** Consider refactoring into smaller functions.

### 28. missing_docstring

- **File:** `scanner.py`
- **Line:** 33
- **Risk:** LOW
- **Message:** Function '__init__' has no docstring

**Suggestion:** Add a docstring to document the purpose and usage.

### 29. dangerous_function

- **File:** `tests\example_vulnerable.py`
- **Line:** 12
- **Risk:** HIGH
- **Message:** Use of eval() can be dangerous

**Suggestion:** Avoid eval/exec/compile. Consider safer alternatives.

### 30. dangerous_function

- **File:** `tests\example_vulnerable.py`
- **Line:** 17
- **Risk:** HIGH
- **Message:** Use of exec() can be dangerous

**Suggestion:** Avoid eval/exec/compile. Consider safer alternatives.

### 31. subprocess_shell_true

- **File:** `tests\example_vulnerable.py`
- **Line:** 21
- **Risk:** HIGH
- **Message:** shell=True in subprocess can allow command injection

**Suggestion:** Use shell=False and pass commands as a list.

### 32. subprocess_shell_true

- **File:** `tests\example_vulnerable.py`
- **Line:** 22
- **Risk:** HIGH
- **Message:** shell=True in subprocess can allow command injection

**Suggestion:** Use shell=False and pass commands as a list.

### 33. potential_secret

- **File:** `tests\example_vulnerable.py`
- **Line:** 7
- **Risk:** CRITICAL
- **Message:** Possible secret or credential hardcoded

**Suggestion:** Use environment variables or a secrets manager.

### 34. potential_secret

- **File:** `tests\example_vulnerable.py`
- **Line:** 8
- **Risk:** CRITICAL
- **Message:** Possible secret or credential hardcoded

**Suggestion:** Use environment variables or a secrets manager.

### 35. missing_docstring

- **File:** `tests\example_vulnerable.py`
- **Line:** 11
- **Risk:** LOW
- **Message:** Function 'process_user_input' has no docstring

**Suggestion:** Add a docstring to document the purpose and usage.

### 36. missing_docstring

- **File:** `tests\example_vulnerable.py`
- **Line:** 16
- **Risk:** LOW
- **Message:** Function 'run_dynamic_code' has no docstring

**Suggestion:** Add a docstring to document the purpose and usage.

### 37. missing_docstring

- **File:** `tests\example_vulnerable.py`
- **Line:** 20
- **Risk:** LOW
- **Message:** Function 'run_command' has no docstring

**Suggestion:** Add a docstring to document the purpose and usage.

### 38. missing_docstring

- **File:** `tests\example_vulnerable.py`
- **Line:** 25
- **Risk:** LOW
- **Message:** Function 'write_file' has no docstring

**Suggestion:** Add a docstring to document the purpose and usage.

### 39. missing_docstring

- **File:** `tests\example_vulnerable.py`
- **Line:** 30
- **Risk:** LOW
- **Message:** Function 'calculate' has no docstring

**Suggestion:** Add a docstring to document the purpose and usage.

### 40. unused_import

- **File:** `tests\example_vulnerable.py`
- **Line:** 4
- **Risk:** LOW
- **Message:** Import 'os' is not used

**Suggestion:** Remove unused imports to keep code clean.

### 41. potential_secret

- **File:** `tests\test_analyzer.py`
- **Line:** 69
- **Risk:** CRITICAL
- **Message:** Possible secret or credential hardcoded

**Suggestion:** Use environment variables or a secrets manager.

### 42. potential_secret

- **File:** `tests\test_analyzer.py`
- **Line:** 70
- **Risk:** CRITICAL
- **Message:** Possible secret or credential hardcoded

**Suggestion:** Use environment variables or a secrets manager.

### 43. unused_import

- **File:** `tests\test_analyzer.py`
- **Line:** 7
- **Risk:** LOW
- **Message:** Import 'Finding' is not used

**Suggestion:** Remove unused imports to keep code clean.

### 44. unused_import

- **File:** `tests\test_manager.py`
- **Line:** 6
- **Risk:** LOW
- **Message:** Import 'shutil' is not used

**Suggestion:** Remove unused imports to keep code clean.

### 45. unused_import

- **File:** `tests\test_scanner.py`
- **Line:** 6
- **Risk:** LOW
- **Message:** Import 'os' is not used

**Suggestion:** Remove unused imports to keep code clean.

### 46. unused_import

- **File:** `tests\test_scanner.py`
- **Line:** 8
- **Risk:** LOW
- **Message:** Import 'IGNORE_DIRS' is not used

**Suggestion:** Remove unused imports to keep code clean.

### 47. unused_import

- **File:** `tests\test_scanner.py`
- **Line:** 8
- **Risk:** LOW
- **Message:** Import 'SUPPORTED_EXTENSIONS' is not used

**Suggestion:** Remove unused imports to keep code clean.

### 48. unused_import

- **File:** `tests\__init__.py`
- **Line:** 3
- **Risk:** LOW
- **Message:** Import 'pytest' is not used

**Suggestion:** Remove unused imports to keep code clean.

### 49. dangerous_function

- **File:** `tests\example_vulnerable.js`
- **Line:** 5
- **Risk:** HIGH
- **Message:** Use of dangerous function detected

**Suggestion:** Avoid eval/Function with dynamic content.

### 50. dom_xss

- **File:** `tests\example_vulnerable.js`
- **Line:** 10
- **Risk:** HIGH
- **Message:** Using innerHTML can lead to XSS

### 51. console_log

- **File:** `tests\example_vulnerable.js`
- **Line:** 15
- **Risk:** LOW
- **Message:** Console statement left in code

### 52. debugger_statement

- **File:** `tests\example_vulnerable.js`
- **Line:** 21
- **Risk:** MEDIUM
- **Message:** Debugger statement left in code

### 53. storage_secret

- **File:** `tests\example_vulnerable.js`
- **Line:** 27
- **Risk:** CRITICAL
- **Message:** Storing passwords in localStorage

### 54. alert_usage

- **File:** `tests\example_vulnerable.js`
- **Line:** 32
- **Risk:** LOW
- **Message:** Using alert() is not recommended

### 55. dangerous_function

- **File:** `tests\example_vulnerable.ts`
- **Line:** 11
- **Risk:** HIGH
- **Message:** Use of dangerous function detected

**Suggestion:** Avoid eval/Function with dynamic content.

### 56. dom_xss

- **File:** `tests\example_vulnerable.ts`
- **Line:** 23
- **Risk:** HIGH
- **Message:** Using innerHTML can lead to XSS

### 57. console_log

- **File:** `tests\example_vulnerable.ts`
- **Line:** 28
- **Risk:** LOW
- **Message:** Console statement left in code

### 58. any_type

- **File:** `tests\example_vulnerable.ts`
- **Line:** 4
- **Risk:** MEDIUM
- **Message:** Using "any" type defeats TypeScript purpose

### 59. ts_nocheck

- **File:** `tests\example_vulnerable.ts`
- **Line:** 9
- **Risk:** HIGH
- **Message:** Using @ts-nocheck disables type checking for file

### 60. ts_ignore

- **File:** `tests\example_vulnerable.ts`
- **Line:** 15
- **Risk:** MEDIUM
- **Message:** Using @ts-ignore suppresses type checking

## RECOMMENDATIONS

1. Review all CRITICAL and HIGH severity issues immediately
2. Implement suggested fixes for security vulnerabilities
3. Add comprehensive test coverage
4. Consider using a secrets management solution
5. Enable pre-commit hooks for security scanning

## BACKUPS

Backups created in: backups
