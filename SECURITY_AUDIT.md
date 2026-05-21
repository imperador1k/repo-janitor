# SECURITY AUDIT REPORT

**Generated:** 2026-05-21T18:28:40.368116
**Repository:** C:\Users\User\Documents\PRECIOSO\coding\GitHub\teste
**Mode:** DRY-RUN

## LANGUAGE DISTRIBUTION

- **Python:** 93.8%
- **Markdown:** 5.4%
- **TOML:** 0.4%
- **JavaScript:** 0.2%
- **TypeScript:** 0.2%

## SUMMARY

- **Total Issues:** 1605
- **Critical:** 593
- **High:** 76
- **Medium:** 150
- **Low:** 786

## FINDINGS

### 1. PY-PATH-001

- **File:** `janitor\cli.py`
- **Line:** 342
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 2. PY-PATH-001

- **File:** `janitor\cli.py`
- **Line:** 363
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 3. PY-PATH-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 229
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 4. PY-PATH-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 248
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 5. PY-PATH-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 265
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 6. PY-PATH-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 283
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 7. PY-PATH-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 311
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 8. PY-PATH-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 328
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 9. PY-PATH-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 340
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 10. PY-PATH-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 354
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 11. PY-PATH-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 367
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 12. PY-PATH-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 383
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 13. PY-PATH-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 396
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 14. PY-PATH-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 405
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 15. PY-PATH-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 414
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 16. PY-COMPILE-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 421
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 17. PY-PATH-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 444
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 18. PY-PATH-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 452
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 19. PY-PATH-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 457
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 20. PY-COMPILE-001

- **File:** `janitor\js_analyzer.py`
- **Line:** 49
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 21. PY-PATH-001

- **File:** `janitor\js_analyzer.py`
- **Line:** 56
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 22. PY-PATH-001

- **File:** `janitor\language_detector.py`
- **Line:** 157
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 23. PY-PATH-001

- **File:** `janitor\manager.py`
- **Line:** 79
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 24. PY-PATH-001

- **File:** `janitor\manager.py`
- **Line:** 223
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 25. PY-PATH-001

- **File:** `janitor\manager.py`
- **Line:** 232
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 26. PY-PATH-001

- **File:** `janitor\manager.py`
- **Line:** 268
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 27. PY-PATH-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 52
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 28. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 91
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 29. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 107
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 30. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 123
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 31. PY-SQL-003

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 128
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 32. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 139
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 33. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 155
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 34. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 171
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 35. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 187
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 36. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 203
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 37. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 219
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 38. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 235
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 39. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 251
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 40. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 267
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 41. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 283
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 42. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 299
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 43. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 315
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 44. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 331
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 45. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 347
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 46. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 363
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 47. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 379
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 48. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 395
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 49. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 411
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 50. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 427
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 51. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 443
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 52. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 466
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 53. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 482
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 54. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 498
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 55. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 514
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 56. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 530
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 57. PY-SQL-003

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 545
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 58. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 546
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 59. PY-SQL-003

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 551
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 60. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 562
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 61. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 578
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 62. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 594
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 63. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 610
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 64. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 626
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 65. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 642
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 66. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 658
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 67. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 674
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 68. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 690
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 69. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 706
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 70. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 729
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 71. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 745
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 72. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 761
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 73. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 777
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 74. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 793
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 75. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 809
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 76. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 825
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 77. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 841
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 78. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 857
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 79. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 873
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 80. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 889
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 81. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 912
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 82. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 928
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 83. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 944
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 84. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 960
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 85. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 976
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 86. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 992
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 87. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1008
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 88. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1024
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 89. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1040
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 90. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1209
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 91. PY-SQL-003

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1222
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 92. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1231
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 93. PY-SQL-003

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1235
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 94. PY-PATH-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 52
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 95. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 91
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 96. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 107
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 97. PY-SQL-003

- **File:** `janitor\analyzers\go.py`
- **Line:** 122
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 98. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 123
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 99. PY-SQL-003

- **File:** `janitor\analyzers\go.py`
- **Line:** 128
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 100. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 139
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 101. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 155
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 102. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 171
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 103. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 187
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 104. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 203
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 105. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 219
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 106. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 235
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 107. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 251
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 108. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 267
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 109. PY-SSTI-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 279
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 110. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 283
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 111. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 299
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 112. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 315
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 113. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 338
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 114. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 354
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 115. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 370
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 116. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 386
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 117. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 402
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 118. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 418
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 119. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 434
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 120. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 450
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 121. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 466
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 122. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 482
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 123. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 498
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 124. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 514
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 125. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 537
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 126. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 553
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 127. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 569
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 128. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 585
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 129. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 601
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 130. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 617
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 131. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 633
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 132. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 649
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 133. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 672
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 134. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 688
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 135. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 704
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 136. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 720
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 137. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 736
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 138. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 752
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 139. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 768
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 140. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 911
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 141. PY-SSTI-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 963
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 142. PY-PATH-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 52
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 143. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 91
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 144. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 107
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 145. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 123
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 146. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 139
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 147. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 155
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 148. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 171
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 149. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 187
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 150. PY-EXEC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 199
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 151. PY-EXEC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 202
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 152. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 203
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 153. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 219
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 154. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 235
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 155. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 251
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 156. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 267
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 157. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 283
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 158. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 299
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 159. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 315
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 160. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 331
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 161. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 347
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 162. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 363
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 163. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 379
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 164. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 395
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 165. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 411
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 166. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 427
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 167. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 443
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 168. PY-SSTI-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 448
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 169. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 459
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 170. PY-SSTI-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 464
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 171. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 475
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 172. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 491
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 173. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 514
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 174. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 530
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 175. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 546
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 176. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 562
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 177. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 578
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 178. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 594
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 179. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 610
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 180. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 626
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 181. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 642
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 182. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 658
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 183. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 674
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 184. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 690
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 185. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 706
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 186. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 722
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 187. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 738
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 188. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 754
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 189. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 770
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 190. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 793
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 191. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 809
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 192. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 825
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 193. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 841
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 194. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 857
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 195. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 873
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 196. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 889
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 197. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 905
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 198. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 921
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 199. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 937
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 200. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 953
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 201. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 969
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 202. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 985
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 203. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1008
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 204. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1024
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 205. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1040
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 206. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1056
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 207. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1072
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 208. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1088
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 209. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1104
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 210. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1120
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 211. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1136
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 212. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1152
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 213. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1327
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 214. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1349
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 215. PY-PATH-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 52
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 216. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 91
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 217. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 107
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 218. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 123
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 219. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 139
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 220. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 155
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 221. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 171
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 222. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 187
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 223. PY-EVAL-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 199
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 224. PY-EVAL-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 202
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 225. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 203
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 226. PY-EVAL-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 208
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 227. PY-EVAL-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 209
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 228. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 219
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 229. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 235
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 230. PY-EXEC-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 250
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 231. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 251
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 232. PY-EXEC-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 257
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 233. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 267
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 234. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 283
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 235. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 299
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 236. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 315
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 237. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 331
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 238. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 347
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 239. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 363
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 240. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 386
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 241. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 402
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 242. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 418
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 243. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 434
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 244. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 450
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 245. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 466
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 246. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 482
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 247. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 498
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 248. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 514
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 249. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 530
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 250. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 546
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 251. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 569
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 252. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 585
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 253. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 601
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 254. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 617
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 255. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 633
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 256. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 649
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 257. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 665
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 258. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 681
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 259. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 697
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 260. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 720
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 261. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 736
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 262. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 752
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 263. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 768
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 264. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 784
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 265. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 800
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 266. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 816
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 267. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 832
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 268. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 848
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 269. PY-EVAL-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 945
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 270. PY-EXEC-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 947
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 271. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 989
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 272. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 990
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 273. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 1002
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 274. PY-PATH-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 53
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 275. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 94
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 276. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 109
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 277. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 124
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 278. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 139
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 279. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 154
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 280. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 169
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 281. PY-EXEC-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 190
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 282. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 191
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 283. PY-EXEC-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 197
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 284. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 206
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 285. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 221
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 286. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 243
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 287. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 258
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 288. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 280
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 289. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 295
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 290. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 310
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 291. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 332
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 292. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 347
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 293. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 362
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 294. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 377
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 295. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 392
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 296. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 414
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 297. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 429
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 298. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 444
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 299. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 459
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 300. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 481
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 301. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 496
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 302. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 511
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 303. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 526
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 304. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 548
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 305. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 563
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 306. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 578
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 307. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 593
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 308. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 615
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 309. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 630
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 310. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 645
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 311. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 660
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 312. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 682
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 313. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 697
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 314. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 712
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 315. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 727
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 316. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 749
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 317. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 764
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 318. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 786
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 319. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 801
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 320. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 823
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 321. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 845
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 322. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 867
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 323. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 889
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 324. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 911
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 325. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 933
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 326. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 955
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 327. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 977
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 328. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 992
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 329. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1164
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 330. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1165
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 331. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1178
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 332. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1205
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 333. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1234
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 334. PY-PATH-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 52
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 335. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 91
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 336. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 107
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 337. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 123
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 338. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 139
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 339. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 155
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 340. PY-EXEC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 160
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 341. PY-EXEC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 161
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 342. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 171
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 343. PY-EVAL-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 183
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 344. PY-EVAL-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 186
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 345. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 187
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 346. PY-EVAL-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 189
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 347. PY-EVAL-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 193
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 348. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 203
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 349. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 219
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 350. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 235
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 351. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 251
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 352. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 267
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 353. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 283
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 354. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 299
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 355. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 315
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 356. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 331
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 357. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 354
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 358. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 370
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 359. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 386
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 360. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 402
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 361. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 418
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 362. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 434
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 363. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 450
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 364. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 466
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 365. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 482
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 366. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 498
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 367. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 514
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 368. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 530
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 369. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 546
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 370. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 562
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 371. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 585
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 372. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 601
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 373. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 617
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 374. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 633
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 375. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 649
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 376. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 665
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 377. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 681
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 378. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 697
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 379. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 713
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 380. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 729
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 381. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 745
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 382. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 761
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 383. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 777
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 384. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 800
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 385. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 816
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 386. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 832
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 387. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 848
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 388. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 864
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 389. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 880
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 390. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 896
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 391. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 912
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 392. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1074
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 393. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1098
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 394. PY-PATH-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 53
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 395. PY-EVAL-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 129
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 396. PY-EVAL-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 132
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 397. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 133
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 398. PY-EVAL-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 139
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 399. PY-EXEC-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 145
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 400. PY-EXEC-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 148
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 401. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 149
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 402. PY-EXEC-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 154
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 403. PY-EXEC-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 155
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 404. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 161
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 405. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 164
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 406. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 165
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 407. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 167
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 408. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 170
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 409. PY-EXEC-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 171
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 410. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 171
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 411. PY-CMD-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 180
- **Risk:** CRITICAL
- **Message:** [Command Injection via os.system] os.system() passes strings to shell, enabling command injection

**Suggestion:** Use subprocess.run with a list of arguments (shell=False)

### 412. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 181
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 413. PY-CMD-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 187
- **Risk:** CRITICAL
- **Message:** [Command Injection via os.system] os.system() passes strings to shell, enabling command injection

**Suggestion:** Use subprocess.run with a list of arguments (shell=False)

### 414. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 197
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 415. PY-CMD-003

- **File:** `janitor\analyzers\python.py`
- **Line:** 212
- **Risk:** CRITICAL
- **Message:** [Command Injection via os.popen] os.popen() executes commands via shell, enabling injection

**Suggestion:** Use subprocess.run with argument list (shell=False)

### 416. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 213
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 417. PY-CMD-003

- **File:** `janitor\analyzers\python.py`
- **Line:** 219
- **Risk:** CRITICAL
- **Message:** [Command Injection via os.popen] os.popen() executes commands via shell, enabling injection

**Suggestion:** Use subprocess.run with argument list (shell=False)

### 418. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 229
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 419. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 245
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 420. PY-SQL-003

- **File:** `janitor\analyzers\python.py`
- **Line:** 254
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 421. PY-SQL-003

- **File:** `janitor\analyzers\python.py`
- **Line:** 260
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 422. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 261
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 423. PY-SQL-003

- **File:** `janitor\analyzers\python.py`
- **Line:** 261
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 424. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 277
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 425. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 293
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 426. PY-DESER-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 308
- **Risk:** CRITICAL
- **Message:** [Unsafe Deserialization via pickle] pickle.loads() can execute arbitrary Python code during deserialization

**Suggestion:** Use json, msgpack, or yaml.safe_load() instead of pickle

### 427. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 309
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 428. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 325
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 429. PY-DESER-003

- **File:** `janitor\analyzers\python.py`
- **Line:** 340
- **Risk:** CRITICAL
- **Message:** [Unsafe Deserialization via jsonpickle] jsonpickle.decode() can reconstruct arbitrary Python objects

**Suggestion:** Use plain json.loads() instead of jsonpickle for untrusted data

### 430. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 341
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 431. PY-SSTI-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 350
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 432. PY-SSTI-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 353
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 433. PY-SSTI-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 356
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 434. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 357
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 435. PY-SSTI-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 357
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 436. PY-SSTI-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 363
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 437. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 373
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 438. PY-SSTI-002

- **File:** `janitor\analyzers\python.py`
- **Line:** 373
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Mako)] Mako templates from user strings can enable SSTI and RCE

**Suggestion:** Use the Mako template lookup with file-based templates, not from_string

### 439. PY-SSTI-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 375
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 440. PY-XSS-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 385
- **Risk:** CRITICAL
- **Message:** [XSS via Django mark_safe or |safe filter] mark_safe() or the |safe template filter disables HTML escaping

**Suggestion:** Avoid marking user input as safe. Use format_html() instead

### 441. PY-XSS-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 388
- **Risk:** CRITICAL
- **Message:** [XSS via Django mark_safe or |safe filter] mark_safe() or the |safe template filter disables HTML escaping

**Suggestion:** Avoid marking user input as safe. Use format_html() instead

### 442. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 389
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 443. PY-XSS-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 395
- **Risk:** CRITICAL
- **Message:** [XSS via Django mark_safe or |safe filter] mark_safe() or the |safe template filter disables HTML escaping

**Suggestion:** Avoid marking user input as safe. Use format_html() instead

### 444. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 405
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 445. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 421
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 446. PY-SSTI-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 426
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 447. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 437
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 448. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 453
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 449. PY-SSRF-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 468
- **Risk:** CRITICAL
- **Message:** [Server-Side Request Forgery (SSRF)] requests.get() with user-controlled URL can target internal services

**Suggestion:** Validate URL against an allowlist. Block private IP ranges

### 450. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 469
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 451. PY-SSRF-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 475
- **Risk:** CRITICAL
- **Message:** [Server-Side Request Forgery (SSRF)] requests.get() with user-controlled URL can target internal services

**Suggestion:** Validate URL against an allowlist. Block private IP ranges

### 452. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 485
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 453. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 501
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 454. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 524
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 455. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 540
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 456. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 556
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 457. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 572
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 458. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 588
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 459. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 604
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 460. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 620
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 461. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 636
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 462. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 652
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 463. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 668
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 464. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 684
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 465. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 700
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 466. PY-PATH-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 705
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 467. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 716
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 468. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 732
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 469. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 748
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 470. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 764
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 471. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 787
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 472. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 803
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 473. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 819
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 474. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 835
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 475. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 851
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 476. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 867
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 477. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 883
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 478. PY-SSRF-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 888
- **Risk:** CRITICAL
- **Message:** [Server-Side Request Forgery (SSRF)] requests.get() with user-controlled URL can target internal services

**Suggestion:** Validate URL against an allowlist. Block private IP ranges

### 479. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 899
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 480. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 915
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 481. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 931
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 482. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 947
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 483. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 970
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 484. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 986
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 485. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1002
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 486. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1018
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 487. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1034
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 488. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1050
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 489. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1066
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 490. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1082
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 491. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1098
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 492. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1114
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 493. PY-SSTI-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1143
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 494. PY-SSTI-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1144
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 495. PY-EVAL-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1216
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 496. PY-EXEC-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1217
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 497. PY-SQL-003

- **File:** `janitor\analyzers\python.py`
- **Line:** 1219
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 498. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1265
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 499. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1266
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 500. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1278
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 501. PY-EVAL-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1290
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 502. PY-EXEC-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1290
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 503. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1307
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 504. PY-PATH-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 51
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 505. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 90
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 506. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 106
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 507. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 122
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 508. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 138
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 509. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 154
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 510. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 170
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 511. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 186
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 512. PY-EVAL-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 198
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 513. PY-EVAL-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 201
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 514. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 202
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 515. PY-EVAL-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 207
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 516. PY-EVAL-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 208
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 517. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 218
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 518. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 234
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 519. PY-EXEC-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 249
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 520. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 250
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 521. PY-EXEC-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 256
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 522. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 266
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 523. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 282
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 524. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 298
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 525. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 314
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 526. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 330
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 527. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 346
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 528. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 362
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 529. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 378
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 530. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 394
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 531. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 410
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 532. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 426
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 533. PY-EVAL-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 431
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 534. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 449
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 535. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 465
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 536. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 481
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 537. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 497
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 538. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 513
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 539. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 529
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 540. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 545
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 541. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 561
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 542. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 577
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 543. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 593
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 544. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 609
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 545. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 625
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 546. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 641
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 547. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 657
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 548. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 673
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 549. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 696
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 550. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 712
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 551. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 728
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 552. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 744
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 553. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 760
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 554. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 776
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 555. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 792
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 556. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 808
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 557. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 824
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 558. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 840
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 559. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 856
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 560. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 872
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 561. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 888
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 562. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 911
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 563. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 927
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 564. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 943
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 565. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 959
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 566. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 975
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 567. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 991
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 568. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1007
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 569. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1023
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 570. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1039
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 571. PY-EVAL-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1140
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 572. PY-EXEC-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1142
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 573. PY-SQL-003

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1146
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 574. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1190
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 575. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1191
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 576. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1203
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 577. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1229
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 578. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1259
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 579. PY-SQL-003

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1355
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 580. PY-AUTH-002

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 7
- **Risk:** CRITICAL
- **Message:** [Hardcoded Password / Credential] Hardcoded passwords, API keys, or tokens in source code

**Suggestion:** Use environment variables, .env files, or a secrets manager

### 581. PY-AUTH-002

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 8
- **Risk:** CRITICAL
- **Message:** [Hardcoded Password / Credential] Hardcoded passwords, API keys, or tokens in source code

**Suggestion:** Use environment variables, .env files, or a secrets manager

### 582. PY-EVAL-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 12
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 583. PY-EXEC-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 17
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 584. PY-CMD-002

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 21
- **Risk:** CRITICAL
- **Message:** [Command Injection via subprocess shell=True] subprocess with shell=True enables shell injection via string arguments

**Suggestion:** Use shell=False with argument list instead of shell string

### 585. PY-CMD-002

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 22
- **Risk:** CRITICAL
- **Message:** [Command Injection via subprocess shell=True] subprocess with shell=True enables shell injection via string arguments

**Suggestion:** Use shell=False with argument list instead of shell string

### 586. PY-PATH-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 26
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 587. PY-EVAL-001

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 39
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 588. PY-EVAL-001

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 40
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 589. PY-EXEC-001

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 47
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 590. PY-EXEC-001

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 48
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 591. PY-CMD-002

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 57
- **Risk:** CRITICAL
- **Message:** [Command Injection via subprocess shell=True] subprocess with shell=True enables shell injection via string arguments

**Suggestion:** Use shell=False with argument list instead of shell string

### 592. PY-AUTH-002

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 68
- **Risk:** CRITICAL
- **Message:** [Hardcoded Password / Credential] Hardcoded passwords, API keys, or tokens in source code

**Suggestion:** Use environment variables, .env files, or a secrets manager

### 593. PY-AUTH-002

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 69
- **Risk:** CRITICAL
- **Message:** [Hardcoded Password / Credential] Hardcoded passwords, API keys, or tokens in source code

**Suggestion:** Use environment variables, .env files, or a secrets manager

### 594. PY-CRYPTO-001

- **File:** `janitor\manager.py`
- **Line:** 78
- **Risk:** HIGH
- **Message:** [Weak Hashing Algorithm (MD5/SHA1)] MD5 and SHA1 are cryptographically broken and vulnerable to collision attacks

**Suggestion:** Use hashlib.sha256() or stronger; use bcrypt/argon2 for passwords

### 595. PY-SMTP-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 96
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 596. PY-SMTP-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 112
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 597. PY-SMTP-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 128
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 598. PY-SMTP-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 830
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 599. PY-SMTP-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1213
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 600. PY-SMTP-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 96
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 601. PY-SMTP-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 112
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 602. PY-SMTP-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 128
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 603. PY-SMTP-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 176
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 604. PY-XXE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 292
- **Risk:** HIGH
- **Message:** [XML External Entity (XXE) Injection] XML parsing without disabling external entities can expose files or SSRF

**Suggestion:** Disable external entity processing when parsing XML

### 605. PY-XXE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 295
- **Risk:** HIGH
- **Message:** [XML External Entity (XXE) Injection] XML parsing without disabling external entities can expose files or SSRF

**Suggestion:** Disable external entity processing when parsing XML

### 606. PY-XXE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 298
- **Risk:** HIGH
- **Message:** [XML External Entity (XXE) Injection] XML parsing without disabling external entities can expose files or SSRF

**Suggestion:** Disable external entity processing when parsing XML

### 607. PY-XXE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 299
- **Risk:** HIGH
- **Message:** [XML External Entity (XXE) Injection] XML parsing without disabling external entities can expose files or SSRF

**Suggestion:** Disable external entity processing when parsing XML

### 608. PY-XXE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 301
- **Risk:** HIGH
- **Message:** [XML External Entity (XXE) Injection] XML parsing without disabling external entities can expose files or SSRF

**Suggestion:** Disable external entity processing when parsing XML

### 609. PY-XXE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 304
- **Risk:** HIGH
- **Message:** [XML External Entity (XXE) Injection] XML parsing without disabling external entities can expose files or SSRF

**Suggestion:** Disable external entity processing when parsing XML

### 610. PY-XXE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 305
- **Risk:** HIGH
- **Message:** [XML External Entity (XXE) Injection] XML parsing without disabling external entities can expose files or SSRF

**Suggestion:** Disable external entity processing when parsing XML

### 611. PY-SMTP-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 384
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 612. PY-SMTP-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 448
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 613. PY-SMTP-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 695
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 614. PY-REDIR-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 727
- **Risk:** HIGH
- **Message:** [Open Redirect via User-Controlled URL] redirect() or HttpResponseRedirect with user input enables phishing

**Suggestion:** Validate redirect URLs against an allowlist of trusted domains

### 615. PY-SMTP-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1331
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 616. PY-XXE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 498
- **Risk:** HIGH
- **Message:** [XML External Entity (XXE) Injection] XML parsing without disabling external entities can expose files or SSRF

**Suggestion:** Disable external entity processing when parsing XML

### 617. PY-SMTP-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 725
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 618. PY-SMTP-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 99
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 619. PY-SMTP-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 114
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 620. PY-SMTP-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 129
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 621. PY-SMTP-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 174
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 622. PY-SMTP-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1182
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 623. PY-SMTP-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 96
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 624. PY-SMTP-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 112
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 625. PY-SMTP-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 128
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 626. PY-SMTP-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 606
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 627. PY-SMTP-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1078
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 628. PY-TAINT-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 606
- **Risk:** HIGH
- **Message:** [Taint Flow] Data from Standard Input reaches SQL Execution without sanitization

**Suggestion:** Sanitize data between source and sink. Use parameterized queries, validation, or escapes

### 629. PY-TAINT-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1078
- **Risk:** HIGH
- **Message:** [Taint Flow] Data from Standard Input reaches SQL Execution without sanitization

**Suggestion:** Sanitize data between source and sink. Use parameterized queries, validation, or escapes

### 630. PY-SMTP-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 362
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 631. PY-SMTP-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 378
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 632. PY-SMTP-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 394
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 633. PY-SMTP-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 426
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 634. PY-SMTP-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 458
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 635. PY-SMTP-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 474
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 636. PY-SMTP-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 545
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 637. PY-CRYPTO-003

- **File:** `janitor\analyzers\python.py`
- **Line:** 556
- **Risk:** HIGH
- **Message:** [Insecure Block Cipher Mode (ECB)] ECB mode encrypts identical plaintext blocks to identical ciphertext blocks

**Suggestion:** Use CBC with random IV, or GCM/CTR mode with authentication

### 638. PY-SMTP-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 561
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 639. PY-SMTP-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 625
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 640. PY-SMTP-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 641
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 641. PY-CORS-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 651
- **Risk:** HIGH
- **Message:** [Overly Permissive CORS (Wildcard)] Flask/Django CORS with origins='*' exposes API to all domains

**Suggestion:** Specify exact allowed origins in an allowlist

### 642. PY-CSRF-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 661
- **Risk:** HIGH
- **Message:** [CSRF Protection Disabled (Django @csrf_exempt)] @csrf_exempt or @csrf_exempt disables CSRF protection for the view

**Suggestion:** Remove @csrf_exempt and use proper CSRF tokens for state-changing operations

### 643. PY-CSRF-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 664
- **Risk:** HIGH
- **Message:** [CSRF Protection Disabled (Django @csrf_exempt)] @csrf_exempt or @csrf_exempt disables CSRF protection for the view

**Suggestion:** Remove @csrf_exempt and use proper CSRF tokens for state-changing operations

### 644. PY-CSRF-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 667
- **Risk:** HIGH
- **Message:** [CSRF Protection Disabled (Django @csrf_exempt)] @csrf_exempt or @csrf_exempt disables CSRF protection for the view

**Suggestion:** Remove @csrf_exempt and use proper CSRF tokens for state-changing operations

### 645. PY-CSRF-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 668
- **Risk:** HIGH
- **Message:** [CSRF Protection Disabled (Django @csrf_exempt)] @csrf_exempt or @csrf_exempt disables CSRF protection for the view

**Suggestion:** Remove @csrf_exempt and use proper CSRF tokens for state-changing operations

### 646. PY-CSRF-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 670
- **Risk:** HIGH
- **Message:** [CSRF Protection Disabled (Django @csrf_exempt)] @csrf_exempt or @csrf_exempt disables CSRF protection for the view

**Suggestion:** Remove @csrf_exempt and use proper CSRF tokens for state-changing operations

### 647. PY-CSRF-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 673
- **Risk:** HIGH
- **Message:** [CSRF Protection Disabled (Django @csrf_exempt)] @csrf_exempt or @csrf_exempt disables CSRF protection for the view

**Suggestion:** Remove @csrf_exempt and use proper CSRF tokens for state-changing operations

### 648. PY-SMTP-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 689
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 649. PY-AUTH-003

- **File:** `janitor\analyzers\python.py`
- **Line:** 716
- **Risk:** HIGH
- **Message:** [SSH Host Key Verification Disabled (Paramiko)] AutoAddPolicy or MissingHostKeyPolicy allows MITM attacks

**Suggestion:** Use paramiko.RejectPolicy (default) or explicitly verify host keys

### 650. PY-CONFIG-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 731
- **Risk:** HIGH
- **Message:** [Django ALLOWED_HOSTS Wildcard] ALLOWED_HOSTS = ['*'] allows HTTP Host header attacks

**Suggestion:** Specify explicit allowed hostnames for your application

### 651. PY-TAINT-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 705
- **Risk:** HIGH
- **Message:** [Taint Flow] Data from Environment Variable reaches File Open without sanitization

**Suggestion:** Sanitize data between source and sink. Use parameterized queries, validation, or escapes

### 652. PY-TAINT-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 824
- **Risk:** HIGH
- **Message:** [Taint Flow] Data from Environment Variable reaches Subprocess Execution without sanitization

**Suggestion:** Sanitize data between source and sink. Use parameterized queries, validation, or escapes

### 653. PY-TAINT-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 840
- **Risk:** HIGH
- **Message:** [Taint Flow] Data from Environment Variable reaches Subprocess Execution without sanitization

**Suggestion:** Sanitize data between source and sink. Use parameterized queries, validation, or escapes

### 654. PY-TAINT-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 888
- **Risk:** HIGH
- **Message:** [Taint Flow] Data from Environment Variable reaches File Open without sanitization

**Suggestion:** Sanitize data between source and sink. Use parameterized queries, validation, or escapes

### 655. PY-TAINT-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1282
- **Risk:** HIGH
- **Message:** [Taint Flow] Data from Environment Variable reaches SQL Execution without sanitization

**Suggestion:** Sanitize data between source and sink. Use parameterized queries, validation, or escapes

### 656. PY-SMTP-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 255
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 657. PY-SMTP-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 415
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 658. PY-SMTP-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 454
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 659. PY-SMTP-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 486
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 660. PY-XXE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 609
- **Risk:** HIGH
- **Message:** [XML External Entity (XXE) Injection] XML parsing without disabling external entities can expose files or SSRF

**Suggestion:** Disable external entity processing when parsing XML

### 661. PY-SMTP-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 614
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 662. PY-SMTP-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 646
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 663. PY-SMTP-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 916
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 664. PY-SMTP-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1207
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 665. DEP-CVE-2024-47081

- **File:** `C:\Users\User\Documents\PRECIOSO\coding\GitHub\teste\requirements.txt`
- **Line:** 1
- **Risk:** HIGH
- **Message:** [MODERATE] requests@2.31.0 - Requests vulnerable to .netrc credentials leak via malicious URLs

**Suggestion:** Upgrade requests to version 2.32.4

### 666. DEP-CVE-2024-35195

- **File:** `C:\Users\User\Documents\PRECIOSO\coding\GitHub\teste\requirements.txt`
- **Line:** 1
- **Risk:** HIGH
- **Message:** [MODERATE] requests@2.31.0 - Requests `Session` object does not verify requests after making first request with verify=False

**Suggestion:** Upgrade requests to version 2.32.0

### 667. DEP-CVE-2026-25645

- **File:** `C:\Users\User\Documents\PRECIOSO\coding\GitHub\teste\requirements.txt`
- **Line:** 1
- **Risk:** HIGH
- **Message:** [MODERATE] requests@2.31.0 - Requests has Insecure Temp File Reuse in its extract_zipped_paths() utility function

**Suggestion:** Upgrade requests to version 2.33.0

### 668. DEP-CVE-2026-28684

- **File:** `C:\Users\User\Documents\PRECIOSO\coding\GitHub\teste\requirements.txt`
- **Line:** 4
- **Risk:** HIGH
- **Message:** [MODERATE] python-dotenv@1.0.0 - python-dotenv: Symlink following in set_key allows arbitrary file overwrite via cross-device rename fallback

**Suggestion:** Upgrade python-dotenv to version 1.2.2

### 669. DEP-CVE-2025-71176

- **File:** `C:\Users\User\Documents\PRECIOSO\coding\GitHub\teste\requirements.txt`
- **Line:** 8
- **Risk:** HIGH
- **Message:** [MODERATE] pytest@7.4.0 - pytest has vulnerable tmpdir handling

**Suggestion:** Upgrade pytest to version 9.0.3

### 670. PY-LOG-001

- **File:** `janitor\cli.py`
- **Line:** 75
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 671. PY-LOG-001

- **File:** `janitor\cli.py`
- **Line:** 130
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 672. PY-LOG-001

- **File:** `janitor\cli.py`
- **Line:** 323
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 673. PY-LOG-001

- **File:** `janitor\cli.py`
- **Line:** 326
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 674. PY-LOG-001

- **File:** `janitor\cli.py`
- **Line:** 360
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 675. PY-LOG-001

- **File:** `janitor\cli.py`
- **Line:** 383
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 676. PY-LOG-001

- **File:** `janitor\cli.py`
- **Line:** 386
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 677. PY-LOG-001

- **File:** `janitor\cli.py`
- **Line:** 415
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 678. PY-LOG-001

- **File:** `janitor\cli.py`
- **Line:** 426
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 679. PY-LOG-001

- **File:** `janitor\cli.py`
- **Line:** 571
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 680. PY-ERR-001

- **File:** `janitor\cli.py`
- **Line:** 423
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 681. PY-LOG-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 226
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 682. PY-LOG-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 477
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 683. PY-LOG-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 528
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 684. PY-LOG-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 532
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 685. PY-LOG-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 586
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 686. PY-LOG-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 619
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 687. PY-LOG-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 630
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 688. PY-LOG-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 641
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 689. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 229
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 690. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 248
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 691. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 265
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 692. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 283
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 693. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 311
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 694. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 328
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 695. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 340
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 696. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 354
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 697. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 367
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 698. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 383
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 699. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 396
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 700. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 405
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 701. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 414
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 702. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 444
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 703. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 452
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 704. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 457
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 705. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 517
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 706. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 575
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 707. PY-LOG-001

- **File:** `janitor\language_detector.py`
- **Line:** 89
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 708. PY-LOG-001

- **File:** `janitor\language_detector.py`
- **Line:** 122
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 709. PY-LOG-001

- **File:** `janitor\llm.py`
- **Line:** 61
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 710. PY-LOG-001

- **File:** `janitor\llm.py`
- **Line:** 63
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 711. PY-LOG-001

- **File:** `janitor\llm.py`
- **Line:** 78
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 712. PY-LOG-001

- **File:** `janitor\llm.py`
- **Line:** 91
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 713. PY-LOG-001

- **File:** `janitor\llm.py`
- **Line:** 100
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 714. PY-LOG-001

- **File:** `janitor\llm.py`
- **Line:** 227
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 715. PY-LOG-001

- **File:** `janitor\llm.py`
- **Line:** 247
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 716. PY-LOG-001

- **File:** `janitor\llm.py`
- **Line:** 324
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 717. PY-ERR-001

- **File:** `janitor\llm.py`
- **Line:** 75
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 718. PY-LOG-001

- **File:** `janitor\manager.py`
- **Line:** 72
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 719. PY-LOG-001

- **File:** `janitor\manager.py`
- **Line:** 179
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 720. PY-LOG-001

- **File:** `janitor\manager.py`
- **Line:** 184
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 721. PY-LOG-001

- **File:** `janitor\manager.py`
- **Line:** 193
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 722. PY-LOG-001

- **File:** `janitor\manager.py`
- **Line:** 271
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 723. PY-LOG-001

- **File:** `janitor\manager.py`
- **Line:** 274
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 724. PY-ERR-001

- **File:** `janitor\manager.py`
- **Line:** 79
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 725. PY-LOG-001

- **File:** `janitor\scanner.py`
- **Line:** 55
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 726. PY-LOG-001

- **File:** `janitor\scanner.py`
- **Line:** 57
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 727. PY-LOG-001

- **File:** `janitor\scanner.py`
- **Line:** 108
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 728. PY-LOG-001

- **File:** `janitor\scanner.py`
- **Line:** 125
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 729. PY-FORMAT-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1017
- **Risk:** MEDIUM
- **Message:** [Format String Vulnerability via User Input] Using user input as the format string with % operator can expose memory

**Suggestion:** Use str.format() or f-strings with positional arguments, not % formatting with user data

### 730. PY-ERR-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 199
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 731. PY-ERR-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 202
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 732. PY-ERR-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 199
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 733. PY-ERR-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 202
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 734. PY-ERR-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 208
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 735. PY-ERR-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 209
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 736. PY-ERR-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 250
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 737. PY-ERR-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 257
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 738. PY-ERR-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 945
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 739. PY-ERR-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 947
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 740. PY-ERR-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 1054
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 741. PY-ERR-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 190
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 742. PY-ERR-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 197
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 743. PY-ASSERT-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 196
- **Risk:** MEDIUM
- **Message:** [Assert Used for Validation] assert statements are removed when Python runs with -O (optimize)

**Suggestion:** Use proper if/raise validation instead of assert for security checks

### 744. PY-ASSERT-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 208
- **Risk:** MEDIUM
- **Message:** [Assert Used for Validation] assert statements are removed when Python runs with -O (optimize)

**Suggestion:** Use proper if/raise validation instead of assert for security checks

### 745. PY-ERR-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 160
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 746. PY-ERR-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 161
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 747. PY-ERR-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 183
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 748. PY-ERR-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 186
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 749. PY-ERR-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 189
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 750. PY-ERR-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 193
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 751. PY-ERR-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 304
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 752. PY-SUBPROCESS-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 186
- **Risk:** MEDIUM
- **Message:** [Subprocess Without Timeout] subprocess.run() without timeout can hang indefinitely

**Suggestion:** Always set a timeout for subprocess operations

### 753. PY-SUBPROCESS-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 202
- **Risk:** MEDIUM
- **Message:** [Subprocess Without Timeout] subprocess.run() without timeout can hang indefinitely

**Suggestion:** Always set a timeout for subprocess operations

### 754. PY-SUBPROCESS-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 218
- **Risk:** MEDIUM
- **Message:** [Subprocess Without Timeout] subprocess.run() without timeout can hang indefinitely

**Suggestion:** Always set a timeout for subprocess operations

### 755. PY-FORMAT-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 808
- **Risk:** MEDIUM
- **Message:** [Format String Vulnerability via User Input] Using user input as the format string with % operator can expose memory

**Suggestion:** Use str.format() or f-strings with positional arguments, not % formatting with user data

### 756. PY-SUBPROCESS-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 840
- **Risk:** MEDIUM
- **Message:** [Subprocess Without Timeout] subprocess.run() without timeout can hang indefinitely

**Suggestion:** Always set a timeout for subprocess operations

### 757. PY-FILE-002

- **File:** `janitor\analyzers\python.py`
- **Line:** 866
- **Risk:** MEDIUM
- **Message:** [Overly Permissive File Permissions (0o777)] os.chmod(0o777) makes files world-readable/writable/executable

**Suggestion:** Use minimum required permissions (e.g., 0o600 for secrets, 0o755 for executables)

### 758. PY-DEPR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 883
- **Risk:** MEDIUM
- **Message:** [Deprecated API Usage] Using deprecated Python APIs that may have known vulnerabilities

**Suggestion:** Replace deprecated APIs with modern alternatives

### 759. PY-DEPR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 888
- **Risk:** MEDIUM
- **Message:** [Deprecated API Usage] Using deprecated Python APIs that may have known vulnerabilities

**Suggestion:** Replace deprecated APIs with modern alternatives

### 760. PY-LOG-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1055
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 761. PY-LOG-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1071
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 762. PY-LOG-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1311
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 763. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 129
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 764. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 132
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 765. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 135
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 766. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 145
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 767. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 148
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 768. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 154
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 769. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 155
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 770. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 171
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 771. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 183
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (subprocess.run) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 772. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 186
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (subprocess.run) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 773. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 202
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (subprocess.run) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 774. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 212
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 775. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 215
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (subprocess.run) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 776. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 218
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (subprocess.run) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 777. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 219
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 778. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 308
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (pickle.load) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 779. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 318
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (yaml.load) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 780. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 321
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (yaml.load) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 781. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 324
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (yaml.load) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 782. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 327
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (yaml.load) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 783. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 433
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 784. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 436
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 785. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 443
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 786. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 699
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 787. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 818
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (subprocess.run) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 788. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 824
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (subprocess.run) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 789. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 840
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (subprocess.run) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 790. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 888
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 791. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1216
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 792. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1217
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 793. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1220
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 794. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1221
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (pickle.load) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 795. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1222
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (yaml.load) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 796. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1321
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 797. PY-ERR-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 198
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 798. PY-ERR-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 201
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 799. PY-ERR-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 207
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 800. PY-ERR-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 208
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 801. PY-ERR-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 249
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 802. PY-ERR-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 256
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 803. PY-ERR-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 431
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 804. PY-ERR-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1140
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 805. PY-ERR-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1142
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 806. PY-ERR-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1327
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 807. PY-SUBPROCESS-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 21
- **Risk:** MEDIUM
- **Message:** [Subprocess Without Timeout] subprocess.run() without timeout can hang indefinitely

**Suggestion:** Always set a timeout for subprocess operations

### 808. PY-SUBPROCESS-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 22
- **Risk:** MEDIUM
- **Message:** [Subprocess Without Timeout] subprocess.run() without timeout can hang indefinitely

**Suggestion:** Always set a timeout for subprocess operations

### 809. PY-ERR-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 12
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 810. PY-ERR-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 17
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 811. PY-ERR-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 21
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (subprocess.run) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 812. PY-ERR-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 22
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 813. PY-ERR-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 26
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 814. PY-SUBPROCESS-001

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 57
- **Risk:** MEDIUM
- **Message:** [Subprocess Without Timeout] subprocess.run() without timeout can hang indefinitely

**Suggestion:** Always set a timeout for subprocess operations

### 815. PY-ERR-001

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 39
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 816. PY-ERR-001

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 40
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 817. PY-ERR-001

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 47
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 818. PY-ERR-001

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 48
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 819. PY-ERR-001

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 57
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (subprocess.run) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 820. PY-QUAL-004

- **File:** `janitor\analyzer.py`
- **Line:** 7
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 821. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 86
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 822. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 90
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 823. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 91
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 824. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 98
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 825. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 99
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 826. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 126
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 827. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 127
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 828. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 139
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 829. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 146
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 830. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 152
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 831. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 156
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 832. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 158
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 833. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 160
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 834. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 162
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 835. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 167
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 836. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 175
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 837. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 175
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 838. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 183
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 839. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 184
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 840. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 185
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 841. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 189
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 842. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 198
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 843. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 200
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 844. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 201
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 845. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 202
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 846. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 204
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 847. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 205
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 848. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 207
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 849. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 208
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 850. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 208
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 851. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 210
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 852. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 215
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 853. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 216
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 854. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 217
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 855. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 218
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 856. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 219
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 857. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 222
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 858. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 232
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 859. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 233
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 860. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 234
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 861. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 236
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 862. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 237
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 863. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 238
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 864. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 239
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 865. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 240
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 866. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 241
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 867. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 267
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 868. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 268
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 869. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 269
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 870. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 270
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 871. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 272
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 872. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 273
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 873. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 274
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 874. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 275
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 875. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 276
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 876. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 285
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 877. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 286
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 878. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 287
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 879. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 289
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 880. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 290
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 881. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 294
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 882. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 295
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 883. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 296
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 884. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 297
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 885. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 298
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 886. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 301
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 887. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 315
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 888. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 317
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 889. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 318
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 890. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 319
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 891. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 389
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 892. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 407
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 893. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 451
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 894. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 452
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 895. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 453
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 896. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 454
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 897. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 463
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 898. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 467
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 899. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 471
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 900. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 472
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 901. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 495
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 902. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 498
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 903. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 504
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 904. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 505
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 905. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 506
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 906. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 507
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 907. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 512
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 908. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 513
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 909. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 514
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 910. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 516
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 911. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 518
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 912. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 519
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 913. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 523
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 914. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 524
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 915. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 530
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 916. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 537
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 917. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 540
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 918. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 547
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 919. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 548
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 920. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 551
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 921. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 552
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 922. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 555
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 923. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 556
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 924. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 603
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 925. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 610
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 926. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 616
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 927. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 624
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 928. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 637
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 929. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 638
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 930. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 639
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 931. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 652
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 932. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 658
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 933. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 664
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 934. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 665
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 935. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 672
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 936. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 678
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 937. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 685
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 938. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 698
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 939. PY-QUAL-004

- **File:** `janitor\core.py`
- **Line:** 11
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 940. PY-QUAL-004

- **File:** `janitor\core.py`
- **Line:** 12
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 941. PY-QUAL-004

- **File:** `janitor\core.py`
- **Line:** 15
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 942. PY-QUAL-004

- **File:** `janitor\core.py`
- **Line:** 16
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 943. PY-QUAL-004

- **File:** `janitor\core.py`
- **Line:** 18
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 944. PY-QUAL-004

- **File:** `janitor\core.py`
- **Line:** 20
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 945. PY-QUAL-004

- **File:** `janitor\core.py`
- **Line:** 21
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 946. PY-QUAL-004

- **File:** `janitor\core.py`
- **Line:** 22
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 947. PY-QUAL-004

- **File:** `janitor\core.py`
- **Line:** 23
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 948. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 63
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 949. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 94
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 950. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 120
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 951. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 129
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 952. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 154
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 953. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 228
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 954. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 231
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 955. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 246
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 956. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 264
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 957. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 267
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 958. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 282
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 959. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 303
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 960. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 306
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 961. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 309
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 962. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 327
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 963. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 339
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 964. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 352
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 965. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 365
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 966. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 369
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 967. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 382
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 968. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 395
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 969. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 404
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 970. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 413
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 971. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 434
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 972. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 443
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 973. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 451
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 974. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 456
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 975. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 471
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 976. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 473
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 977. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 483
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 978. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 499
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 979. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 511
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 980. PY-MAGIC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 525
- **Risk:** LOW
- **Message:** [Magic Number Used] Hardcoded numeric literals should be named constants

**Suggestion:** Define magic numbers as named constants with descriptive names

### 981. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 547
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 982. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 571
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 983. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 610
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 984. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 654
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 985. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 655
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 986. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 656
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 987. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 657
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 988. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 658
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 989. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 659
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 990. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 660
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 991. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 661
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 992. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 686
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 993. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 689
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 994. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 723
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 995. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 724
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 996. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 725
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 997. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 726
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 998. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 726
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 999. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 727
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1000. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 727
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1001. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 728
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1002. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 728
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1003. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 729
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1004. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 729
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1005. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 730
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1006. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 730
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1007. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 731
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1008. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 732
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1009. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 733
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1010. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 734
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1011. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 736
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1012. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 737
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1013. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 746
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1014. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 749
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1015. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 750
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1016. PY-QUAL-004

- **File:** `janitor\js_analyzer.py`
- **Line:** 36
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1017. PY-QUAL-004

- **File:** `janitor\js_analyzer.py`
- **Line:** 37
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1018. PY-QUAL-004

- **File:** `janitor\js_analyzer.py`
- **Line:** 38
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1019. PY-QUAL-004

- **File:** `janitor\js_analyzer.py`
- **Line:** 39
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1020. PY-QUAL-004

- **File:** `janitor\js_analyzer.py`
- **Line:** 45
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1021. PY-DOC-001

- **File:** `janitor\js_analyzer.py`
- **Line:** 48
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1022. PY-QUAL-004

- **File:** `janitor\js_analyzer.py`
- **Line:** 77
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1023. PY-QUAL-004

- **File:** `janitor\language_detector.py`
- **Line:** 13
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1024. PY-QUAL-004

- **File:** `janitor\language_detector.py`
- **Line:** 14
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1025. PY-QUAL-004

- **File:** `janitor\language_detector.py`
- **Line:** 28
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1026. PY-QUAL-004

- **File:** `janitor\language_detector.py`
- **Line:** 37
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1027. PY-QUAL-004

- **File:** `janitor\language_detector.py`
- **Line:** 43
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1028. PY-QUAL-004

- **File:** `janitor\language_detector.py`
- **Line:** 44
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1029. PY-QUAL-004

- **File:** `janitor\language_detector.py`
- **Line:** 58
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1030. PY-QUAL-004

- **File:** `janitor\language_detector.py`
- **Line:** 59
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1031. PY-QUAL-004

- **File:** `janitor\language_detector.py`
- **Line:** 67
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1032. PY-QUAL-004

- **File:** `janitor\language_detector.py`
- **Line:** 68
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1033. PY-QUAL-002

- **File:** `janitor\language_detector.py`
- **Line:** 111
- **Risk:** LOW
- **Message:** [Overly Broad Exception Catch] except Exception: catches too many error types, can hide bugs

**Suggestion:** Catch only specific exception types that you expect

### 1034. PY-QUAL-002

- **File:** `janitor\language_detector.py`
- **Line:** 159
- **Risk:** LOW
- **Message:** [Overly Broad Exception Catch] except Exception: catches too many error types, can hide bugs

**Suggestion:** Catch only specific exception types that you expect

### 1035. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 70
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1036. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 170
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1037. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 171
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1038. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 175
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1039. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 180
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1040. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 182
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1041. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 194
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1042. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 198
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1043. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 205
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1044. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 206
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1045. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 210
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1046. PY-DOC-001

- **File:** `janitor\llm.py`
- **Line:** 212
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1047. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 220
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1048. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 221
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1049. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 225
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1050. PY-DOC-001

- **File:** `janitor\llm.py`
- **Line:** 250
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1051. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 258
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1052. PY-DOC-001

- **File:** `janitor\llm.py`
- **Line:** 297
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1053. PY-DOC-001

- **File:** `janitor\manager.py`
- **Line:** 98
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1054. PY-DOC-001

- **File:** `janitor\manager.py`
- **Line:** 122
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1055. PY-DOC-001

- **File:** `janitor\manager.py`
- **Line:** 138
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1056. PY-QUAL-004

- **File:** `janitor\manager.py`
- **Line:** 189
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1057. PY-DOC-001

- **File:** `janitor\manager.py`
- **Line:** 256
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1058. PY-QUAL-004

- **File:** `janitor\scanner.py`
- **Line:** 12
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1059. PY-QUAL-004

- **File:** `janitor\scanner.py`
- **Line:** 13
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1060. PY-QUAL-004

- **File:** `janitor\analyzers\base.py`
- **Line:** 38
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1061. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 41
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1062. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 44
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1063. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 62
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1064. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 312
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1065. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 328
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1066. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 344
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1067. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 463
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1068. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 479
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1069. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 495
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1070. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 607
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1071. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 639
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1072. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 726
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1073. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 742
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1074. PY-MAGIC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 766
- **Risk:** LOW
- **Message:** [Magic Number Used] Hardcoded numeric literals should be named constants

**Suggestion:** Define magic numbers as named constants with descriptive names

### 1075. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 782
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1076. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 854
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1077. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 886
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1078. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 909
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1079. PY-COMM-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 944
- **Risk:** LOW
- **Message:** [TODO Comment in Code] TODO comments may indicate incomplete security work

**Suggestion:** Address TODO/FIXME items before production deployment

### 1080. PY-QUAL-005

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1045
- **Risk:** LOW
- **Message:** [Hardcoded localhost/127.0.0.1] Hardcoded localhost addresses may indicate test/debug code

**Suggestion:** Use environment variables or configuration for host addresses

### 1081. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1101
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1082. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1103
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1083. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1104
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1084. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1105
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1085. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1139
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1086. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1140
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1087. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1141
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1088. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1142
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1089. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1143
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1090. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1147
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1091. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1157
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1092. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1159
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1093. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1245
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1094. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1250
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1095. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1254
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1096. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1261
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1097. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1270
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1098. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1273
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1099. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1277
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1100. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1278
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1101. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1280
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1102. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1284
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1103. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1289
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1104. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1290
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1105. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1292
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1106. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1298
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1107. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1303
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1108. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1304
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1109. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1308
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1110. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1311
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1111. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1315
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1112. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1322
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1113. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1323
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1114. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1329
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1115. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1330
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1116. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1334
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1117. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1337
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1118. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1341
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1119. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1342
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1120. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1348
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1121. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1355
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1122. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1356
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1123. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1358
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1124. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1362
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1125. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1363
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1126. PY-QUAL-005

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1365
- **Risk:** LOW
- **Message:** [Hardcoded localhost/127.0.0.1] Hardcoded localhost addresses may indicate test/debug code

**Suggestion:** Use environment variables or configuration for host addresses

### 1127. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1369
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1128. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1376
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1129. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1381
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1130. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1384
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1131. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1388
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1132. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1391
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1133. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1395
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1134. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1396
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1135. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1398
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1136. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1404
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1137. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1407
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1138. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1411
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1139. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1412
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1140. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1416
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1141. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1417
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1142. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1421
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1143. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1434
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1144. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1441
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1145. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 41
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1146. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 44
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1147. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 62
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1148. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 216
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1149. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 232
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1150. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 283
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1151. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 335
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1152. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 351
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1153. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 383
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1154. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 399
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1155. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 431
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1156. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 534
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1157. PY-MAGIC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 542
- **Risk:** LOW
- **Message:** [Magic Number Used] Hardcoded numeric literals should be named constants

**Suggestion:** Define magic numbers as named constants with descriptive names

### 1158. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 582
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1159. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 598
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1160. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 614
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1161. PY-MAGIC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 654
- **Risk:** LOW
- **Message:** [Magic Number Used] Hardcoded numeric literals should be named constants

**Suggestion:** Define magic numbers as named constants with descriptive names

### 1162. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 669
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1163. PY-COMM-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 704
- **Risk:** LOW
- **Message:** [TODO Comment in Code] TODO comments may indicate incomplete security work

**Suggestion:** Address TODO/FIXME items before production deployment

### 1164. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 825
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1165. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 827
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1166. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 828
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1167. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 829
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1168. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 925
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1169. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 932
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1170. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 939
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1171. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 944
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1172. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 947
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1173. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 951
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1174. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 952
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1175. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 956
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1176. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 957
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1177. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 963
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1178. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 964
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1179. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 968
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1180. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 973
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1181. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 978
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1182. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 985
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1183. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 986
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1184. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 992
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1185. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 993
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1186. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 997
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1187. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 998
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1188. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1002
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1189. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1009
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1190. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 1010
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1191. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1014
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1192. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1021
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1193. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1028
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1194. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 1029
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1195. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1033
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1196. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1038
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1197. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1045
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1198. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1050
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1199. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1059
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1200. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1064
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1201. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1069
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1202. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 1070
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1203. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1074
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1204. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1086
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1205. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1093
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1206. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 41
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1207. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 44
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1208. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 62
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1209. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 312
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1210. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 328
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1211. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 511
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1212. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 527
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1213. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 543
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1214. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 559
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1215. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 575
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1216. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 703
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1217. PY-MAGIC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 727
- **Risk:** LOW
- **Message:** [Magic Number Used] Hardcoded numeric literals should be named constants

**Suggestion:** Define magic numbers as named constants with descriptive names

### 1218. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 790
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1219. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 806
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1220. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 822
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1221. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 886
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1222. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 950
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1223. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 966
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1224. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1005
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1225. PY-COMM-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1040
- **Risk:** LOW
- **Message:** [TODO Comment in Code] TODO comments may indicate incomplete security work

**Suggestion:** Address TODO/FIXME items before production deployment

### 1226. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1191
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1227. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1217
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1228. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1219
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1229. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1220
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1230. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1221
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1231. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1254
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1232. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1255
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1233. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1257
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1234. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1258
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1235. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1261
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1236. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1262
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1237. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1263
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1238. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1265
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1239. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1269
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1240. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1273
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1241. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1274
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1242. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1276
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1243. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1340
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1244. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1363
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1245. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1366
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1246. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1370
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1247. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1377
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1248. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1378
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1249. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1384
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1250. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1391
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1251. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1394
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1252. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1396
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1253. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1400
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1254. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1401
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1255. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1403
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1256. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1405
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1257. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1409
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1258. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1410
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1259. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1412
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1260. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1416
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1261. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1421
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1262. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1424
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1263. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1428
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1264. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1429
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1265. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1435
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1266. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1436
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1267. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1444
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1268. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1445
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1269. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1447
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1270. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1451
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1271. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1454
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1272. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1458
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1273. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1465
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1274. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1466
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1275. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1472
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1276. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1473
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1277. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1475
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1278. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1481
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1279. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1484
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1280. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1492
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1281. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1497
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1282. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1502
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1283. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1509
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1284. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1510
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1285. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1514
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1286. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1515
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1287. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1519
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1288. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1524
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1289. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1529
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1290. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1536
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1291. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1541
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1292. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1542
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1293. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1546
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1294. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1547
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1295. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1549
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1296. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1553
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1297. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1554
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1298. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1562
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1299. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1563
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1300. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1569
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1301. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1576
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1302. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1577
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1303. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1581
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1304. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1586
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1305. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1587
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1306. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1593
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1307. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1606
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1308. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1615
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1309. PY-DOC-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 41
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1310. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 42
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1311. PY-DOC-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 44
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1312. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 62
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1313. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 256
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1314. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 360
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1315. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 383
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1316. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 399
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1317. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 415
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1318. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 447
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1319. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 598
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1320. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 678
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1321. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 686
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1322. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 733
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1323. PY-COMM-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 768
- **Risk:** LOW
- **Message:** [TODO Comment in Code] TODO comments may indicate incomplete security work

**Suggestion:** Address TODO/FIXME items before production deployment

### 1324. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 853
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1325. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 911
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1326. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 913
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1327. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 914
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1328. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 915
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1329. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 930
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1330. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 931
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1331. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 943
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1332. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 1078
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1333. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 1086
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1334. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 1092
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1335. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 1098
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1336. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 1106
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1337. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 1126
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1338. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 1146
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1339. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 1152
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1340. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 1188
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1341. PY-DOC-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 42
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1342. PY-DOC-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 45
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1343. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 62
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1344. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 329
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1345. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 344
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1346. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 359
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1347. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 374
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1348. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 389
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1349. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 411
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1350. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 426
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1351. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 441
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1352. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 456
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1353. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 612
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1354. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 627
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1355. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 642
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1356. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 657
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1357. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 746
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1358. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 761
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1359. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 783
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1360. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 798
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1361. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 820
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1362. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 842
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1363. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 864
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1364. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 908
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1365. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 952
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1366. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1038
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1367. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1069
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1368. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1071
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1369. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1072
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1370. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1073
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1371. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1101
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1372. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1104
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1373. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1106
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1374. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1107
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1375. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1109
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1376. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1110
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1377. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1191
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1378. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1216
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1379. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1220
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1380. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1224
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1381. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1252
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1382. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1262
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1383. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1270
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1384. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1280
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1385. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1308
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1386. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1332
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1387. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1344
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1388. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1350
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1389. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1356
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1390. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1362
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1391. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1368
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1392. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1380
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1393. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1386
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1394. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1392
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1395. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1398
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1396. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1404
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1397. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1410
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1398. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1430
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1399. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1436
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1400. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1448
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1401. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 41
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1402. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 44
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1403. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 62
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1404. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 232
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1405. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 240
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1406. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 383
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1407. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 399
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1408. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 415
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1409. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 479
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1410. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 487
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1411. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 511
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1412. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 551
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1413. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 567
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1414. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 582
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1415. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 598
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1416. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 622
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1417. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 742
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1418. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 774
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1419. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 782
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1420. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 797
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1421. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 821
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1422. PY-COMM-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 832
- **Risk:** LOW
- **Message:** [TODO Comment in Code] TODO comments may indicate incomplete security work

**Suggestion:** Address TODO/FIXME items before production deployment

### 1423. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 939
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1424. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 973
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1425. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 975
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1426. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 976
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1427. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 977
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1428. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 993
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1429. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 994
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1430. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 996
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1431. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1000
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1432. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1001
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1433. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1007
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1434. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1010
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1435. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1019
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1436. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1112
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1437. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1119
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1438. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1126
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1439. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1127
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1440. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1133
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1441. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1134
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1442. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1136
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1443. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1140
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1444. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1147
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1445. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1154
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1446. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1155
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1447. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1157
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1448. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1159
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1449. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1163
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1450. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1164
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1451. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1170
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1452. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1171
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1453. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1179
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1454. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1180
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1455. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1182
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1456. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1186
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1457. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1187
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1458. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1195
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1459. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1200
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1460. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1204
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1461. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1205
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1462. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1211
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1463. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1214
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1464. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1220
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1465. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1221
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1466. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1225
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1467. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1226
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1468. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1228
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1469. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1232
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1470. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1235
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1471. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1239
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1472. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1242
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1473. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1246
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1474. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1247
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1475. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1253
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1476. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1254
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1477. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1256
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1478. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1260
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1479. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1261
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1480. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1265
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1481. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1266
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1482. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1270
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1483. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1271
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1484. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1275
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1485. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1279
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1486. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1280
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1487. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1284
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1488. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1293
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1489. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1306
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1490. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1313
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1491. PY-DOC-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 42
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1492. PY-DOC-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 45
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1493. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 83
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1494. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 306
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1495. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 322
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1496. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 338
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1497. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 442
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1498. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 458
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1499. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 482
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1500. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 490
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1501. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 498
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1502. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 506
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1503. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 521
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1504. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 537
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1505. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 545
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1506. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 553
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1507. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 569
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1508. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 585
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1509. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 713
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1510. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 729
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1511. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 745
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1512. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 784
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1513. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 816
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1514. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 880
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1515. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 912
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1516. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 928
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1517. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 952
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1518. PY-LOG-002

- **File:** `janitor\analyzers\python.py`
- **Line:** 966
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1519. PY-LOG-002

- **File:** `janitor\analyzers\python.py`
- **Line:** 969
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1520. PY-LOG-002

- **File:** `janitor\analyzers\python.py`
- **Line:** 972
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1521. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 983
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1522. PY-COMM-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1018
- **Risk:** LOW
- **Message:** [TODO Comment in Code] TODO comments may indicate incomplete security work

**Suggestion:** Address TODO/FIXME items before production deployment

### 1523. PY-COMM-002

- **File:** `janitor\analyzers\python.py`
- **Line:** 1034
- **Risk:** LOW
- **Message:** [HACK Comment in Code] HACK/XXX comments indicate potentially unsafe workarounds

**Suggestion:** Address HACK/XXX items before production deployment

### 1524. PY-QUAL-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1049
- **Risk:** LOW
- **Message:** [Bare Except Clause] bare except: catches all exceptions including SystemExit, KeyboardInterrupt

**Suggestion:** Catch specific exceptions (except ValueError:, except OSError:)

### 1525. PY-QUAL-002

- **File:** `janitor\analyzers\python.py`
- **Line:** 1065
- **Risk:** LOW
- **Message:** [Overly Broad Exception Catch] except Exception: catches too many error types, can hide bugs

**Suggestion:** Catch only specific exception types that you expect

### 1526. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1103
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1527. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1141
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1528. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1183
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1529. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1185
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1530. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1186
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1531. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1187
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1532. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1214
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1533. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1349
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1534. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1357
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1535. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1363
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1536. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1379
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1537. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1385
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1538. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1407
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1539. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1419
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1540. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1431
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1541. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1437
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1542. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1443
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1543. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1479
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1544. PY-DOC-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 40
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1545. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 41
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1546. PY-DOC-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 43
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1547. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 61
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1548. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 255
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1549. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 375
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1550. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 415
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1551. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 423
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1552. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 446
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1553. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 462
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1554. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 478
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1555. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 494
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1556. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 526
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1557. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 582
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1558. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 741
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1559. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 869
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1560. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 877
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1561. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 885
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1562. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 924
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1563. PY-COMM-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 959
- **Risk:** LOW
- **Message:** [TODO Comment in Code] TODO comments may indicate incomplete security work

**Suggestion:** Address TODO/FIXME items before production deployment

### 1564. PY-COMM-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 964
- **Risk:** LOW
- **Message:** [TODO Comment in Code] TODO comments may indicate incomplete security work

**Suggestion:** Address TODO/FIXME items before production deployment

### 1565. PY-COMM-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 980
- **Risk:** LOW
- **Message:** [TODO Comment in Code] TODO comments may indicate incomplete security work

**Suggestion:** Address TODO/FIXME items before production deployment

### 1566. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1028
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1567. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1106
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1568. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1108
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1569. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1109
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1570. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1110
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1571. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1138
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1572. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1287
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1573. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1303
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1574. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1351
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1575. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1357
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1576. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1382
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1577. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1390
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1578. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1396
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1579. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1402
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1580. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1408
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1581. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1440
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1582. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1456
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1583. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1462
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1584. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1470
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1585. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1472
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1586. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1478
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1587. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1496
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1588. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1520
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1589. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1538
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1590. PY-QUAL-005

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1571
- **Risk:** LOW
- **Message:** [Hardcoded localhost/127.0.0.1] Hardcoded localhost addresses may indicate test/debug code

**Suggestion:** Use environment variables or configuration for host addresses

### 1591. PY-QUAL-004

- **File:** `janitor\analyzers\__init__.py`
- **Line:** 47
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1592. PY-QUAL-004

- **File:** `janitor\analyzers\__init__.py`
- **Line:** 48
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1593. PY-QUAL-004

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 8
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1594. PY-DOC-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 11
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1595. PY-DOC-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 16
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1596. PY-DOC-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 20
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1597. PY-DOC-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 25
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1598. PY-DOC-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 30
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1599. PY-LOG-002

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 40
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1600. PY-LOG-002

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 48
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1601. PY-LOG-002

- **File:** `janitor\tests\test_manager.py`
- **Line:** 25
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1602. PY-QUAL-004

- **File:** `janitor\tests\test_scanner.py`
- **Line:** 58
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1603. PY-QUAL-004

- **File:** `janitor\tests\test_scanner.py`
- **Line:** 67
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1604. PY-QUAL-004

- **File:** `janitor\tests\test_scanner.py`
- **Line:** 98
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1605. PY-QUAL-004

- **File:** `janitor\tests\test_scanner.py`
- **Line:** 107
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

## RECOMMENDATIONS

1. Review all CRITICAL and HIGH severity issues immediately
2. Implement suggested fixes for security vulnerabilities
3. Add comprehensive test coverage
4. Consider using a secrets management solution
5. Enable pre-commit hooks for security scanning

## BACKUPS

Backups created in: backups
