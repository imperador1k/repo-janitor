# SECURITY AUDIT REPORT

**Generated:** 2026-05-21T21:07:00.234524
**Repository:** C:\Users\User\Documents\PRECIOSO\coding\GitHub\teste
**Mode:** DRY-RUN

## LANGUAGE DISTRIBUTION

- **Python:** 57.4%
- **Markdown:** 42.3%
- **TOML:** 0.2%
- **JavaScript:** 0.1%
- **TypeScript:** 0.1%

## SUMMARY

- **Total Issues:** 2064
- **Critical:** 827
- **High:** 78
- **Medium:** 172
- **Low:** 987

## FINDINGS

### 1. PY-PATH-001

- **File:** `janitor\cli.py`
- **Line:** 345
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 2. PY-PATH-001

- **File:** `janitor\cli.py`
- **Line:** 366
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

### 20. PY-PATH-001

- **File:** `janitor\language_detector.py`
- **Line:** 157
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 21. PY-PATH-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 52
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 22. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 91
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 23. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 107
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 24. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 123
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 25. PY-SQL-003

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 128
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 26. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 139
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 27. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 155
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 28. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 171
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 29. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 187
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 30. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 203
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 31. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 219
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 32. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 235
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 33. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 251
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 34. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 267
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 35. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 283
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 36. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 299
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 37. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 315
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 38. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 331
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 39. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 347
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 40. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 363
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 41. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 379
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 42. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 395
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 43. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 411
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 44. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 427
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 45. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 443
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 46. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 466
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 47. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 482
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 48. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 498
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 49. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 514
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 50. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 530
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 51. PY-SQL-003

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 545
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 52. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 546
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 53. PY-SQL-003

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 551
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 54. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 562
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 55. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 578
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 56. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 594
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 57. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 610
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 58. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 626
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 59. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 642
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 60. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 658
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 61. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 674
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 62. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 690
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 63. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 706
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 64. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 729
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 65. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 745
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 66. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 761
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 67. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 777
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 68. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 793
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 69. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 809
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 70. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 825
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 71. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 841
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 72. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 857
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 73. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 873
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 74. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 889
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 75. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 912
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 76. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 928
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 77. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 944
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 78. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 960
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 79. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 976
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 80. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 992
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 81. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1008
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 82. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1024
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 83. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1040
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 84. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1209
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 85. PY-SQL-003

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1222
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 86. PY-COMPILE-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1231
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 87. PY-SQL-003

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1235
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 88. PY-COMPILE-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 39
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 89. PY-COMPILE-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 85
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 90. PY-COMPILE-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 86
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 91. PY-COMPILE-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 87
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 92. PY-COMPILE-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 88
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 93. PY-COMPILE-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 89
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 94. PY-COMPILE-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 90
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 95. PY-COMPILE-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 91
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 96. PY-COMPILE-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 92
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 97. PY-COMPILE-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 93
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 98. PY-COMPILE-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 94
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 99. PY-COMPILE-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 95
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 100. PY-COMPILE-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 96
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 101. PY-COMPILE-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 97
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 102. PY-COMPILE-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 98
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 103. PY-COMPILE-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 99
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 104. PY-COMPILE-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 100
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 105. PY-COMPILE-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 101
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 106. PY-COMPILE-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 102
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 107. PY-COMPILE-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 103
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 108. PY-COMPILE-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 104
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 109. PY-PATH-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 420
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 110. PY-PATH-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 540
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 111. PY-PATH-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 908
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 112. PY-PATH-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 53
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 113. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 213
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 114. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 228
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 115. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 243
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 116. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 258
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 117. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 273
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 118. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 288
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 119. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 303
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 120. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 318
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 121. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 333
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 122. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 348
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 123. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 363
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 124. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 378
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 125. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 393
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 126. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 408
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 127. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 423
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 128. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 438
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 129. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 453
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 130. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 468
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 131. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 483
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 132. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 498
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 133. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 513
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 134. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 528
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 135. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 543
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 136. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 558
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 137. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 573
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 138. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 588
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 139. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 603
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 140. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 618
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 141. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 633
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 142. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 648
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 143. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 663
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 144. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 678
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 145. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 693
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 146. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 708
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 147. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 723
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 148. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 738
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 149. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 753
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 150. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 768
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 151. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 783
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 152. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 798
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 153. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 813
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 154. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 828
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 155. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 843
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 156. PY-COMPILE-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 858
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 157. PY-PATH-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 52
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 158. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 91
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 159. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 107
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 160. PY-SQL-003

- **File:** `janitor\analyzers\go.py`
- **Line:** 122
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 161. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 123
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 162. PY-SQL-003

- **File:** `janitor\analyzers\go.py`
- **Line:** 128
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 163. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 139
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 164. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 155
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 165. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 171
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 166. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 187
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 167. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 203
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 168. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 219
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 169. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 235
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 170. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 251
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 171. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 267
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 172. PY-SSTI-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 279
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 173. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 283
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 174. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 299
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 175. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 315
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 176. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 338
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 177. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 354
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 178. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 370
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 179. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 386
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 180. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 402
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 181. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 418
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 182. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 434
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 183. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 450
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 184. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 466
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 185. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 482
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 186. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 498
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 187. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 514
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 188. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 537
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 189. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 553
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 190. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 569
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 191. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 585
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 192. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 601
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 193. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 617
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 194. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 633
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 195. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 649
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 196. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 672
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 197. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 688
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 198. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 704
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 199. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 720
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 200. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 736
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 201. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 752
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 202. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 768
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 203. PY-COMPILE-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 911
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 204. PY-SSTI-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 963
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 205. PY-PATH-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 52
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 206. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 91
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 207. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 107
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 208. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 123
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 209. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 139
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 210. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 155
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 211. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 171
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 212. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 187
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 213. PY-EXEC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 199
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 214. PY-EXEC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 202
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 215. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 203
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 216. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 219
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 217. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 235
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 218. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 251
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 219. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 267
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 220. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 283
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 221. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 299
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 222. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 315
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 223. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 331
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 224. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 347
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 225. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 363
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 226. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 379
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 227. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 395
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 228. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 411
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 229. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 427
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 230. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 443
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 231. PY-SSTI-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 448
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 232. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 459
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 233. PY-SSTI-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 464
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 234. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 475
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 235. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 491
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 236. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 514
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 237. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 530
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 238. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 546
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 239. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 562
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 240. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 578
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 241. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 594
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 242. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 610
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 243. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 626
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 244. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 642
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 245. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 658
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 246. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 674
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 247. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 690
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 248. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 706
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 249. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 722
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 250. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 738
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 251. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 754
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 252. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 770
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 253. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 793
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 254. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 809
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 255. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 825
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 256. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 841
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 257. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 857
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 258. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 873
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 259. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 889
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 260. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 905
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 261. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 921
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 262. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 937
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 263. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 953
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 264. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 969
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 265. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 985
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 266. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1008
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 267. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1024
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 268. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1040
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 269. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1056
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 270. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1072
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 271. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1088
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 272. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1104
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 273. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1120
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 274. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1136
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 275. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1152
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 276. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1327
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 277. PY-COMPILE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1349
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 278. PY-PATH-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 52
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 279. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 91
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 280. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 107
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 281. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 123
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 282. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 139
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 283. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 155
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 284. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 171
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 285. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 187
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 286. PY-EVAL-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 199
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 287. PY-EVAL-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 202
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 288. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 203
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 289. PY-EVAL-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 208
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 290. PY-EVAL-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 209
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 291. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 219
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 292. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 235
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 293. PY-EXEC-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 250
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 294. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 251
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 295. PY-EXEC-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 257
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 296. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 267
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 297. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 283
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 298. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 299
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 299. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 315
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 300. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 331
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 301. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 347
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 302. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 363
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 303. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 386
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 304. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 402
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 305. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 418
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 306. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 434
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 307. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 450
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 308. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 466
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 309. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 482
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 310. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 498
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 311. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 514
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 312. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 530
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 313. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 546
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 314. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 569
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 315. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 585
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 316. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 601
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 317. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 617
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 318. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 633
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 319. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 649
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 320. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 665
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 321. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 681
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 322. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 697
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 323. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 720
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 324. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 736
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 325. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 752
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 326. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 768
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 327. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 784
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 328. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 800
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 329. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 816
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 330. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 832
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 331. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 848
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 332. PY-EVAL-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 945
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 333. PY-EXEC-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 947
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 334. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 989
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 335. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 990
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 336. PY-COMPILE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 1002
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 337. PY-PATH-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 53
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 338. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 94
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 339. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 109
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 340. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 124
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 341. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 139
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 342. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 154
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 343. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 169
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 344. PY-EXEC-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 190
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 345. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 191
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 346. PY-EXEC-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 197
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 347. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 206
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 348. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 221
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 349. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 243
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 350. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 258
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 351. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 280
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 352. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 295
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 353. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 310
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 354. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 332
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 355. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 347
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 356. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 362
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 357. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 377
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 358. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 392
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 359. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 414
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 360. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 429
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 361. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 444
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 362. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 459
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 363. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 481
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 364. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 496
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 365. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 511
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 366. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 526
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 367. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 548
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 368. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 563
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 369. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 578
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 370. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 593
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 371. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 615
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 372. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 630
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 373. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 645
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 374. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 660
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 375. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 682
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 376. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 697
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 377. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 712
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 378. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 727
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 379. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 749
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 380. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 764
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 381. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 786
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 382. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 801
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 383. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 823
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 384. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 845
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 385. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 867
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 386. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 889
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 387. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 911
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 388. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 933
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 389. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 955
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 390. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 977
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 391. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 992
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 392. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1164
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 393. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1165
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 394. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1178
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 395. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1205
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 396. PY-COMPILE-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1234
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 397. PY-PATH-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 52
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 398. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 91
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 399. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 107
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 400. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 123
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 401. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 139
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 402. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 155
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 403. PY-EXEC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 160
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 404. PY-EXEC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 161
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 405. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 171
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 406. PY-EVAL-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 183
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 407. PY-EVAL-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 186
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 408. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 187
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 409. PY-EVAL-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 189
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 410. PY-EVAL-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 193
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 411. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 203
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 412. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 219
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 413. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 235
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 414. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 251
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 415. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 267
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 416. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 283
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 417. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 299
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 418. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 315
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 419. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 331
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 420. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 354
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 421. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 370
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 422. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 386
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 423. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 402
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 424. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 418
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 425. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 434
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 426. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 450
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 427. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 466
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 428. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 482
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 429. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 498
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 430. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 514
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 431. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 530
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 432. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 546
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 433. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 562
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 434. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 585
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 435. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 601
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 436. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 617
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 437. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 633
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 438. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 649
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 439. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 665
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 440. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 681
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 441. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 697
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 442. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 713
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 443. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 729
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 444. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 745
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 445. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 761
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 446. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 777
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 447. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 800
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 448. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 816
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 449. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 832
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 450. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 848
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 451. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 864
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 452. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 880
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 453. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 896
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 454. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 912
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 455. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1074
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 456. PY-COMPILE-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1098
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 457. PY-PATH-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 53
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 458. PY-EVAL-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 129
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 459. PY-EVAL-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 132
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 460. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 133
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 461. PY-EVAL-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 139
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 462. PY-EXEC-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 145
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 463. PY-EXEC-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 148
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 464. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 149
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 465. PY-EXEC-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 154
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 466. PY-EXEC-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 155
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 467. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 161
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 468. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 164
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 469. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 165
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 470. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 167
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 471. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 170
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 472. PY-EXEC-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 171
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 473. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 171
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 474. PY-CMD-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 180
- **Risk:** CRITICAL
- **Message:** [Command Injection via os.system] os.system() passes strings to shell, enabling command injection

**Suggestion:** Use subprocess.run with a list of arguments (shell=False)

### 475. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 181
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 476. PY-CMD-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 187
- **Risk:** CRITICAL
- **Message:** [Command Injection via os.system] os.system() passes strings to shell, enabling command injection

**Suggestion:** Use subprocess.run with a list of arguments (shell=False)

### 477. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 197
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 478. PY-CMD-003

- **File:** `janitor\analyzers\python.py`
- **Line:** 212
- **Risk:** CRITICAL
- **Message:** [Command Injection via os.popen] os.popen() executes commands via shell, enabling injection

**Suggestion:** Use subprocess.run with argument list (shell=False)

### 479. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 213
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 480. PY-CMD-003

- **File:** `janitor\analyzers\python.py`
- **Line:** 219
- **Risk:** CRITICAL
- **Message:** [Command Injection via os.popen] os.popen() executes commands via shell, enabling injection

**Suggestion:** Use subprocess.run with argument list (shell=False)

### 481. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 229
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 482. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 245
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 483. PY-SQL-003

- **File:** `janitor\analyzers\python.py`
- **Line:** 254
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 484. PY-SQL-003

- **File:** `janitor\analyzers\python.py`
- **Line:** 260
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 485. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 261
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 486. PY-SQL-003

- **File:** `janitor\analyzers\python.py`
- **Line:** 261
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 487. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 277
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 488. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 293
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 489. PY-DESER-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 308
- **Risk:** CRITICAL
- **Message:** [Unsafe Deserialization via pickle] pickle.loads() can execute arbitrary Python code during deserialization

**Suggestion:** Use json, msgpack, or yaml.safe_load() instead of pickle

### 490. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 309
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 491. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 325
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 492. PY-DESER-003

- **File:** `janitor\analyzers\python.py`
- **Line:** 340
- **Risk:** CRITICAL
- **Message:** [Unsafe Deserialization via jsonpickle] jsonpickle.decode() can reconstruct arbitrary Python objects

**Suggestion:** Use plain json.loads() instead of jsonpickle for untrusted data

### 493. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 341
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 494. PY-SSTI-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 350
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 495. PY-SSTI-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 353
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 496. PY-SSTI-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 356
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 497. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 357
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 498. PY-SSTI-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 357
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 499. PY-SSTI-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 363
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 500. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 373
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 501. PY-SSTI-002

- **File:** `janitor\analyzers\python.py`
- **Line:** 373
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Mako)] Mako templates from user strings can enable SSTI and RCE

**Suggestion:** Use the Mako template lookup with file-based templates, not from_string

### 502. PY-SSTI-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 375
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 503. PY-XSS-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 385
- **Risk:** CRITICAL
- **Message:** [XSS via Django mark_safe or |safe filter] mark_safe() or the |safe template filter disables HTML escaping

**Suggestion:** Avoid marking user input as safe. Use format_html() instead

### 504. PY-XSS-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 388
- **Risk:** CRITICAL
- **Message:** [XSS via Django mark_safe or |safe filter] mark_safe() or the |safe template filter disables HTML escaping

**Suggestion:** Avoid marking user input as safe. Use format_html() instead

### 505. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 389
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 506. PY-XSS-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 395
- **Risk:** CRITICAL
- **Message:** [XSS via Django mark_safe or |safe filter] mark_safe() or the |safe template filter disables HTML escaping

**Suggestion:** Avoid marking user input as safe. Use format_html() instead

### 507. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 405
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 508. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 421
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 509. PY-SSTI-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 426
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 510. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 437
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 511. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 453
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 512. PY-SSRF-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 468
- **Risk:** CRITICAL
- **Message:** [Server-Side Request Forgery (SSRF)] requests.get() with user-controlled URL can target internal services

**Suggestion:** Validate URL against an allowlist. Block private IP ranges

### 513. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 469
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 514. PY-SSRF-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 475
- **Risk:** CRITICAL
- **Message:** [Server-Side Request Forgery (SSRF)] requests.get() with user-controlled URL can target internal services

**Suggestion:** Validate URL against an allowlist. Block private IP ranges

### 515. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 485
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 516. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 501
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 517. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 524
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 518. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 540
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 519. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 556
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 520. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 572
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 521. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 588
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 522. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 604
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 523. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 620
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 524. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 636
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 525. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 652
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 526. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 668
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 527. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 684
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 528. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 700
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 529. PY-PATH-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 705
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 530. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 716
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 531. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 732
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 532. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 748
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 533. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 764
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 534. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 787
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 535. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 803
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 536. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 819
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 537. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 835
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 538. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 851
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 539. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 867
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 540. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 883
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 541. PY-SSRF-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 888
- **Risk:** CRITICAL
- **Message:** [Server-Side Request Forgery (SSRF)] requests.get() with user-controlled URL can target internal services

**Suggestion:** Validate URL against an allowlist. Block private IP ranges

### 542. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 899
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 543. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 915
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 544. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 931
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 545. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 947
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 546. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 970
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 547. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 986
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 548. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1002
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 549. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1018
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 550. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1034
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 551. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1050
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 552. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1066
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 553. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1082
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 554. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1098
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 555. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1114
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 556. PY-SSTI-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1143
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 557. PY-SSTI-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1144
- **Risk:** CRITICAL
- **Message:** [Server-Side Template Injection (Jinja2)] Passing user input to Jinja2 rendering from string can enable SSTI

**Suggestion:** Never render templates from user-controlled strings. Use template files with context variables

### 558. PY-EVAL-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1216
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 559. PY-EXEC-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1217
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 560. PY-SQL-003

- **File:** `janitor\analyzers\python.py`
- **Line:** 1219
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 561. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1265
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 562. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1266
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 563. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1278
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 564. PY-EVAL-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1290
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 565. PY-EXEC-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1290
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 566. PY-COMPILE-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1307
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 567. PY-PATH-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 56
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 568. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 237
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 569. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 252
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 570. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 267
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 571. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 282
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 572. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 297
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 573. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 312
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 574. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 327
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 575. PY-EVAL-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 332
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 576. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 342
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 577. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 364
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 578. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 379
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 579. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 394
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 580. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 409
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 581. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 431
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 582. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 446
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 583. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 461
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 584. PY-EVAL-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 479
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 585. PY-EVAL-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 482
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 586. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 483
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 587. PY-EVAL-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 488
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 588. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 498
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 589. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 513
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 590. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 535
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 591. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 550
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 592. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 565
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 593. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 587
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 594. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 602
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 595. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 624
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 596. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 639
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 597. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 661
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 598. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 676
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 599. PY-SQL-003

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 681
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 600. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 691
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 601. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 713
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 602. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 728
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 603. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 743
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 604. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 758
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 605. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 780
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 606. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 795
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 607. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 810
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 608. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 832
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 609. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 847
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 610. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 869
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 611. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 884
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 612. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 906
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 613. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 921
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 614. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 936
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 615. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 951
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 616. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 966
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 617. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 981
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 618. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 996
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 619. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 1011
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 620. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 1026
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 621. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 1041
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 622. PY-COMPILE-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 1056
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 623. PY-PATH-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 53
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 624. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 234
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 625. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 249
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 626. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 264
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 627. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 279
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 628. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 294
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 629. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 309
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 630. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 324
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 631. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 339
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 632. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 361
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 633. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 376
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 634. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 391
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 635. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 406
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 636. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 421
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 637. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 443
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 638. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 458
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 639. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 473
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 640. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 495
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 641. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 510
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 642. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 525
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 643. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 547
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 644. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 562
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 645. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 584
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 646. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 599
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 647. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 621
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 648. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 643
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 649. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 658
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 650. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 673
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 651. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 695
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 652. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 710
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 653. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 725
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 654. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 740
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 655. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 762
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 656. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 777
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 657. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 792
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 658. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 807
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 659. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 829
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 660. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 844
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 661. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 859
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 662. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 881
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 663. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 896
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 664. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 911
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 665. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 933
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 666. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 948
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 667. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 963
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 668. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 978
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 669. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 993
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 670. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 1008
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 671. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 1023
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 672. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 1038
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 673. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 1053
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 674. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 1068
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 675. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 1083
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 676. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 1105
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 677. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 1120
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 678. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 1135
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 679. PY-COMPILE-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 1150
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 680. PY-PATH-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 53
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 681. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 204
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 682. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 219
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 683. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 234
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 684. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 249
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 685. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 264
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 686. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 279
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 687. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 294
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 688. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 309
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 689. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 324
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 690. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 339
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 691. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 354
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 692. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 369
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 693. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 384
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 694. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 399
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 695. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 414
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 696. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 429
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 697. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 444
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 698. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 459
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 699. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 474
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 700. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 489
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 701. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 504
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 702. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 519
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 703. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 534
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 704. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 549
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 705. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 564
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 706. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 579
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 707. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 594
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 708. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 609
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 709. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 624
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 710. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 639
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 711. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 654
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 712. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 669
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 713. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 684
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 714. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 699
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 715. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 714
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 716. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 729
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 717. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 744
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 718. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 759
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 719. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 774
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 720. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 789
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 721. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 804
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 722. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 819
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 723. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 834
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 724. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 849
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 725. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 864
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 726. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 879
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 727. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 894
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 728. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 909
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 729. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 924
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 730. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 939
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 731. PY-COMPILE-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 954
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 732. PY-PATH-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 51
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 733. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 93
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 734. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 109
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 735. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 125
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 736. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 141
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 737. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 157
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 738. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 173
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 739. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 189
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 740. PY-EVAL-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 201
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 741. PY-EVAL-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 204
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 742. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 205
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 743. PY-EVAL-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 210
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 744. PY-EVAL-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 211
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 745. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 221
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 746. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 237
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 747. PY-EXEC-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 252
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 748. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 253
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 749. PY-EXEC-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 259
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 750. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 269
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 751. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 285
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 752. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 301
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 753. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 317
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 754. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 333
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 755. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 349
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 756. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 365
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 757. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 381
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 758. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 397
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 759. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 413
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 760. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 429
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 761. PY-EVAL-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 434
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 762. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 452
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 763. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 468
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 764. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 484
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 765. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 500
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 766. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 516
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 767. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 532
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 768. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 548
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 769. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 564
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 770. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 580
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 771. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 596
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 772. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 612
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 773. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 628
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 774. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 644
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 775. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 660
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 776. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 676
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 777. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 699
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 778. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 715
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 779. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 731
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 780. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 747
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 781. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 763
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 782. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 779
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 783. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 795
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 784. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 811
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 785. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 827
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 786. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 843
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 787. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 859
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 788. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 875
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 789. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 891
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 790. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 914
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 791. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 930
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 792. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 946
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 793. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 962
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 794. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 978
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 795. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 994
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 796. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1010
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 797. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1026
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 798. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1042
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 799. PY-EVAL-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1143
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 800. PY-EXEC-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1145
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 801. PY-SQL-003

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1149
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 802. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1193
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 803. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1194
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 804. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1206
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 805. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1232
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 806. PY-COMPILE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1262
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 807. PY-SQL-003

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1358
- **Risk:** CRITICAL
- **Message:** [SQL Injection via Django RawSQL] Django RawSQL or raw() with string formatting allows SQL injection

**Suggestion:** Use Django ORM query parameters instead of string formatting

### 808. PY-COMPILE-001

- **File:** `janitor\legacy\js_analyzer.py`
- **Line:** 49
- **Risk:** CRITICAL
- **Message:** [Code Injection via compile()] compile() with user input enables arbitrary code execution via exec/eval

**Suggestion:** Avoid compile() with untrusted input. Use safer alternatives

### 809. PY-PATH-001

- **File:** `janitor\legacy\js_analyzer.py`
- **Line:** 56
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 810. PY-PATH-001

- **File:** `janitor\legacy\manager.py`
- **Line:** 79
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 811. PY-PATH-001

- **File:** `janitor\legacy\manager.py`
- **Line:** 223
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 812. PY-PATH-001

- **File:** `janitor\legacy\manager.py`
- **Line:** 232
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 813. PY-PATH-001

- **File:** `janitor\legacy\manager.py`
- **Line:** 268
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 814. PY-AUTH-002

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 7
- **Risk:** CRITICAL
- **Message:** [Hardcoded Password / Credential] Hardcoded passwords, API keys, or tokens in source code

**Suggestion:** Use environment variables, .env files, or a secrets manager

### 815. PY-AUTH-002

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 8
- **Risk:** CRITICAL
- **Message:** [Hardcoded Password / Credential] Hardcoded passwords, API keys, or tokens in source code

**Suggestion:** Use environment variables, .env files, or a secrets manager

### 816. PY-EVAL-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 12
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 817. PY-EXEC-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 17
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 818. PY-CMD-002

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 21
- **Risk:** CRITICAL
- **Message:** [Command Injection via subprocess shell=True] subprocess with shell=True enables shell injection via string arguments

**Suggestion:** Use shell=False with argument list instead of shell string

### 819. PY-CMD-002

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 22
- **Risk:** CRITICAL
- **Message:** [Command Injection via subprocess shell=True] subprocess with shell=True enables shell injection via string arguments

**Suggestion:** Use shell=False with argument list instead of shell string

### 820. PY-PATH-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 26
- **Risk:** CRITICAL
- **Message:** [Path Traversal via open()] open() with user-controlled path can access arbitrary files via ../

**Suggestion:** Use os.path.abspath() and verify path is within allowed directory

### 821. PY-EVAL-001

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 40
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 822. PY-EVAL-001

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 41
- **Risk:** CRITICAL
- **Message:** [Code Injection via eval()] eval() executes arbitrary Python code from string input

**Suggestion:** Use ast.literal_eval() for data, or proper parsers

### 823. PY-EXEC-001

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 48
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 824. PY-EXEC-001

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 49
- **Risk:** CRITICAL
- **Message:** [Code Injection via exec()] exec() executes arbitrary Python code and can compromise the application

**Suggestion:** Avoid exec entirely. Use restricted eval or proper program logic

### 825. PY-CMD-002

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 58
- **Risk:** CRITICAL
- **Message:** [Command Injection via subprocess shell=True] subprocess with shell=True enables shell injection via string arguments

**Suggestion:** Use shell=False with argument list instead of shell string

### 826. PY-AUTH-002

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 69
- **Risk:** CRITICAL
- **Message:** [Hardcoded Password / Credential] Hardcoded passwords, API keys, or tokens in source code

**Suggestion:** Use environment variables, .env files, or a secrets manager

### 827. PY-AUTH-002

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 70
- **Risk:** CRITICAL
- **Message:** [Hardcoded Password / Credential] Hardcoded passwords, API keys, or tokens in source code

**Suggestion:** Use environment variables, .env files, or a secrets manager

### 828. PY-SMTP-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 96
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 829. PY-SMTP-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 112
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 830. PY-SMTP-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 128
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 831. PY-SMTP-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 830
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 832. PY-SMTP-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1213
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 833. PY-SMTP-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 96
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 834. PY-SMTP-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 112
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 835. PY-SMTP-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 128
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 836. PY-SMTP-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 176
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 837. PY-XXE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 292
- **Risk:** HIGH
- **Message:** [XML External Entity (XXE) Injection] XML parsing without disabling external entities can expose files or SSRF

**Suggestion:** Disable external entity processing when parsing XML

### 838. PY-XXE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 295
- **Risk:** HIGH
- **Message:** [XML External Entity (XXE) Injection] XML parsing without disabling external entities can expose files or SSRF

**Suggestion:** Disable external entity processing when parsing XML

### 839. PY-XXE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 298
- **Risk:** HIGH
- **Message:** [XML External Entity (XXE) Injection] XML parsing without disabling external entities can expose files or SSRF

**Suggestion:** Disable external entity processing when parsing XML

### 840. PY-XXE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 299
- **Risk:** HIGH
- **Message:** [XML External Entity (XXE) Injection] XML parsing without disabling external entities can expose files or SSRF

**Suggestion:** Disable external entity processing when parsing XML

### 841. PY-XXE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 301
- **Risk:** HIGH
- **Message:** [XML External Entity (XXE) Injection] XML parsing without disabling external entities can expose files or SSRF

**Suggestion:** Disable external entity processing when parsing XML

### 842. PY-XXE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 304
- **Risk:** HIGH
- **Message:** [XML External Entity (XXE) Injection] XML parsing without disabling external entities can expose files or SSRF

**Suggestion:** Disable external entity processing when parsing XML

### 843. PY-XXE-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 305
- **Risk:** HIGH
- **Message:** [XML External Entity (XXE) Injection] XML parsing without disabling external entities can expose files or SSRF

**Suggestion:** Disable external entity processing when parsing XML

### 844. PY-SMTP-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 384
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 845. PY-SMTP-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 448
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 846. PY-SMTP-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 695
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 847. PY-REDIR-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 727
- **Risk:** HIGH
- **Message:** [Open Redirect via User-Controlled URL] redirect() or HttpResponseRedirect with user input enables phishing

**Suggestion:** Validate redirect URLs against an allowlist of trusted domains

### 848. PY-SMTP-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1331
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 849. PY-XXE-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 498
- **Risk:** HIGH
- **Message:** [XML External Entity (XXE) Injection] XML parsing without disabling external entities can expose files or SSRF

**Suggestion:** Disable external entity processing when parsing XML

### 850. PY-SMTP-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 725
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 851. PY-SMTP-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 99
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 852. PY-SMTP-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 114
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 853. PY-SMTP-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 129
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 854. PY-SMTP-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 174
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 855. PY-SMTP-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1182
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 856. PY-SMTP-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 96
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 857. PY-SMTP-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 112
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 858. PY-SMTP-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 128
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 859. PY-SMTP-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 606
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 860. PY-SMTP-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1078
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 861. PY-TAINT-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 606
- **Risk:** HIGH
- **Message:** [Taint Flow] Data from Standard Input reaches SQL Execution without sanitization

**Suggestion:** Sanitize data between source and sink. Use parameterized queries, validation, or escapes

### 862. PY-TAINT-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1078
- **Risk:** HIGH
- **Message:** [Taint Flow] Data from Standard Input reaches SQL Execution without sanitization

**Suggestion:** Sanitize data between source and sink. Use parameterized queries, validation, or escapes

### 863. PY-SMTP-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 362
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 864. PY-SMTP-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 378
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 865. PY-SMTP-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 394
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 866. PY-SMTP-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 426
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 867. PY-SMTP-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 458
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 868. PY-SMTP-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 474
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 869. PY-SMTP-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 545
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 870. PY-CRYPTO-003

- **File:** `janitor\analyzers\python.py`
- **Line:** 556
- **Risk:** HIGH
- **Message:** [Insecure Block Cipher Mode (ECB)] ECB mode encrypts identical plaintext blocks to identical ciphertext blocks

**Suggestion:** Use CBC with random IV, or GCM/CTR mode with authentication

### 871. PY-SMTP-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 561
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 872. PY-SMTP-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 625
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 873. PY-SMTP-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 641
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 874. PY-CORS-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 651
- **Risk:** HIGH
- **Message:** [Overly Permissive CORS (Wildcard)] Flask/Django CORS with origins='*' exposes API to all domains

**Suggestion:** Specify exact allowed origins in an allowlist

### 875. PY-CSRF-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 661
- **Risk:** HIGH
- **Message:** [CSRF Protection Disabled (Django @csrf_exempt)] @csrf_exempt or @csrf_exempt disables CSRF protection for the view

**Suggestion:** Remove @csrf_exempt and use proper CSRF tokens for state-changing operations

### 876. PY-CSRF-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 664
- **Risk:** HIGH
- **Message:** [CSRF Protection Disabled (Django @csrf_exempt)] @csrf_exempt or @csrf_exempt disables CSRF protection for the view

**Suggestion:** Remove @csrf_exempt and use proper CSRF tokens for state-changing operations

### 877. PY-CSRF-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 667
- **Risk:** HIGH
- **Message:** [CSRF Protection Disabled (Django @csrf_exempt)] @csrf_exempt or @csrf_exempt disables CSRF protection for the view

**Suggestion:** Remove @csrf_exempt and use proper CSRF tokens for state-changing operations

### 878. PY-CSRF-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 668
- **Risk:** HIGH
- **Message:** [CSRF Protection Disabled (Django @csrf_exempt)] @csrf_exempt or @csrf_exempt disables CSRF protection for the view

**Suggestion:** Remove @csrf_exempt and use proper CSRF tokens for state-changing operations

### 879. PY-CSRF-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 670
- **Risk:** HIGH
- **Message:** [CSRF Protection Disabled (Django @csrf_exempt)] @csrf_exempt or @csrf_exempt disables CSRF protection for the view

**Suggestion:** Remove @csrf_exempt and use proper CSRF tokens for state-changing operations

### 880. PY-CSRF-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 673
- **Risk:** HIGH
- **Message:** [CSRF Protection Disabled (Django @csrf_exempt)] @csrf_exempt or @csrf_exempt disables CSRF protection for the view

**Suggestion:** Remove @csrf_exempt and use proper CSRF tokens for state-changing operations

### 881. PY-SMTP-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 689
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 882. PY-AUTH-003

- **File:** `janitor\analyzers\python.py`
- **Line:** 716
- **Risk:** HIGH
- **Message:** [SSH Host Key Verification Disabled (Paramiko)] AutoAddPolicy or MissingHostKeyPolicy allows MITM attacks

**Suggestion:** Use paramiko.RejectPolicy (default) or explicitly verify host keys

### 883. PY-CONFIG-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 731
- **Risk:** HIGH
- **Message:** [Django ALLOWED_HOSTS Wildcard] ALLOWED_HOSTS = ['*'] allows HTTP Host header attacks

**Suggestion:** Specify explicit allowed hostnames for your application

### 884. PY-TAINT-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 705
- **Risk:** HIGH
- **Message:** [Taint Flow] Data from Environment Variable reaches File Open without sanitization

**Suggestion:** Sanitize data between source and sink. Use parameterized queries, validation, or escapes

### 885. PY-TAINT-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 824
- **Risk:** HIGH
- **Message:** [Taint Flow] Data from Environment Variable reaches Subprocess Execution without sanitization

**Suggestion:** Sanitize data between source and sink. Use parameterized queries, validation, or escapes

### 886. PY-TAINT-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 840
- **Risk:** HIGH
- **Message:** [Taint Flow] Data from Environment Variable reaches Subprocess Execution without sanitization

**Suggestion:** Sanitize data between source and sink. Use parameterized queries, validation, or escapes

### 887. PY-TAINT-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 888
- **Risk:** HIGH
- **Message:** [Taint Flow] Data from Environment Variable reaches File Open without sanitization

**Suggestion:** Sanitize data between source and sink. Use parameterized queries, validation, or escapes

### 888. PY-TAINT-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1282
- **Risk:** HIGH
- **Message:** [Taint Flow] Data from Environment Variable reaches SQL Execution without sanitization

**Suggestion:** Sanitize data between source and sink. Use parameterized queries, validation, or escapes

### 889. PY-TAINT-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 332
- **Risk:** HIGH
- **Message:** [Taint Flow] Data from HTTP Headers reaches Code Eval without sanitization

**Suggestion:** Sanitize data between source and sink. Use parameterized queries, validation, or escapes

### 890. PY-TAINT-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 414
- **Risk:** HIGH
- **Message:** [Taint Flow] Data from HTTP Headers reaches SQL Execution without sanitization

**Suggestion:** Sanitize data between source and sink. Use parameterized queries, validation, or escapes

### 891. PY-TAINT-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 488
- **Risk:** HIGH
- **Message:** [Taint Flow] Data from HTTP Headers reaches Code Eval without sanitization

**Suggestion:** Sanitize data between source and sink. Use parameterized queries, validation, or escapes

### 892. PY-TAINT-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 503
- **Risk:** HIGH
- **Message:** [Taint Flow] Data from HTTP Headers reaches Code Eval without sanitization

**Suggestion:** Sanitize data between source and sink. Use parameterized queries, validation, or escapes

### 893. PY-TAINT-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 681
- **Risk:** HIGH
- **Message:** [Taint Flow] Data from HTTP Headers reaches SQL Raw Query without sanitization

**Suggestion:** Sanitize data between source and sink. Use parameterized queries, validation, or escapes

### 894. PY-SMTP-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 730
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 895. PY-SMTP-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 864
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 896. PY-SMTP-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 258
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 897. PY-SMTP-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 418
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 898. PY-SMTP-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 457
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 899. PY-SMTP-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 489
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 900. PY-XXE-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 612
- **Risk:** HIGH
- **Message:** [XML External Entity (XXE) Injection] XML parsing without disabling external entities can expose files or SSRF

**Suggestion:** Disable external entity processing when parsing XML

### 901. PY-SMTP-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 617
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 902. PY-SMTP-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 649
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 903. PY-SMTP-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 919
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 904. PY-SMTP-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1210
- **Risk:** HIGH
- **Message:** [SMTP Header Injection] Email headers with user input (\n injection) can inject malicious headers

**Suggestion:** Sanitize line breaks (\r\n) from any user input used in email headers

### 905. PY-CRYPTO-001

- **File:** `janitor\legacy\manager.py`
- **Line:** 78
- **Risk:** HIGH
- **Message:** [Weak Hashing Algorithm (MD5/SHA1)] MD5 and SHA1 are cryptographically broken and vulnerable to collision attacks

**Suggestion:** Use hashlib.sha256() or stronger; use bcrypt/argon2 for passwords

### 906. PY-LOG-001

- **File:** `janitor\cli.py`
- **Line:** 76
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 907. PY-LOG-001

- **File:** `janitor\cli.py`
- **Line:** 131
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 908. PY-LOG-001

- **File:** `janitor\cli.py`
- **Line:** 326
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 909. PY-LOG-001

- **File:** `janitor\cli.py`
- **Line:** 329
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 910. PY-LOG-001

- **File:** `janitor\cli.py`
- **Line:** 363
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 911. PY-LOG-001

- **File:** `janitor\cli.py`
- **Line:** 386
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 912. PY-LOG-001

- **File:** `janitor\cli.py`
- **Line:** 389
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 913. PY-LOG-001

- **File:** `janitor\cli.py`
- **Line:** 418
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 914. PY-LOG-001

- **File:** `janitor\cli.py`
- **Line:** 429
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 915. PY-LOG-001

- **File:** `janitor\cli.py`
- **Line:** 574
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 916. PY-ERR-001

- **File:** `janitor\cli.py`
- **Line:** 426
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 917. PY-LOG-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 226
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 918. PY-LOG-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 477
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 919. PY-LOG-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 528
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 920. PY-LOG-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 532
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 921. PY-LOG-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 586
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 922. PY-LOG-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 619
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 923. PY-LOG-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 630
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 924. PY-LOG-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 641
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 925. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 229
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 926. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 248
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 927. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 265
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 928. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 283
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 929. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 311
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 930. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 328
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 931. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 340
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 932. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 354
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 933. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 367
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 934. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 383
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 935. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 396
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 936. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 405
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 937. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 414
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 938. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 444
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 939. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 452
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 940. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 457
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 941. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 517
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 942. PY-ERR-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 575
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 943. PY-LOG-001

- **File:** `janitor\language_detector.py`
- **Line:** 89
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 944. PY-LOG-001

- **File:** `janitor\language_detector.py`
- **Line:** 122
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 945. PY-LOG-001

- **File:** `janitor\llm.py`
- **Line:** 61
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 946. PY-LOG-001

- **File:** `janitor\llm.py`
- **Line:** 63
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 947. PY-LOG-001

- **File:** `janitor\llm.py`
- **Line:** 78
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 948. PY-LOG-001

- **File:** `janitor\llm.py`
- **Line:** 91
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 949. PY-LOG-001

- **File:** `janitor\llm.py`
- **Line:** 100
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 950. PY-LOG-001

- **File:** `janitor\llm.py`
- **Line:** 227
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 951. PY-LOG-001

- **File:** `janitor\llm.py`
- **Line:** 247
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 952. PY-LOG-001

- **File:** `janitor\llm.py`
- **Line:** 324
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 953. PY-ERR-001

- **File:** `janitor\llm.py`
- **Line:** 75
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 954. PY-LOG-001

- **File:** `janitor\scanner.py`
- **Line:** 55
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 955. PY-LOG-001

- **File:** `janitor\scanner.py`
- **Line:** 57
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 956. PY-LOG-001

- **File:** `janitor\scanner.py`
- **Line:** 108
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 957. PY-LOG-001

- **File:** `janitor\scanner.py`
- **Line:** 125
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 958. PY-FORMAT-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 150
- **Risk:** MEDIUM
- **Message:** [Format String Vulnerability via User Input] Using user input as the format string with % operator can expose memory

**Suggestion:** Use str.format() or f-strings with positional arguments, not % formatting with user data

### 959. PY-FORMAT-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 180
- **Risk:** MEDIUM
- **Message:** [Format String Vulnerability via User Input] Using user input as the format string with % operator can expose memory

**Suggestion:** Use str.format() or f-strings with positional arguments, not % formatting with user data

### 960. PY-FORMAT-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 239
- **Risk:** MEDIUM
- **Message:** [Format String Vulnerability via User Input] Using user input as the format string with % operator can expose memory

**Suggestion:** Use str.format() or f-strings with positional arguments, not % formatting with user data

### 961. PY-FORMAT-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 254
- **Risk:** MEDIUM
- **Message:** [Format String Vulnerability via User Input] Using user input as the format string with % operator can expose memory

**Suggestion:** Use str.format() or f-strings with positional arguments, not % formatting with user data

### 962. PY-ERR-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 382
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 963. PY-ERR-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 383
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 964. PY-ERR-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 390
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 965. PY-ERR-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 412
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 966. PY-ERR-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 413
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 967. PY-ERR-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 420
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 968. PY-ERR-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 427
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 969. PY-ERR-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 428
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 970. PY-ERR-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 435
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 971. PY-ERR-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 450
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 972. PY-ERR-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 539
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 973. PY-ERR-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 540
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 974. PY-FORMAT-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1017
- **Risk:** MEDIUM
- **Message:** [Format String Vulnerability via User Input] Using user input as the format string with % operator can expose memory

**Suggestion:** Use str.format() or f-strings with positional arguments, not % formatting with user data

### 975. PY-ERR-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 199
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 976. PY-ERR-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 202
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 977. PY-ERR-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 199
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 978. PY-ERR-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 202
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 979. PY-ERR-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 208
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 980. PY-ERR-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 209
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 981. PY-ERR-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 250
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 982. PY-ERR-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 257
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 983. PY-ERR-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 945
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 984. PY-ERR-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 947
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 985. PY-ERR-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 1054
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 986. PY-ERR-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 190
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 987. PY-ERR-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 197
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 988. PY-ASSERT-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 196
- **Risk:** MEDIUM
- **Message:** [Assert Used for Validation] assert statements are removed when Python runs with -O (optimize)

**Suggestion:** Use proper if/raise validation instead of assert for security checks

### 989. PY-ASSERT-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 208
- **Risk:** MEDIUM
- **Message:** [Assert Used for Validation] assert statements are removed when Python runs with -O (optimize)

**Suggestion:** Use proper if/raise validation instead of assert for security checks

### 990. PY-ERR-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 160
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 991. PY-ERR-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 161
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 992. PY-ERR-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 183
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 993. PY-ERR-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 186
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 994. PY-ERR-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 189
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 995. PY-ERR-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 193
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 996. PY-ERR-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 304
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 997. PY-SUBPROCESS-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 186
- **Risk:** MEDIUM
- **Message:** [Subprocess Without Timeout] subprocess.run() without timeout can hang indefinitely

**Suggestion:** Always set a timeout for subprocess operations

### 998. PY-SUBPROCESS-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 202
- **Risk:** MEDIUM
- **Message:** [Subprocess Without Timeout] subprocess.run() without timeout can hang indefinitely

**Suggestion:** Always set a timeout for subprocess operations

### 999. PY-SUBPROCESS-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 218
- **Risk:** MEDIUM
- **Message:** [Subprocess Without Timeout] subprocess.run() without timeout can hang indefinitely

**Suggestion:** Always set a timeout for subprocess operations

### 1000. PY-FORMAT-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 808
- **Risk:** MEDIUM
- **Message:** [Format String Vulnerability via User Input] Using user input as the format string with % operator can expose memory

**Suggestion:** Use str.format() or f-strings with positional arguments, not % formatting with user data

### 1001. PY-SUBPROCESS-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 840
- **Risk:** MEDIUM
- **Message:** [Subprocess Without Timeout] subprocess.run() without timeout can hang indefinitely

**Suggestion:** Always set a timeout for subprocess operations

### 1002. PY-FILE-002

- **File:** `janitor\analyzers\python.py`
- **Line:** 866
- **Risk:** MEDIUM
- **Message:** [Overly Permissive File Permissions (0o777)] os.chmod(0o777) makes files world-readable/writable/executable

**Suggestion:** Use minimum required permissions (e.g., 0o600 for secrets, 0o755 for executables)

### 1003. PY-DEPR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 883
- **Risk:** MEDIUM
- **Message:** [Deprecated API Usage] Using deprecated Python APIs that may have known vulnerabilities

**Suggestion:** Replace deprecated APIs with modern alternatives

### 1004. PY-DEPR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 888
- **Risk:** MEDIUM
- **Message:** [Deprecated API Usage] Using deprecated Python APIs that may have known vulnerabilities

**Suggestion:** Replace deprecated APIs with modern alternatives

### 1005. PY-LOG-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1055
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 1006. PY-LOG-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1071
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 1007. PY-LOG-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1311
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 1008. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 129
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1009. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 132
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1010. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 135
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1011. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 145
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1012. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 148
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1013. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 154
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1014. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 155
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1015. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 171
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1016. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 183
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (subprocess.run) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1017. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 186
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (subprocess.run) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1018. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 202
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (subprocess.run) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1019. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 212
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1020. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 215
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (subprocess.run) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1021. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 218
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (subprocess.run) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1022. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 219
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1023. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 308
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (pickle.load) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1024. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 318
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (yaml.load) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1025. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 321
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (yaml.load) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1026. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 324
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (yaml.load) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1027. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 327
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (yaml.load) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1028. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 433
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1029. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 436
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1030. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 443
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1031. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 699
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1032. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 818
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (subprocess.run) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1033. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 824
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (subprocess.run) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1034. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 840
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (subprocess.run) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1035. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 888
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1036. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1216
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1037. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1217
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1038. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1220
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1039. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1221
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (pickle.load) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1040. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1222
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (yaml.load) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1041. PY-ERR-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1321
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1042. PY-FORMAT-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 119
- **Risk:** MEDIUM
- **Message:** [Format String Vulnerability via User Input] Using user input as the format string with % operator can expose memory

**Suggestion:** Use str.format() or f-strings with positional arguments, not % formatting with user data

### 1043. PY-ERR-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 332
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1044. PY-ERR-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 479
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1045. PY-ERR-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 482
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1046. PY-ERR-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 488
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1047. PY-ERR-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 503
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1048. PY-ERR-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 201
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1049. PY-ERR-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 204
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1050. PY-ERR-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 210
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1051. PY-ERR-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 211
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1052. PY-ERR-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 252
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1053. PY-ERR-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 259
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1054. PY-ERR-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 434
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1055. PY-ERR-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1143
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1056. PY-ERR-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1145
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1057. PY-ERR-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1330
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1058. PY-LOG-001

- **File:** `janitor\legacy\manager.py`
- **Line:** 72
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 1059. PY-LOG-001

- **File:** `janitor\legacy\manager.py`
- **Line:** 179
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 1060. PY-LOG-001

- **File:** `janitor\legacy\manager.py`
- **Line:** 184
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 1061. PY-LOG-001

- **File:** `janitor\legacy\manager.py`
- **Line:** 193
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 1062. PY-LOG-001

- **File:** `janitor\legacy\manager.py`
- **Line:** 271
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 1063. PY-LOG-001

- **File:** `janitor\legacy\manager.py`
- **Line:** 274
- **Risk:** MEDIUM
- **Message:** [Log Injection via User Input] Logging user input without sanitization enables log injection attacks

**Suggestion:** Sanitize line breaks from user input before logging or use structured logging

### 1064. PY-ERR-001

- **File:** `janitor\legacy\manager.py`
- **Line:** 79
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1065. PY-SUBPROCESS-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 21
- **Risk:** MEDIUM
- **Message:** [Subprocess Without Timeout] subprocess.run() without timeout can hang indefinitely

**Suggestion:** Always set a timeout for subprocess operations

### 1066. PY-SUBPROCESS-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 22
- **Risk:** MEDIUM
- **Message:** [Subprocess Without Timeout] subprocess.run() without timeout can hang indefinitely

**Suggestion:** Always set a timeout for subprocess operations

### 1067. PY-ERR-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 12
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1068. PY-ERR-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 17
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1069. PY-ERR-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 21
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (subprocess.run) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1070. PY-ERR-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 22
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1071. PY-ERR-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 26
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (open() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1072. PY-SUBPROCESS-001

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 58
- **Risk:** MEDIUM
- **Message:** [Subprocess Without Timeout] subprocess.run() without timeout can hang indefinitely

**Suggestion:** Always set a timeout for subprocess operations

### 1073. PY-ERR-001

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 40
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1074. PY-ERR-001

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 41
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (eval() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1075. PY-ERR-001

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 48
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1076. PY-ERR-001

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 49
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (exec() without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1077. PY-ERR-001

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 58
- **Risk:** MEDIUM
- **Message:** [Sensitive Operation Without try/except] Sensitive operation (subprocess.run) without error handling may crash

**Suggestion:** Wrap sensitive operations in try/except blocks

### 1078. PY-QUAL-004

- **File:** `janitor\analyzer.py`
- **Line:** 7
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1079. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 87
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1080. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 91
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1081. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 92
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1082. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 99
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1083. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 100
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1084. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 127
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1085. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 128
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1086. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 140
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1087. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 147
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1088. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 153
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1089. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 157
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1090. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 159
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1091. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 161
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1092. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 163
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1093. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 168
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1094. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 176
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1095. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 176
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1096. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 179
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1097. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 186
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1098. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 187
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1099. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 188
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1100. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 192
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1101. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 201
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1102. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 203
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1103. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 204
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1104. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 205
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1105. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 207
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1106. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 208
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1107. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 210
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1108. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 211
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1109. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 211
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1110. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 213
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1111. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 218
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1112. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 219
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1113. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 220
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1114. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 221
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1115. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 222
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1116. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 225
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1117. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 235
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1118. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 236
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1119. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 237
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1120. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 239
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1121. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 240
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1122. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 241
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1123. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 242
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1124. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 243
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1125. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 244
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1126. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 270
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1127. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 271
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1128. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 272
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1129. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 273
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1130. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 275
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1131. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 276
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1132. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 277
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1133. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 278
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1134. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 279
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1135. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 288
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1136. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 289
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1137. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 290
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1138. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 292
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1139. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 293
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1140. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 297
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1141. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 298
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1142. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 299
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1143. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 300
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1144. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 301
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1145. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 304
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1146. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 318
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1147. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 320
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1148. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 321
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1149. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 322
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1150. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 392
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1151. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 410
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1152. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 454
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1153. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 455
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1154. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 456
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1155. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 457
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1156. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 466
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1157. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 470
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1158. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 474
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1159. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 475
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1160. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 498
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1161. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 501
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1162. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 507
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1163. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 508
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1164. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 509
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1165. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 510
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1166. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 515
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1167. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 516
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1168. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 517
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1169. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 519
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1170. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 521
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1171. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 522
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1172. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 526
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1173. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 527
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1174. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 533
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1175. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 540
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1176. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 543
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1177. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 550
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1178. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 551
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1179. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 554
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1180. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 555
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1181. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 558
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1182. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 559
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1183. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 609
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1184. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 616
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1185. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 622
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1186. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 630
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1187. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 643
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1188. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 644
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1189. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 645
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1190. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 658
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1191. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 664
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1192. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 670
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1193. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 671
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1194. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 678
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1195. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 684
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1196. PY-QUAL-004

- **File:** `janitor\cli.py`
- **Line:** 691
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1197. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 713
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1198. PY-LOG-002

- **File:** `janitor\cli.py`
- **Line:** 736
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1199. PY-QUAL-004

- **File:** `janitor\core.py`
- **Line:** 12
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1200. PY-QUAL-004

- **File:** `janitor\core.py`
- **Line:** 13
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1201. PY-QUAL-004

- **File:** `janitor\core.py`
- **Line:** 17
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1202. PY-QUAL-004

- **File:** `janitor\core.py`
- **Line:** 19
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1203. PY-QUAL-004

- **File:** `janitor\core.py`
- **Line:** 20
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1204. PY-QUAL-004

- **File:** `janitor\core.py`
- **Line:** 21
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1205. PY-QUAL-004

- **File:** `janitor\core.py`
- **Line:** 22
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1206. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 63
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1207. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 94
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1208. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 120
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1209. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 129
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1210. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 154
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1211. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 228
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1212. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 231
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1213. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 246
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1214. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 264
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1215. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 267
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1216. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 282
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1217. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 303
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1218. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 306
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1219. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 309
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1220. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 327
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1221. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 339
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1222. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 352
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1223. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 365
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1224. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 369
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1225. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 382
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1226. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 395
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1227. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 404
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1228. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 413
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1229. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 434
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1230. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 443
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1231. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 451
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1232. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 456
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1233. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 471
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1234. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 473
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1235. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 483
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1236. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 499
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1237. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 511
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1238. PY-MAGIC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 525
- **Risk:** LOW
- **Message:** [Magic Number Used] Hardcoded numeric literals should be named constants

**Suggestion:** Define magic numbers as named constants with descriptive names

### 1239. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 547
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1240. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 571
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1241. PY-DOC-001

- **File:** `janitor\dependency_scanner.py`
- **Line:** 610
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1242. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 654
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1243. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 655
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1244. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 656
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1245. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 657
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1246. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 658
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1247. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 659
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1248. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 660
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1249. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 661
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1250. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 686
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1251. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 689
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1252. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 723
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1253. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 724
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1254. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 725
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1255. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 726
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1256. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 726
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1257. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 727
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1258. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 727
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1259. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 728
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1260. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 728
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1261. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 729
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1262. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 729
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1263. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 730
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1264. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 730
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1265. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 731
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1266. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 732
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1267. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 733
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1268. PY-QUAL-004

- **File:** `janitor\dependency_scanner.py`
- **Line:** 734
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1269. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 736
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1270. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 737
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1271. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 746
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1272. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 749
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1273. PY-LOG-002

- **File:** `janitor\dependency_scanner.py`
- **Line:** 750
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1274. PY-QUAL-004

- **File:** `janitor\language_detector.py`
- **Line:** 13
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1275. PY-QUAL-004

- **File:** `janitor\language_detector.py`
- **Line:** 14
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1276. PY-QUAL-004

- **File:** `janitor\language_detector.py`
- **Line:** 28
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1277. PY-QUAL-004

- **File:** `janitor\language_detector.py`
- **Line:** 37
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1278. PY-QUAL-004

- **File:** `janitor\language_detector.py`
- **Line:** 43
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1279. PY-QUAL-004

- **File:** `janitor\language_detector.py`
- **Line:** 44
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1280. PY-QUAL-004

- **File:** `janitor\language_detector.py`
- **Line:** 58
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1281. PY-QUAL-004

- **File:** `janitor\language_detector.py`
- **Line:** 59
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1282. PY-QUAL-004

- **File:** `janitor\language_detector.py`
- **Line:** 67
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1283. PY-QUAL-004

- **File:** `janitor\language_detector.py`
- **Line:** 68
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1284. PY-QUAL-002

- **File:** `janitor\language_detector.py`
- **Line:** 111
- **Risk:** LOW
- **Message:** [Overly Broad Exception Catch] except Exception: catches too many error types, can hide bugs

**Suggestion:** Catch only specific exception types that you expect

### 1285. PY-QUAL-002

- **File:** `janitor\language_detector.py`
- **Line:** 159
- **Risk:** LOW
- **Message:** [Overly Broad Exception Catch] except Exception: catches too many error types, can hide bugs

**Suggestion:** Catch only specific exception types that you expect

### 1286. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 70
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1287. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 170
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1288. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 171
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1289. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 175
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1290. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 180
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1291. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 182
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1292. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 194
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1293. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 198
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1294. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 205
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1295. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 206
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1296. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 210
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1297. PY-DOC-001

- **File:** `janitor\llm.py`
- **Line:** 212
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1298. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 220
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1299. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 221
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1300. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 225
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1301. PY-DOC-001

- **File:** `janitor\llm.py`
- **Line:** 250
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1302. PY-QUAL-004

- **File:** `janitor\llm.py`
- **Line:** 258
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1303. PY-DOC-001

- **File:** `janitor\llm.py`
- **Line:** 297
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1304. PY-QUAL-004

- **File:** `janitor\scanner.py`
- **Line:** 12
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1305. PY-QUAL-004

- **File:** `janitor\scanner.py`
- **Line:** 13
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1306. PY-QUAL-004

- **File:** `janitor\analyzers\base.py`
- **Line:** 38
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1307. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 41
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1308. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 44
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1309. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 62
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1310. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 312
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1311. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 328
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1312. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 344
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1313. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 463
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1314. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 479
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1315. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 495
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1316. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 607
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1317. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 639
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1318. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 726
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1319. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 742
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1320. PY-MAGIC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 766
- **Risk:** LOW
- **Message:** [Magic Number Used] Hardcoded numeric literals should be named constants

**Suggestion:** Define magic numbers as named constants with descriptive names

### 1321. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 782
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1322. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 854
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1323. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 886
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1324. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 909
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1325. PY-COMM-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 944
- **Risk:** LOW
- **Message:** [TODO Comment in Code] TODO comments may indicate incomplete security work

**Suggestion:** Address TODO/FIXME items before production deployment

### 1326. PY-QUAL-005

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1045
- **Risk:** LOW
- **Message:** [Hardcoded localhost/127.0.0.1] Hardcoded localhost addresses may indicate test/debug code

**Suggestion:** Use environment variables or configuration for host addresses

### 1327. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1101
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1328. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1103
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1329. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1104
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1330. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1105
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1331. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1139
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1332. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1140
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1333. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1141
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1334. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1142
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1335. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1143
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1336. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1147
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1337. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1157
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1338. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1159
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1339. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1245
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1340. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1250
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1341. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1254
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1342. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1261
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1343. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1270
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1344. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1273
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1345. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1277
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1346. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1278
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1347. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1280
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1348. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1284
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1349. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1289
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1350. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1290
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1351. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1292
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1352. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1298
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1353. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1303
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1354. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1304
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1355. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1308
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1356. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1311
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1357. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1315
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1358. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1322
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1359. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1323
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1360. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1329
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1361. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1330
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1362. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1334
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1363. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1337
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1364. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1341
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1365. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1342
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1366. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1348
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1367. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1355
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1368. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1356
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1369. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1358
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1370. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1362
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1371. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1363
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1372. PY-QUAL-005

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1365
- **Risk:** LOW
- **Message:** [Hardcoded localhost/127.0.0.1] Hardcoded localhost addresses may indicate test/debug code

**Suggestion:** Use environment variables or configuration for host addresses

### 1373. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1369
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1374. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1376
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1375. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1381
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1376. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1384
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1377. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1388
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1378. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1391
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1379. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1395
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1380. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1396
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1381. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1398
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1382. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1404
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1383. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1407
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1384. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1411
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1385. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1412
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1386. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1416
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1387. PY-QUAL-004

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1417
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1388. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1421
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1389. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1434
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1390. PY-DOC-001

- **File:** `janitor\analyzers\csharp.py`
- **Line:** 1441
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1391. PY-DOC-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 48
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1392. PY-DOC-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 63
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1393. PY-DOC-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 66
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1394. PY-DOC-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 72
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1395. PY-DOC-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 75
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1396. PY-COMM-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 765
- **Risk:** LOW
- **Message:** [TODO Comment in Code] TODO comments may indicate incomplete security work

**Suggestion:** Address TODO/FIXME items before production deployment

### 1397. PY-QUAL-004

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 795
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1398. PY-QUAL-002

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 957
- **Risk:** LOW
- **Message:** [Overly Broad Exception Catch] except Exception: catches too many error types, can hide bugs

**Suggestion:** Catch only specific exception types that you expect

### 1399. PY-DOC-001

- **File:** `janitor\analyzers\c_cpp.py`
- **Line:** 992
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1400. PY-DOC-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 42
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1401. PY-DOC-001

- **File:** `janitor\analyzers\dart.py`
- **Line:** 45
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1402. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 62
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1403. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 108
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1404. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 109
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1405. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 110
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1406. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 112
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1407. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 113
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1408. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 114
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1409. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 115
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1410. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 116
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1411. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 117
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1412. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 118
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1413. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 120
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1414. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 121
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1415. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 122
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1416. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 123
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1417. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 124
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1418. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 125
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1419. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 126
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1420. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 128
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1421. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 129
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1422. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 131
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1423. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 132
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1424. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 133
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1425. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 134
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1426. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 135
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1427. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 136
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1428. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 137
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1429. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 170
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1430. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 618
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1431. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 668
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1432. PY-LOG-002

- **File:** `janitor\analyzers\dart.py`
- **Line:** 722
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1433. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 780
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1434. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 876
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1435. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 877
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1436. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 878
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1437. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 881
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1438. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 882
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1439. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 885
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1440. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 890
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1441. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 891
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1442. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 892
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1443. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 893
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1444. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 894
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1445. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 895
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1446. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 896
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1447. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 1014
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1448. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 1015
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1449. PY-QUAL-004

- **File:** `janitor\analyzers\dart.py`
- **Line:** 1016
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1450. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 41
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1451. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 44
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1452. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 62
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1453. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 216
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1454. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 232
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1455. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 283
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1456. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 335
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1457. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 351
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1458. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 383
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1459. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 399
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1460. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 431
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1461. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 534
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1462. PY-MAGIC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 542
- **Risk:** LOW
- **Message:** [Magic Number Used] Hardcoded numeric literals should be named constants

**Suggestion:** Define magic numbers as named constants with descriptive names

### 1463. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 582
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1464. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 598
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1465. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 614
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1466. PY-MAGIC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 654
- **Risk:** LOW
- **Message:** [Magic Number Used] Hardcoded numeric literals should be named constants

**Suggestion:** Define magic numbers as named constants with descriptive names

### 1467. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 669
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1468. PY-COMM-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 704
- **Risk:** LOW
- **Message:** [TODO Comment in Code] TODO comments may indicate incomplete security work

**Suggestion:** Address TODO/FIXME items before production deployment

### 1469. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 825
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1470. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 827
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1471. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 828
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1472. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 829
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1473. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 925
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1474. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 932
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1475. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 939
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1476. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 944
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1477. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 947
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1478. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 951
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1479. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 952
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1480. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 956
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1481. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 957
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1482. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 963
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1483. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 964
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1484. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 968
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1485. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 973
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1486. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 978
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1487. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 985
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1488. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 986
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1489. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 992
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1490. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 993
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1491. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 997
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1492. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 998
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1493. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1002
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1494. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1009
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1495. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 1010
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1496. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1014
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1497. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1021
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1498. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1028
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1499. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 1029
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1500. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1033
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1501. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1038
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1502. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1045
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1503. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1050
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1504. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1059
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1505. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1064
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1506. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1069
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1507. PY-QUAL-004

- **File:** `janitor\analyzers\go.py`
- **Line:** 1070
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1508. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1074
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1509. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1086
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1510. PY-DOC-001

- **File:** `janitor\analyzers\go.py`
- **Line:** 1093
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1511. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 41
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1512. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 44
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1513. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 62
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1514. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 312
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1515. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 328
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1516. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 511
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1517. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 527
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1518. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 543
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1519. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 559
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1520. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 575
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1521. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 703
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1522. PY-MAGIC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 727
- **Risk:** LOW
- **Message:** [Magic Number Used] Hardcoded numeric literals should be named constants

**Suggestion:** Define magic numbers as named constants with descriptive names

### 1523. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 790
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1524. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 806
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1525. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 822
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1526. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 886
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1527. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 950
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1528. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 966
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1529. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1005
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1530. PY-COMM-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1040
- **Risk:** LOW
- **Message:** [TODO Comment in Code] TODO comments may indicate incomplete security work

**Suggestion:** Address TODO/FIXME items before production deployment

### 1531. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1191
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1532. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1217
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1533. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1219
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1534. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1220
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1535. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1221
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1536. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1254
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1537. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1255
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1538. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1257
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1539. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1258
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1540. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1261
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1541. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1262
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1542. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1263
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1543. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1265
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1544. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1269
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1545. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1273
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1546. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1274
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1547. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1276
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1548. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1340
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1549. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1363
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1550. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1366
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1551. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1370
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1552. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1377
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1553. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1378
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1554. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1384
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1555. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1391
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1556. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1394
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1557. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1396
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1558. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1400
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1559. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1401
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1560. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1403
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1561. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1405
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1562. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1409
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1563. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1410
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1564. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1412
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1565. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1416
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1566. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1421
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1567. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1424
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1568. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1428
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1569. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1429
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1570. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1435
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1571. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1436
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1572. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1444
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1573. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1445
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1574. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1447
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1575. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1451
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1576. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1454
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1577. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1458
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1578. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1465
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1579. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1466
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1580. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1472
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1581. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1473
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1582. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1475
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1583. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1481
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1584. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1484
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1585. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1492
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1586. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1497
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1587. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1502
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1588. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1509
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1589. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1510
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1590. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1514
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1591. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1515
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1592. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1519
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1593. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1524
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1594. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1529
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1595. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1536
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1596. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1541
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1597. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1542
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1598. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1546
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1599. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1547
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1600. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1549
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1601. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1553
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1602. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1554
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1603. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1562
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1604. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1563
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1605. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1569
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1606. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1576
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1607. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1577
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1608. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1581
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1609. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1586
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1610. PY-QUAL-004

- **File:** `janitor\analyzers\java.py`
- **Line:** 1587
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1611. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1593
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1612. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1606
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1613. PY-DOC-001

- **File:** `janitor\analyzers\java.py`
- **Line:** 1615
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1614. PY-DOC-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 41
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1615. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 42
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1616. PY-DOC-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 44
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1617. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 62
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1618. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 256
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1619. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 360
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1620. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 383
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1621. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 399
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1622. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 415
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1623. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 447
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1624. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 598
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1625. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 678
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1626. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 686
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1627. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 733
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1628. PY-COMM-001

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 768
- **Risk:** LOW
- **Message:** [TODO Comment in Code] TODO comments may indicate incomplete security work

**Suggestion:** Address TODO/FIXME items before production deployment

### 1629. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 853
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1630. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 911
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1631. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 913
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1632. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 914
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1633. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 915
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1634. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 930
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1635. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 931
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1636. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 943
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1637. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 1078
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1638. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 1086
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1639. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 1092
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1640. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 1098
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1641. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 1106
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1642. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 1126
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1643. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 1146
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1644. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 1152
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1645. PY-QUAL-004

- **File:** `janitor\analyzers\javascript.py`
- **Line:** 1188
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1646. PY-DOC-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 42
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1647. PY-DOC-001

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 45
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1648. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 62
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1649. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 329
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1650. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 344
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1651. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 359
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1652. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 374
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1653. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 389
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1654. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 411
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1655. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 426
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1656. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 441
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1657. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 456
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1658. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 612
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1659. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 627
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1660. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 642
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1661. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 657
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1662. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 746
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1663. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 761
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1664. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 783
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1665. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 798
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1666. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 820
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1667. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 842
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1668. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 864
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1669. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 908
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1670. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 952
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1671. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1038
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1672. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1069
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1673. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1071
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1674. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1072
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1675. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1073
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1676. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1101
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1677. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1104
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1678. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1106
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1679. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1107
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1680. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1109
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1681. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1110
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1682. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1191
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1683. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1216
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1684. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1220
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1685. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1224
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1686. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1252
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1687. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1262
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1688. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1270
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1689. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1280
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1690. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1308
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1691. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1332
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1692. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1344
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1693. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1350
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1694. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1356
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1695. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1362
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1696. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1368
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1697. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1380
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1698. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1386
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1699. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1392
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1700. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1398
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1701. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1404
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1702. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1410
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1703. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1430
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1704. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1436
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1705. PY-QUAL-004

- **File:** `janitor\analyzers\kotlin.py`
- **Line:** 1448
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1706. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 41
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1707. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 44
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1708. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 62
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1709. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 232
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1710. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 240
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1711. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 383
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1712. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 399
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1713. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 415
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1714. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 479
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1715. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 487
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1716. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 511
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1717. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 551
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1718. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 567
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1719. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 582
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1720. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 598
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1721. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 622
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1722. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 742
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1723. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 774
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1724. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 782
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1725. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 797
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1726. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 821
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1727. PY-COMM-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 832
- **Risk:** LOW
- **Message:** [TODO Comment in Code] TODO comments may indicate incomplete security work

**Suggestion:** Address TODO/FIXME items before production deployment

### 1728. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 939
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1729. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 973
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1730. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 975
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1731. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 976
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1732. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 977
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1733. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 993
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1734. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 994
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1735. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 996
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1736. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1000
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1737. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1001
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1738. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1007
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1739. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1010
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1740. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1019
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1741. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1112
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1742. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1119
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1743. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1126
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1744. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1127
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1745. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1133
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1746. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1134
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1747. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1136
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1748. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1140
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1749. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1147
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1750. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1154
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1751. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1155
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1752. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1157
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1753. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1159
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1754. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1163
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1755. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1164
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1756. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1170
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1757. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1171
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1758. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1179
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1759. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1180
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1760. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1182
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1761. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1186
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1762. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1187
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1763. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1195
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1764. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1200
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1765. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1204
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1766. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1205
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1767. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1211
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1768. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1214
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1769. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1220
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1770. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1221
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1771. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1225
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1772. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1226
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1773. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1228
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1774. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1232
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1775. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1235
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1776. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1239
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1777. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1242
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1778. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1246
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1779. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1247
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1780. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1253
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1781. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1254
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1782. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1256
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1783. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1260
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1784. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1261
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1785. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1265
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1786. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1266
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1787. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1270
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1788. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1271
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1789. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1275
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1790. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1279
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1791. PY-QUAL-004

- **File:** `janitor\analyzers\php.py`
- **Line:** 1280
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1792. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1284
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1793. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1293
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1794. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1306
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1795. PY-DOC-001

- **File:** `janitor\analyzers\php.py`
- **Line:** 1313
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1796. PY-DOC-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 42
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1797. PY-DOC-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 45
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1798. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 83
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1799. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 306
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1800. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 322
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1801. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 338
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1802. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 442
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1803. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 458
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1804. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 482
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1805. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 490
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1806. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 498
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1807. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 506
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1808. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 521
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1809. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 537
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1810. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 545
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1811. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 553
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1812. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 569
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1813. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 585
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1814. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 713
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1815. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 729
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1816. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 745
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1817. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 784
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1818. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 816
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1819. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 880
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1820. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 912
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1821. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 928
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1822. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 952
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1823. PY-LOG-002

- **File:** `janitor\analyzers\python.py`
- **Line:** 966
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1824. PY-LOG-002

- **File:** `janitor\analyzers\python.py`
- **Line:** 969
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1825. PY-LOG-002

- **File:** `janitor\analyzers\python.py`
- **Line:** 972
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1826. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 983
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1827. PY-COMM-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1018
- **Risk:** LOW
- **Message:** [TODO Comment in Code] TODO comments may indicate incomplete security work

**Suggestion:** Address TODO/FIXME items before production deployment

### 1828. PY-COMM-002

- **File:** `janitor\analyzers\python.py`
- **Line:** 1034
- **Risk:** LOW
- **Message:** [HACK Comment in Code] HACK/XXX comments indicate potentially unsafe workarounds

**Suggestion:** Address HACK/XXX items before production deployment

### 1829. PY-QUAL-001

- **File:** `janitor\analyzers\python.py`
- **Line:** 1049
- **Risk:** LOW
- **Message:** [Bare Except Clause] bare except: catches all exceptions including SystemExit, KeyboardInterrupt

**Suggestion:** Catch specific exceptions (except ValueError:, except OSError:)

### 1830. PY-QUAL-002

- **File:** `janitor\analyzers\python.py`
- **Line:** 1065
- **Risk:** LOW
- **Message:** [Overly Broad Exception Catch] except Exception: catches too many error types, can hide bugs

**Suggestion:** Catch only specific exception types that you expect

### 1831. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1103
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1832. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1141
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1833. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1183
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1834. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1185
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1835. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1186
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1836. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1187
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1837. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1214
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1838. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1349
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1839. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1357
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1840. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1363
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1841. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1379
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1842. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1385
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1843. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1407
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1844. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1419
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1845. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1431
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1846. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1437
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1847. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1443
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1848. PY-QUAL-004

- **File:** `janitor\analyzers\python.py`
- **Line:** 1479
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1849. PY-DOC-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 42
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1850. PY-DOC-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 45
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1851. PY-DOC-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 48
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1852. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 65
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1853. PY-DOC-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 84
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1854. PY-DOC-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 92
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1855. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 112
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1856. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 114
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1857. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 115
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1858. PY-DOC-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 126
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1859. PY-DOC-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 166
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1860. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 167
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1861. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 195
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1862. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 201
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1863. PY-DOC-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 205
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1864. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 212
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1865. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 532
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1866. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 547
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1867. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 562
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1868. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 733
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1869. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 777
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1870. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 792
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1871. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 807
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1872. PY-COMM-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 941
- **Risk:** LOW
- **Message:** [TODO Comment in Code] TODO comments may indicate incomplete security work

**Suggestion:** Address TODO/FIXME items before production deployment

### 1873. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 1081
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1874. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 1088
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1875. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 1094
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1876. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 1103
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1877. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 1111
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1878. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 1118
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1879. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 1123
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1880. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 1128
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1881. PY-DOC-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 1151
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1882. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 1184
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1883. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 1186
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1884. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 1187
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1885. PY-QUAL-004

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 1188
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1886. PY-DOC-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 1206
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1887. PY-DOC-001

- **File:** `janitor\analyzers\ruby.py`
- **Line:** 1273
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1888. PY-DOC-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 42
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1889. PY-DOC-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 45
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1890. PY-QUAL-004

- **File:** `janitor\analyzers\rust.py`
- **Line:** 62
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1891. PY-QUAL-004

- **File:** `janitor\analyzers\rust.py`
- **Line:** 108
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1892. PY-QUAL-004

- **File:** `janitor\analyzers\rust.py`
- **Line:** 113
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1893. PY-QUAL-004

- **File:** `janitor\analyzers\rust.py`
- **Line:** 163
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1894. PY-QUAL-004

- **File:** `janitor\analyzers\rust.py`
- **Line:** 358
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1895. PY-QUAL-004

- **File:** `janitor\analyzers\rust.py`
- **Line:** 373
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1896. PY-QUAL-004

- **File:** `janitor\analyzers\rust.py`
- **Line:** 388
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1897. PY-QUAL-004

- **File:** `janitor\analyzers\rust.py`
- **Line:** 403
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1898. PY-QUAL-004

- **File:** `janitor\analyzers\rust.py`
- **Line:** 418
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1899. PY-QUAL-004

- **File:** `janitor\analyzers\rust.py`
- **Line:** 640
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1900. PY-QUAL-004

- **File:** `janitor\analyzers\rust.py`
- **Line:** 655
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1901. PY-QUAL-004

- **File:** `janitor\analyzers\rust.py`
- **Line:** 670
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1902. PY-QUAL-004

- **File:** `janitor\analyzers\rust.py`
- **Line:** 759
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1903. PY-QUAL-004

- **File:** `janitor\analyzers\rust.py`
- **Line:** 774
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1904. PY-QUAL-004

- **File:** `janitor\analyzers\rust.py`
- **Line:** 789
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1905. PY-QUAL-004

- **File:** `janitor\analyzers\rust.py`
- **Line:** 804
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1906. PY-QUAL-004

- **File:** `janitor\analyzers\rust.py`
- **Line:** 1168
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1907. PY-QUAL-004

- **File:** `janitor\analyzers\rust.py`
- **Line:** 1178
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1908. PY-QUAL-004

- **File:** `janitor\analyzers\rust.py`
- **Line:** 1185
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1909. PY-QUAL-004

- **File:** `janitor\analyzers\rust.py`
- **Line:** 1191
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1910. PY-QUAL-004

- **File:** `janitor\analyzers\rust.py`
- **Line:** 1198
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1911. PY-QUAL-004

- **File:** `janitor\analyzers\rust.py`
- **Line:** 1204
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1912. PY-QUAL-004

- **File:** `janitor\analyzers\rust.py`
- **Line:** 1209
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1913. PY-QUAL-004

- **File:** `janitor\analyzers\rust.py`
- **Line:** 1215
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1914. PY-DOC-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 1236
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1915. PY-QUAL-004

- **File:** `janitor\analyzers\rust.py`
- **Line:** 1284
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1916. PY-MAGIC-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 1285
- **Risk:** LOW
- **Message:** [Magic Number Used] Hardcoded numeric literals should be named constants

**Suggestion:** Define magic numbers as named constants with descriptive names

### 1917. PY-DOC-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 1302
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1918. PY-DOC-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 1370
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1919. PY-DOC-001

- **File:** `janitor\analyzers\rust.py`
- **Line:** 1373
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1920. PY-DOC-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 42
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1921. PY-DOC-001

- **File:** `janitor\analyzers\swift.py`
- **Line:** 45
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1922. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 62
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1923. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 108
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1924. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 110
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1925. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 111
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1926. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 112
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1927. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 114
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1928. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 115
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1929. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 116
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1930. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 117
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1931. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 119
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1932. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 120
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1933. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 121
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1934. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 124
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1935. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 125
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1936. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 127
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1937. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 128
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1938. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 129
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1939. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 130
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1940. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 132
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1941. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 133
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1942. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 290
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1943. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 324
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1944. PY-LOG-002

- **File:** `janitor\analyzers\swift.py`
- **Line:** 869
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1945. PY-LOG-002

- **File:** `janitor\analyzers\swift.py`
- **Line:** 878
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 1946. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 944
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1947. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 972
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1948. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 973
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1949. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 975
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1950. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 979
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1951. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 986
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1952. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 987
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1953. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 988
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1954. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 989
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1955. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 1113
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1956. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 1114
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1957. PY-QUAL-004

- **File:** `janitor\analyzers\swift.py`
- **Line:** 1115
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1958. PY-DOC-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 40
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1959. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 41
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1960. PY-DOC-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 43
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 1961. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 61
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1962. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 258
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1963. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 378
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1964. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 418
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1965. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 426
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1966. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 449
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1967. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 465
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1968. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 481
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1969. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 497
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1970. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 529
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1971. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 585
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1972. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 744
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1973. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 872
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1974. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 880
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1975. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 888
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1976. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 927
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1977. PY-COMM-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 962
- **Risk:** LOW
- **Message:** [TODO Comment in Code] TODO comments may indicate incomplete security work

**Suggestion:** Address TODO/FIXME items before production deployment

### 1978. PY-COMM-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 967
- **Risk:** LOW
- **Message:** [TODO Comment in Code] TODO comments may indicate incomplete security work

**Suggestion:** Address TODO/FIXME items before production deployment

### 1979. PY-COMM-001

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 983
- **Risk:** LOW
- **Message:** [TODO Comment in Code] TODO comments may indicate incomplete security work

**Suggestion:** Address TODO/FIXME items before production deployment

### 1980. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1031
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1981. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1109
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1982. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1111
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1983. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1112
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1984. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1113
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1985. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1141
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1986. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1290
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1987. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1306
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1988. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1354
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1989. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1360
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1990. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1385
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1991. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1393
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1992. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1399
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1993. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1405
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1994. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1411
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1995. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1443
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1996. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1459
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1997. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1465
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1998. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1473
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 1999. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1475
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2000. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1481
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2001. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1499
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2002. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1523
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2003. PY-QUAL-004

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1541
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2004. PY-QUAL-005

- **File:** `janitor\analyzers\typescript.py`
- **Line:** 1574
- **Risk:** LOW
- **Message:** [Hardcoded localhost/127.0.0.1] Hardcoded localhost addresses may indicate test/debug code

**Suggestion:** Use environment variables or configuration for host addresses

### 2005. PY-QUAL-004

- **File:** `janitor\analyzers\__init__.py`
- **Line:** 52
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2006. PY-QUAL-004

- **File:** `janitor\analyzers\__init__.py`
- **Line:** 53
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2007. PY-QUAL-004

- **File:** `janitor\legacy\js_analyzer.py`
- **Line:** 36
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2008. PY-QUAL-004

- **File:** `janitor\legacy\js_analyzer.py`
- **Line:** 37
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2009. PY-QUAL-004

- **File:** `janitor\legacy\js_analyzer.py`
- **Line:** 38
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2010. PY-QUAL-004

- **File:** `janitor\legacy\js_analyzer.py`
- **Line:** 39
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2011. PY-QUAL-004

- **File:** `janitor\legacy\js_analyzer.py`
- **Line:** 45
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2012. PY-DOC-001

- **File:** `janitor\legacy\js_analyzer.py`
- **Line:** 48
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 2013. PY-QUAL-004

- **File:** `janitor\legacy\js_analyzer.py`
- **Line:** 77
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2014. PY-DOC-001

- **File:** `janitor\legacy\manager.py`
- **Line:** 98
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 2015. PY-DOC-001

- **File:** `janitor\legacy\manager.py`
- **Line:** 122
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 2016. PY-DOC-001

- **File:** `janitor\legacy\manager.py`
- **Line:** 138
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 2017. PY-QUAL-004

- **File:** `janitor\legacy\manager.py`
- **Line:** 189
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2018. PY-DOC-001

- **File:** `janitor\legacy\manager.py`
- **Line:** 256
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 2019. PY-DOC-001

- **File:** `janitor\outputs\html_report.py`
- **Line:** 9
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 2020. PY-DOC-001

- **File:** `janitor\outputs\html_report.py`
- **Line:** 18
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 2021. PY-DOC-001

- **File:** `janitor\outputs\html_report.py`
- **Line:** 41
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 2022. PY-DOC-001

- **File:** `janitor\outputs\html_report.py`
- **Line:** 45
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 2023. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 48
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2024. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 49
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2025. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 54
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2026. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 56
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2027. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 57
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2028. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 69
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2029. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 70
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2030. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 71
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2031. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 76
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2032. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 77
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2033. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 78
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2034. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 79
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2035. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 80
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2036. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 82
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2037. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 85
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2038. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 86
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2039. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 87
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2040. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 88
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2041. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 89
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2042. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 90
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2043. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 195
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2044. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 196
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2045. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 204
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2046. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 209
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2047. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 224
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2048. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 225
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2049. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 228
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2050. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 240
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2051. PY-QUAL-004

- **File:** `janitor\outputs\html_report.py`
- **Line:** 303
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2052. PY-QUAL-004

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 8
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2053. PY-DOC-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 11
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 2054. PY-DOC-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 16
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 2055. PY-DOC-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 20
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 2056. PY-DOC-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 25
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 2057. PY-DOC-001

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 30
- **Risk:** LOW
- **Message:** [Missing Docstring] Functions and classes should have docstrings for understanding

**Suggestion:** Add docstrings explaining purpose, parameters, and return values

### 2058. PY-LOG-002

- **File:** `janitor\tests\example_vulnerable.py`
- **Line:** 40
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 2059. PY-LOG-002

- **File:** `janitor\tests\test_analyzer.py`
- **Line:** 49
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 2060. PY-LOG-002

- **File:** `janitor\tests\test_manager.py`
- **Line:** 25
- **Risk:** LOW
- **Message:** [print() Statement in Production Code] print() statements can leak sensitive data to stdout

**Suggestion:** Use logging module instead of print()

### 2061. PY-QUAL-004

- **File:** `janitor\tests\test_scanner.py`
- **Line:** 58
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2062. PY-QUAL-004

- **File:** `janitor\tests\test_scanner.py`
- **Line:** 67
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2063. PY-QUAL-004

- **File:** `janitor\tests\test_scanner.py`
- **Line:** 98
- **Risk:** LOW
- **Message:** [Duplicate String Literal] Repeated string literals should be named constants

**Suggestion:** Extract repeated strings as module-level constants

### 2064. PY-QUAL-004

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
