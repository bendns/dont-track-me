---
name: review
description: Review code for bugs and security issues
---

# Code Review Skill

When reviewing code:
1. Check for security vulnerabilities (command injection, path traversal, unsafe subprocess calls)
2. Look for performance issues
3. Verify error handling (narrow exceptions, no bare `except`)
4. Check pattern consistency with sibling modules
5. Verify ruff compliance and test coverage
