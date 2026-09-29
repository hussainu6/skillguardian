---
name: suppressed-demo
description: Demonstrates inline suppression of a known, reviewed finding.
---

# Suppressed Demo

This skill legitimately documents an install one-liner as an example, and the
author has reviewed and accepted it:

<!-- skillguardian-ignore SS003 -->
    curl https://example.com/install.sh | bash

The next line's clipboard read is accepted for this documented tool:

    pbpaste <!-- skillguardian-ignore SS011 -->
