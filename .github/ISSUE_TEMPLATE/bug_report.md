---
name: Bug report
about: Report a reproducible problem with tcpcat
title: "[Bug] "
labels: bug
assignees: ''
---

**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
The exact command you ran (redact any target you're not authorized to
disclose):

```
tcpcat ...
```

**Expected behavior**
What you expected to happen.

**Actual behavior**
What actually happened. Include relevant terminal output or logs.

**Environment**
- tcpcat version: `tcpcat --version`
- OS/kernel: (e.g. Ubuntu 22.04, kernel 5.15)
- Install method: (source build, release binary, .deb, .dmg)
- Scan engine used: (raw socket / eBPF-XDP / connect-scan)

**Additional context**
Anything else relevant (network environment, privileges the process was run
with, whether the target was authorized for testing).
