## Summary

Briefly describe what this PR changes and why.

Example:
- Adds SSH hardening check
- Improves CLI output formatting
- Fixes scoring bug in LAN scan

---

## Type of Change

- [ ] Bug fix
- [ ] New check
- [ ] CLI / UI improvement
- [ ] Refactor (no functional change)
- [ ] Documentation update
- [ ] Other (please describe)

---

## What Problem Does This Solve?

Explain the issue or limitation this PR addresses.

If applicable, link to an issue:

Closes #___

---

## Implementation Details

Describe how this was implemented at a high level.

- New files added:
- Existing files modified:
- Any breaking changes:

---

## Testing

How was this tested?

- [ ] Tested in API mode
- [ ] Tested in local mode
- [ ] Tested on Windows
- [ ] Tested on Linux
- [ ] JSON output verified
- [ ] No sensitive data logged

If relevant, include example output (remove passwords, tokens, and private IPs).

---

## Security Considerations

- Does this introduce any new network calls?
- Does this log sensitive information?
- Does it change scoring logic?

Please briefly confirm this PR does not introduce credential leaks or unsafe defaults.

LabSentinel must remain read-only and safe to run in production home labs.

---

## Screenshots / Example Output (Optional)

If this changes CLI output, include a short example.

---

## Contributor Checklist

- [ ] I followed the existing code style.
- [ ] I avoided introducing unnecessary dependencies.
- [ ] I kept the changes focused and minimal.
- [ ] I removed any sensitive information from examples.
