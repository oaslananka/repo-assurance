## Summary

Describe the repository assurance change and the evidence or behavior it affects.

## Verification

- [ ] `pytest -q`
- [ ] `python -m compileall -q src tests`
- [ ] Control catalogs validate
- [ ] Plugin archive builds when plugin-facing files change

## Safety

- [ ] Audit behavior remains read-only by default
- [ ] Unknown/inaccessible evidence is not converted to PASS
- [ ] Findings remain bound to the exact audited commit
- [ ] Repository/worktree cleanup preserves unique work first
- [ ] No secret values are included in logs, reports, fixtures, or screenshots
