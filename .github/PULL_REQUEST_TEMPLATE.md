## What and why

<!-- What does this change, and which catastrophe, false positive or bug does it address? Link the issue. -->

## Checklist

- [ ] `npm run build` and `npm test` pass
- [ ] New detections come with catastrophic/destructive tests **and** harmless (false-positive) tests
- [ ] No `bypass*` test or corpus entry was weakened
- [ ] The guard still fails closed on every new error path
- [ ] Docs updated (`docs/policy.md` catalog list, README, CHANGELOG)
