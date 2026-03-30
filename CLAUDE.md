# prisma-ra-tls Development Guide

## Commit Requirements

**No AI attribution in commit messages.**

Do not include `Co-Authored-By: Claude` or any other AI attribution lines in commits.
AI tools may be used to assist with development, but all commits must be authored by the
human developer. A pre-push hook enforces this — see `.git/hooks/pre-push`.

New clones must install the hook manually:
```bash
cp -f hooks/pre-push .git/hooks/pre-push
chmod +x .git/hooks/pre-push
```

All commits must be GPG-signed:
```bash
git config commit.gpgsign true
git config user.signingkey EC13425E92A56C29
```

## Test Commands

```bash
npm test
npm run test:coverage   # must stay at 100%
```

## Build Commands

```bash
npm run build
npm run typecheck
```

## Publish Checklist

- [ ] All tests pass at 100% coverage
- [ ] `npm run typecheck` clean
- [ ] All commits GPG-signed with no AI attribution
- [ ] Version bumped in `package.json`
- [ ] `npm publish --access public`
