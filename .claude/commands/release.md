# Release

Tag and publish a release from main. Run this after merging a PR that used `/bump`.

## Steps

### 1. Verify on main

Check the current branch. If not on `main`, warn the user and ask for confirmation before proceeding.

### 2. Audit current state

Read and report:

- `js/package.json` → current version
- Latest git tag (`git tag --sort=-creatordate | head -1`)
- `CHANGELOG.md` → latest entry

Verify the version in `package.json` is ahead of the latest git tag (i.e., a `/bump` was merged). If not, warn the user that there's nothing new to release.

### 3. Confirm tag creation

Ask the user for confirmation:

> Ready to tag `v{version}` on the current commit. Proceed?

Create an annotated git tag:

```bash
git tag -a v{version} -m "v{version}"
```

### 4. Push tag

Ask the user for confirmation, then push:

```bash
git push origin main --tags
```

### 5. Create GitHub release

Ask the user for confirmation, then create a GitHub release using the changelog entry:

```bash
gh release create v{version} --title "v{version}" --notes "$(sed -n '/## \[{version}\]/,/^## \[/{//!p;}' CHANGELOG.md)"
```

### 6. npm publish reminder

Print:

```
Release v{version} published!

To publish to npm:
  cd js && yarn publish
```

Do not auto-publish to npm — this requires credentials and should be done manually.
