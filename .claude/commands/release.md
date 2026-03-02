# Release

Automate version bumps, changelog updates, and release tagging for zkemail.nr.

## Steps

### 1. Audit current versions

Read and report the current version state:

- `js/package.json` → current npm version
- Latest git tag (`git tag --sort=-creatordate | head -1`)
- `README.md` → Nargo.toml tag example
- `CHANGELOG.md` → latest entry

Report any inconsistencies between these sources.

### 2. Ask for release details

Use AskUserQuestion to gather:

**Change type:**
- `patch` — bug fix, no breaking changes
- `minor` — new feature, backwards compatible
- `major` — breaking change (verifier key regeneration, API changes)

**Change description:** Brief summary for the changelog entry.

**Breaking changes?** If major, or if user confirms breaking: ask for migration notes (e.g., "Verifier keys must be regenerated").

### 3. Compute new version

Parse the current version from `js/package.json` and bump according to the change type:
- patch: `1.4.0` → `1.4.1`
- minor: `1.4.0` → `1.5.0`
- major: `1.4.0` → `2.0.0`

The git tag will be `v{new_version}` (e.g., `v1.4.1`). This aligns npm and git tag versions.

### 4. Apply changes

**4a. Update `js/package.json`**

Change the `"version"` field to the new version.

**4b. Prepend to `CHANGELOG.md`**

Add a new entry at the top (below the header), following Keep a Changelog format:

```markdown
## [{version}] - {YYYY-MM-DD}

### {Section}

- {description}
```

Sections: Added, Changed, Fixed, Removed, Breaking Changes.

If there are breaking changes, add a `### Breaking Changes` section with migration notes.

Update the comparison links at the bottom of the file.

**4c. Update `README.md`**

Find the Nargo.toml dependency example and update the tag:

```toml
zkemail = { tag = "v{new_version}", git = "https://github.com/zkemail/zkemail.nr", directory = "lib" }
```

### 5. Create commit and tag

Stage the changed files and create a commit:

```
chore: release v{new_version}
```

Then create an annotated git tag:

```bash
git tag -a v{new_version} -m "v{new_version}"
```

### 6. Post-release reminders

Print the following:

```
Release v{new_version} committed and tagged locally.

Next steps:
  1. Push the branch and tag:
     git push origin {branch} --tags

  2. Publish to npm:
     cd js && yarn publish

  3. Create a GitHub release:
     gh release create v{new_version} --title "v{new_version}" --notes-file <(sed -n '/## \[{version}\]/,/## \[/{{ /## \[{version}\]/d; /## \[/d; p; }}' CHANGELOG.md)
```
