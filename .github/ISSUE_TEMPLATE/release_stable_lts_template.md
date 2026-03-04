---
name: stable and LTS release Workflow
about: Checklist to follow for stable and LTS releases
title: "release: vX.Y.Z stable release from vX.Y-stable branch"
labels: [release]
assignees: []
---

## Release: vX.Y.Z

Replace `X.Y.Z` with the actual version being released throughout this issue.

Example: `v0.3.1` stable release from `v0.3-stable` branch.

### Trigger

> Patch releases (`X.Y.Z` where `Z > 0`) do **not** require a new stable branch.

> Patches are tagged directly from the existing `vX.Y-stable` branch.

> LTS versions are chosen based on their stability and long-term support requirements.

### Checklist

- [ ] Create a stable branch `vX.Y-stable` from the chosen tag. This may already have been performed if the stable branch was created at the time of the release. If so, then skip this step.

```bash
# v1.1.0 as an LTS base
export RELEASE=v1.1.0
export STABLE_BRANCH=v1.1-stable
git checkout -b $STABLE_BRANCH $RELEASE
git push origin $STABLE_BRANCH
```

- [ ] Add `vX.Y-stable` to the _Versions and Stable branches_ list in [Releases and Stable Branches doc](docs/releases-and-stable-branches.md) in main branch. Remove from the documentation unused stable branches. This may already have been performed if the stable branch was created at the time of the release.

- [ ] Backport the necessary fixes, and update the documentation to reference the stable release tag `vX.Y.Z` under the corresponding stable branch `vX.Y-stable` in the _Versions and Stable branches_ list in [Releases and Stable Branches doc](docs/releases-and-stable-branches.md).

```bash
export STABLE_RELEASE=v1.1.1
export STABLE_BRANCH=v1.1-stable
git checkout $STABLE_BRANCH
git checkout -b backports/$STABLE_RELEASE
# Backport PRs
# Update documentation docs/releases-and-stable-branches.md with the new $STABLE_RELEASE.
# merge PRs into $STABLE_BRANCH for the $STABLE_RELEASE
```

- [ ] Tag directly from the existing `vX.Y-stable` branch that was created previously and push the tag to the repository.

```bash
export STABLE_RELEASE=v1.1.1
export STABLE_BRANCH=v1.1-stable
git checkout $STABLE_BRANCH
git pull
# git tag $STABLE_RELEASE
# or
# git tag -a $STABLE_RELEASE -m "$STABLE_RELEASE release"
git push origin $STABLE_RELEASE
```

- [ ] Verify the new release tag and stable branch are visible and properly tracked in the repository.

### Notes

- Current stable branch at time of writing: `v0.3-stable`.
- All backports to stable branches must follow the criteria in `docs/releases-and-stable-branches.md`.
