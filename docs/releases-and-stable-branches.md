# Releases and Stable Branches

Major, minor, and patch releases follow the version format `X.Y.Z`:

- Increment **X** for major releases.
- Increment **Y** for minor releases.
- Increment **Z** for patch releases.

## Versions and Stable branches

| LTS Branch | Latest Stable Release |
|------------|-----------------------|
| v0.3-stable | v0.3.0                |

## Branching strategy

Since this repository is under active development, one or two stable branches are maintained for the LTS versions.

LTS versions are chosen based on their stability and long-term support requirements.

New development happens in the main branch. Tags are created from this branch as needed to mark releases. When an LTS version is chosen from a specific release, a corresponding stable branch is created. All patch releases for that minor release are published from that stable branch. The main branch continues to be the development branch for new features and bug fixes.

The following example illustrates the branching strategy:

```
  |-- main (development branch for new features and bug fixes until the next release is cut)
  |
  |-- commit tag "v0.3.0" release
  |     | branch v0.3-stable (stable branch for 0.3 fixes and patches)
  |     |
  |     |-- commit fixes into v0.3-stable for 0.3.1
  |     |-- tag v0.3.1 (from v0.3-stable)
  |     |
  |     |
  |     |-- commit fixes into v0.3-stable for 0.3.2
  |     |-- tag v0.3.2 (from v0.3-stable)
  |     |-- ...
  |
  |-- main development continues for next release
  |-- commit tag "v1.0.0" release
  |
  |-- main development continues for next release
  |-- commit tag "v1.1.0" release
  |     |
  |     | If v1.1.0 is chosen as the next LTS release, then a stable branch is created for it and all patch releases for v1.1 are published from that stable branch.
  |     |-- branch v1.1-stable (stable branch for 1.1 fixes and patches)
  |     |
  |     |-- commit fixes into v1.1-stable for 1.1.1
  |     |-- tag v1.1.1 (from v1.1-stable)
  |     |...
  |
  |
  |-- main development continues for next release
  |-- commit tag "v1.2.0" release
  |     |
  |     | If v1.2.0 is chosen as the next LTS release, then a stable branch is created for it and all patch releases for v1.2 are published from that stable branch.
  |     |-- branch v1.2-stable (stable branch for 1.2 fixes and patches)
  |     |
  |     |-- commit fixes into v1.2-stable for 1.2.1
  |     |-- tag v1.2.1 (from v1.2-stable)
  |     |...
```

## Backporting fixes

Backporting is the process of taking a fix that was made in the main branch and applying it to a stable branch.
This is typically done for bug fixes, but can also be done for other types of changes if they meet the backport criteria outlined below.

- Backport if it fixes a customer-related issue.
- Backport if it improves the stability of an existing stable branch.
- Backport only if it does not break customers or stable branches.

## How to backport a fix

The process of backporting a fix involves the following steps:

- After a fix is merged into the main branch, determine if it meets the backport criteria outlined above.

- If it does, create a new PR that cherry-picks the commit(s) from the main branch into the appropriate stable branch, or do it manually.

- Mark the commits as backports and reference the upstream commits in the commit message of the backports.

- Once the backport PR is created, it should be reviewed and approved by the team before being merged into the stable branch.
