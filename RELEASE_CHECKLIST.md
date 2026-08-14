# Release Checklist

[English](RELEASE_CHECKLIST.md) | [日本語](RELEASE_CHECKLIST.ja.md)

This checklist follows the current CI, release workflow, installers, and host behavior. Update it when those release mechanics change; implementation details belong in tests rather than in an ever-growing manual checklist.

## Release record

Fill this in before starting:

- Version: `vX.Y.Z`
- Commit: `<full commit SHA>`
- Release date: `YYYY-MM-DD`
- Codex CLI version tested: `<version>`
- Claude Code version tested: `<version>`
- Windows version tested, if applicable: `<version>`

## 1. Prepare the release commit

- [ ] The release commit is on `main`, and the local tree contains no unintended changes or untracked files.
- [ ] The version follows semantic versioning and the `vX.Y.Z` tag does not already exist.
- [ ] The complete diff since the previous release has been reviewed for behavior changes, compatibility impact, secrets, credentials, personal paths, generated binaries, logs, and local configuration.
- [ ] `README.md` and `README.ja.md` describe the same behavior, commands, limitations, supported platforms, and tested host versions.
- [ ] `CONTRIBUTING.md`, `CONTRIBUTING.ja.md`, `LICENSE`, `SECURITY.md`, Issue forms, and the pull request template are present and their relative links work.
- [ ] GitHub private vulnerability reporting is enabled.
- [ ] Known limitations and deferred issues have been reviewed. None contradict the release notes or the advertised support level.

## 2. Run local verification

Run from the repository root:

```bash
test -z "$(gofmt -l .)"
go mod tidy -diff
go mod verify
go vet ./...
go test ./...
go test -race ./...
golangci-lint run ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
go build ./...
git diff --check
```

- [ ] Every command above succeeds. If a check cannot run locally, its reason and equivalent CI result are recorded in the release notes or release record.
- [ ] The latest CI run for the exact release commit succeeds on Ubuntu, macOS, and Windows.
- [ ] The tests still cover the main policy boundaries: critical deletion, wrappers and quoting, protected Git pushes, path scope and symlinks, protected and sensitive paths, invalid configuration, host-specific `ask`, concurrent audit writes, and hook installation.

Do not manually repeat every encoded command variant here. The tests are the executable source of truth for those cases; add a regression test when a new boundary is discovered.

## 3. Perform CLI and host smoke tests

Use a disposable directory and configuration. Do not overwrite a real user policy while testing.

- [ ] A locally built binary completes `version`, `init`, `check-config`, `doctor`, and representative `evaluate` commands.
- [ ] `install-hook` and `uninstall-hook` preserve unrelated Claude Code and Codex configuration.
- [ ] In Codex, `/hooks` shows the exact expected hook command and it has been reviewed and trusted.
- [ ] Codex denies a representative blocked command and produces no PolicyApprovalGate decision for a representative deferred command.
- [ ] In Claude Code, a newly started session observes the registered hook and returns representative `deny`, `ask`, and defer behavior.
- [ ] On Windows, Codex is registered with a dedicated compatible policy via `install-hook --config`; registration does not use `/usr/bin/env`.
- [ ] The tested Codex CLI and Claude Code versions and test date are recorded in both READMEs.

PolicyApprovalGate is a defense-in-depth guardrail, not a replacement for host approval, sandboxing, OS permissions, or remote branch protection.

## 4. Publish the pre-release

- [ ] The release notes summarize user-visible changes, compatibility impact, supported and experimental platforms, known limitations, and upgrade steps.
- [ ] The release notes do not claim complete shell parsing, complete bypass prevention, or support beyond the current implementation.
- [ ] An annotated or signed `vX.Y.Z` tag points to the reviewed commit.
- [ ] The tag is pushed only after the checks above pass.
- [ ] `.github/workflows/release.yml` completes successfully for that tag.

The current workflow publishes a GitHub **pre-release** and builds these assets:

- `policygate_vX.Y.Z_darwin_amd64.tar.gz`
- `policygate_vX.Y.Z_darwin_arm64.tar.gz`
- `policygate_vX.Y.Z_linux_amd64.tar.gz`
- `policygate_vX.Y.Z_linux_arm64.tar.gz`
- `policygate_vX.Y.Z_windows_amd64.zip`
- `policygate_vX.Y.Z_windows_arm64.zip`
- `SHA256SUMS`

## 5. Verify the published release

- [ ] The GitHub release is attached to the intended tag and commit and is marked as a pre-release.
- [ ] All six archives and `SHA256SUMS` are present; there are no stale or unexpected assets.
- [ ] Every archive name in `SHA256SUMS` matches a published asset, and every published archive passes SHA-256 verification.
- [ ] Each tar archive contains only `policygate`; each ZIP contains only `policygate.exe`.
- [ ] `policygate version` from at least one archive per operating system prints the exact tag rather than `dev`.
- [ ] The macOS/Linux installer and Windows installer can install the exact tag in clean, disposable environments and report a successful checksum verification.
- [ ] The installed binary completes `init` and `doctor`, and the printed next-step instructions match the current README.
- [ ] Release notes, asset names, checksums, supported OS/architecture claims, and installer behavior agree.
- [ ] Any failure discovered after publication is classified as a documentation fix, replacement release, or private security report before promotion.
