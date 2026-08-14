# Contributing to PolicyApprovalGate

[English](CONTRIBUTING.md) | [日本語](CONTRIBUTING.ja.md)

Thank you for contributing. Issues, pull requests, and commit messages are written in English so they remain accessible to the whole project community.

Security-sensitive bypasses must not be reported in a public issue. See [Reporting security issues](#reporting-security-issues) before sharing a reproduction.

## Development setup

PolicyApprovalGate requires Go 1.26, as declared in [`go.mod`](go.mod). Clone the repository, then verify the checkout:

```bash
go mod download
go build ./...
go test ./...
```

The project uses `golangci-lint`; install a version compatible with [the CI configuration](.github/workflows/ci.yml), or run the same version through your preferred isolated tool setup.

## Before opening a pull request

Run the full local checks:

```bash
gofmt -w .
go mod tidy -diff
go vet ./...
go test -race ./...
golangci-lint run ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
go build ./...
```

`gofmt -w .` changes files; review its diff before committing. Add or update focused tests for behavior changes. Keep `README.md` and `README.ja.md` semantically synchronized when user-facing behavior or documentation changes.

### Windows notes

- The repository enforces LF line endings through `.gitattributes`. An older checkout may need `git add --renormalize .` before formatting checks pass.
- `go test -race` requires CGO and a supported C compiler. If the local Windows environment has no compiler, run `go test ./...` and rely on the Linux CI race job.
- Windows Defender Application Control may block temporary executables used by tests in `internal/gitpush`.
- Tests that create symbolic links may require Developer Mode or an elevated shell on Windows.
- Keep PowerShell 5.1-compatible scripts ASCII-only because BOM-less UTF-8 may otherwise be decoded using a legacy code page.
- Do not hard-code platform-specific quoting in assertions. Test the intended property, or expose OS-dependent decisions so both branches can be tested.

## Commits and pull requests

Use [Conventional Commits](https://www.conventionalcommits.org/) for commit subjects, for example `fix: reject an escaped destructive command` or `docs: clarify Windows test requirements`.

Keep each pull request focused on one problem. Before submitting it:

1. Link the relevant issue, or explain why no issue is needed.
2. Describe the behavior before and after the change.
3. Add regression tests for fixes and unit tests for new behavior.
4. Run the checks above and report any check that could not be run locally.
5. Update both READMEs and examples when the public behavior changes.

Maintainers first review the scope and security impact, then the implementation, tests, cross-platform behavior, and documentation. Address review comments with additional commits; maintainers may squash when merging.

## Proposing a rule

Use the rule-proposal issue form before opening a pull request. A deny or ask rule proposal must include:

- the exact command or command family it targets and why it is dangerous;
- the proposed regular expression or matching approach;
- the applicable dialect: POSIX shell, PowerShell, or both;
- positive tests that must match; and
- realistic safe commands that could be false positives and must not match.

A proposal without false-positive examples is incomplete. Prefer the narrowest rule that captures the security property. Do not broaden a rule merely to catch visually similar commands.

## Reporting security issues

If a bypass could have real security impact, follow [SECURITY.md](SECURITY.md) and report it privately through a GitHub Security Advisory. Do not publish the bypass command, sensitive paths, credentials, or exploit details in an issue. If you are unsure whether a report is sensitive, use the private route.

The public bypass form is only for non-sensitive classification gaps that are safe to disclose.

## Adding fuzz seeds

The fuzz targets are `FuzzParseDoesNotPanic`, `FuzzClassifyDoesNotPanic`, and `FuzzCheckDoesNotPanic`. For a small, readable regression input, add an `f.Add(...)` seed to the closest target and add a named unit test when a specific decision must be preserved.

For a corpus file produced by `go test -fuzz`, place the minimized file under the matching package's `testdata/fuzz/<FuzzTarget>/` directory. Keep only minimal, non-sensitive inputs, and verify it with:

```bash
go test ./internal/shellparse -run=FuzzParseDoesNotPanic
go test ./internal/pathpolicy -run=FuzzClassifyDoesNotPanic
go test ./internal/gitpush -run=FuzzCheckDoesNotPanic
```

Never add credentials, private paths, or unreviewed production commands to the corpus.

## Releases

Maintainers use [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) as the publication gate. Contributions do not need to complete the release-only host and distribution checks.
