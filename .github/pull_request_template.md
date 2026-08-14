## Summary

Describe the problem and the focused change that solves it.

## Related issue

Closes #

## Behavior and compatibility

- Does this change a default policy decision or classification? If yes, describe the before/after behavior and compatibility impact.
- Does it affect POSIX shell, PowerShell, or both?

## Verification

- [ ] I added or updated tests for the changed behavior, or explained why tests are not needed.
- [ ] `gofmt -w .`
- [ ] `go vet ./...`
- [ ] `go test -race ./...`
- [ ] `golangci-lint run ./...`
- [ ] Other relevant checks are described below.

List any check that could not be run and why.

## Documentation

- [ ] I updated both `README.md` and `README.ja.md` when user-facing behavior changed.
- [ ] I updated configuration examples or other documentation when applicable.
- [ ] No documentation change is needed.

## Security

- [ ] This pull request contains no secrets, credentials, sensitive local paths, or undisclosed security-sensitive bypass details.
