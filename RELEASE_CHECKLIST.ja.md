# リリースチェックリスト

[English](RELEASE_CHECKLIST.md) | [日本語](RELEASE_CHECKLIST.ja.md)

このチェックリストは、現在のCI、リリースworkflow、installer、ホストの挙動に合わせています。リリース方法を変更した場合はこの文書も更新してください。実装の細かな条件は手作業の一覧を増やすのではなく、テストで管理します。

## リリース記録

作業前に記入します。

- バージョン: `vX.Y.Z`
- commit: `<完全なcommit SHA>`
- リリース日: `YYYY-MM-DD`
- 確認したCodex CLIバージョン: `<version>`
- 確認したClaude Codeバージョン: `<version>`
- 確認したWindowsバージョン（該当する場合）: `<version>`

## 1. リリースcommitの準備

- [ ] リリース対象のcommitが`main`にあり、ローカルツリーに意図しない変更や未追跡ファイルがない。
- [ ] バージョンがSemantic Versioningに従い、同じ`vX.Y.Z`タグがまだ存在しない。
- [ ] 前回リリースからの全差分について、挙動、互換性、secret、認証情報、個人パス、生成バイナリ、ログ、ローカル設定を確認した。
- [ ] `README.md`と`README.ja.md`で、挙動、コマンド、制限、対応環境、確認済みホストバージョンが一致している。
- [ ] `CONTRIBUTING.md`、`CONTRIBUTING.ja.md`、`LICENSE`、`SECURITY.md`、Issue Form、Pull Requestテンプレートが存在し、相対リンクが機能する。
- [ ] GitHubのPrivate vulnerability reportingが有効になっている。
- [ ] 既知の制限と延期中のIssueを確認し、release notesやサポート範囲の説明と矛盾していない。

## 2. ローカル検証

リポジトリのルートで実行します。

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

- [ ] 上記の全コマンドが成功する。ローカルで実行できない項目がある場合は、理由と対応するCI結果をrelease notesまたはリリース記録に残す。
- [ ] リリース対象commitに対する最新CIがUbuntu、macOS、Windowsですべて成功している。
- [ ] 致命的な削除、wrapperと引用符、保護branchへのpush、パス範囲とsymlink、保護・機微パス、不正な設定、ホスト別の`ask`、監査ログの並行書き込み、hook登録がテストで引き続き網羅されている。

ここで個々のコマンド表記を手作業で再確認する必要はありません。テストをこれらの境界の正とし、新しい境界が見つかった場合はregression testを追加します。

## 3. CLIと実ホストのsmoke test

使い捨てのディレクトリと設定を使い、実際に利用中のpolicyを上書きしないようにします。

- [ ] ローカルbuildしたバイナリで`version`、`init`、`check-config`、`doctor`、代表的な`evaluate`が完了する。
- [ ] `install-hook`と`uninstall-hook`が、Claude CodeとCodexの無関係な設定を保持する。
- [ ] Codexの`/hooks`に意図したhookコマンドが表示され、内容を確認してtrustした。
- [ ] Codexで代表的な拒否対象がdenyされ、代表的なdefer対象ではPolicyApprovalGateの判定が返らない。
- [ ] Claude Codeを新しいsessionで起動し、登録したhookで代表的なdeny、ask、deferの挙動を確認した。
- [ ] WindowsのCodexでは、専用の互換設定を`install-hook --config`で登録し、`/usr/bin/env`を使っていない。
- [ ] 確認したCodex CLI / Claude Codeのバージョンと日付を両READMEへ記録した。

PolicyApprovalGateは多層防御のための補助的なguardrailです。ホストの承認、sandbox、OS権限、remote branch protectionの代替ではありません。

## 4. pre-releaseの公開

- [ ] release notesに、利用者に影響する変更、互換性への影響、通常・実験的サポート対象、既知の制限、更新手順を記載した。
- [ ] release notesで、shellの完全な解析、すべてのbypass防止、実装を超えるサポートを主張していない。
- [ ] annotatedまたは署名付きの`vX.Y.Z`タグが、確認済みcommitを指している。
- [ ] 上記の確認がすべて終わってからタグをpushする。
- [ ] タグに対する`.github/workflows/release.yml`が成功した。

現在のworkflowはGitHub **pre-release**を作成し、次のassetを公開します。

- `policygate_vX.Y.Z_darwin_amd64.tar.gz`
- `policygate_vX.Y.Z_darwin_arm64.tar.gz`
- `policygate_vX.Y.Z_linux_amd64.tar.gz`
- `policygate_vX.Y.Z_linux_arm64.tar.gz`
- `policygate_vX.Y.Z_windows_amd64.zip`
- `policygate_vX.Y.Z_windows_arm64.zip`
- `SHA256SUMS`

## 5. 公開物の確認

- [ ] GitHub Releaseが意図したtagとcommitに紐付き、pre-releaseになっている。
- [ ] 6個のarchiveと`SHA256SUMS`があり、古いassetや想定外のassetが混ざっていない。
- [ ] `SHA256SUMS`内の全archive名が公開assetと一致し、すべてSHA-256検証に成功する。
- [ ] tar archiveには`policygate`だけ、ZIPには`policygate.exe`だけが含まれている。
- [ ] OSごとに最低1つのarchiveを確認し、`policygate version`が`dev`ではなく正確なtagを表示する。
- [ ] macOS / Linux installerとWindows installerが、クリーンな使い捨て環境で指定tagをinstallでき、checksum検証の成功を表示する。
- [ ] installしたバイナリで`init`と`doctor`が完了し、表示される次の手順が現在のREADMEと一致する。
- [ ] release notes、asset名、checksum、対応OS / architecture、installerの挙動が一致する。
- [ ] 公開後に問題が見つかった場合、告知前にdocumentation修正、差し替えrelease、非公開security reportのいずれとして扱うか判断する。
