# PolicyApprovalGateへのコントリビューション

[English](CONTRIBUTING.md) | [日本語](CONTRIBUTING.ja.md)

コントリビューションに関心をお寄せいただき、ありがとうございます。プロジェクト全体で情報を共有できるよう、Issue、Pull Request、commit messageは英語で記載してください。

セキュリティ上の影響があるbypassを公開Issueで報告しないでください。再現手順を共有する前に「[セキュリティ問題の報告](#セキュリティ問題の報告)」を確認してください。

## 開発環境の準備

PolicyApprovalGateには[`go.mod`](go.mod)で指定されたGo 1.26が必要です。リポジトリをcloneし、checkoutを確認します。

```bash
go mod download
go build ./...
go test ./...
```

このプロジェクトでは`golangci-lint`を使用します。[CI設定](.github/workflows/ci.yml)と互換性のあるバージョンをinstallするか、任意の分離されたtool環境で同じバージョンを実行してください。

## Pull Requestを作成する前の確認

次のローカル検証をすべて実行します。

```bash
gofmt -w .
go mod tidy -diff
go vet ./...
go test -race ./...
golangci-lint run ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
go build ./...
```

`gofmt -w .`はファイルを変更するため、commit前に差分を確認してください。挙動を変更する場合は、対象を絞ったテストを追加または更新します。利用者向けの挙動や文書を変更する場合は、`README.md`と`README.ja.md`の意味を同期してください。

### Windowsでの注意事項

- `.gitattributes`でLF改行を指定しています。古いcheckoutでは、format checkの前に`git add --renormalize .`が必要な場合があります。
- `go test -race`にはCGOと対応するC compilerが必要です。ローカルのWindows環境にcompilerがない場合は`go test ./...`を実行し、race testはLinux CIの結果を確認してください。
- Windows Defender Application Controlにより、`internal/gitpush`のテストで使う一時実行ファイルがblockされる場合があります。
- symlinkを作成するテストには、WindowsのDeveloper Modeまたは管理者権限が必要な場合があります。
- PowerShell 5.1対応スクリプトはASCIIだけで記述してください。BOMなしUTF-8が古いcode pageで解釈される場合があります。
- テストでプラットフォーム固有の引用符を決め打ちしないでください。意図する性質を検証するか、OS依存の判定を分離して両方の分岐をテストできるようにします。

## CommitとPull Request

Commit subjectには[Conventional Commits](https://www.conventionalcommits.org/)を使用します。例: `fix: reject an escaped destructive command`、`docs: clarify Windows test requirements`

1つのPull Requestでは1つの問題に集中してください。提出前に次を確認します。

1. 関連Issueへlinkするか、Issueが不要な理由を説明する。
2. 変更前後の挙動を説明する。
3. 修正にはregression test、新しい挙動にはunit testを追加する。
4. 上記の検証を実行し、ローカルで実行できなかった項目を報告する。
5. 公開される挙動を変更した場合は、両READMEと設定例を更新する。

メンテナーは最初にscopeとsecurityへの影響を確認し、その後に実装、テスト、cross-platformの挙動、ドキュメントをレビューします。レビュー対応は追加commitで行い、merge時にsquashする場合があります。

## ルールの提案

Pull Requestを作成する前にrule proposal用のIssue Formを使用してください。denyまたはaskルールの提案には次の情報が必要です。

- 対象となる正確なコマンドまたはコマンド群と、その危険性
- 提案する正規表現またはmatching方法
- 対象方言（POSIX shell、PowerShell、または両方）
- 一致すべきpositive test
- 誤検知する可能性があり、一致してはいけない現実的な安全なコマンド

誤検知例がない提案は未完成です。security上の性質を満たす最も限定的なルールを優先してください。見た目が似ているコマンドまで検出するためだけに、ルールを広げないでください。

## セキュリティ問題の報告

bypassに実際のsecurity上の影響がある場合は、[SECURITY.md](SECURITY.md)に従い、GitHub Security Advisoryから非公開で報告してください。bypassコマンド、機微なパス、認証情報、exploitの詳細をIssueで公開しないでください。機微情報に該当するか判断に迷う場合も、非公開経路を使用してください。

公開bypass formは、安全に公開できる機微ではないclassification gapだけを対象とします。

## Fuzz seedの追加

Fuzz targetは`FuzzParseDoesNotPanic`、`FuzzClassifyDoesNotPanic`、`FuzzCheckDoesNotPanic`です。短く読みやすいregression inputは、最も近いtargetへ`f.Add(...)`のseedとして追加します。特定の判定を維持する必要がある場合は、名前付きunit testも追加してください。

`go test -fuzz`が生成したcorpus fileは、対象packageの`testdata/fuzz/<FuzzTarget>/`に配置します。最小化済みで機微情報を含まないinputだけを残し、次のコマンドで確認してください。

```bash
go test ./internal/shellparse -run=FuzzParseDoesNotPanic
go test ./internal/pathpolicy -run=FuzzClassifyDoesNotPanic
go test ./internal/gitpush -run=FuzzCheckDoesNotPanic
```

認証情報、非公開パス、レビューしていない本番コマンドをcorpusへ追加しないでください。

## リリース

メンテナーは[RELEASE_CHECKLIST.ja.md](RELEASE_CHECKLIST.ja.md)を公開判定に使用します。通常のコントリビューションで、実ホストや配布物に関するリリース専用項目を実施する必要はありません。
