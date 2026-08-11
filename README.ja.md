# PolicyApprovalGate

[English](README.md) | [日本語](README.ja.md)

Claude Code / Codex CLI がBashコマンドを実行する前に、ルールベースのポリシーを適用するPreToolUseフックです。危険なコマンド、保護ブランチへのpush、プロジェクト外や機微なパスへのアクセスを検査し、判定を監査ログへ記録します。

> [!IMPORTANT]
> PolicyApprovalGateは既存の権限管理、サンドボックス、人による確認を補助するツールです。完全なシェル解析器やセキュリティ境界ではなく、単独で最後の防御線になるものではありません。

既定ルールは明確に危険な操作の見落としを減らすためのもので、あらゆるリスクを厳格に遮断することは目指していません。判定できない操作は、既定ではホスト側の通常の承認フローへ委ねます。

## 特長

- AI/LLMを使わない、決定論的なルール判定
- 危険なコマンドを正規表現で拒否
- 特定コマンドをClaude Codeでは確認要求へ回し、Codexではdenyへ変換する正規表現ベースのaskルール
- rootまたは現在ユーザーのhomeに対する再帰的強制削除を構造解析で常時拒否
- 保護ブランチへのforce push、削除、直接pushを制御
- パスアクセスをread / write / deleteへ分類
- プロジェクト外、機微パス、設定ファイルへのアクセスを制御
- `cd` とシンボリックリンクを考慮したパス追跡
- `env` / `command` wrapper、`git -C`、`cp/install -t`の正規化
- 静的に確定できる引用符付きパスと、literalな`sh/bash/zsh -c`・`eval`内の致命的削除を解析
- ローテーション、ハッシュ記録、秘密情報マスクに対応した監査ログ
- 設定スキーマの移行・検証と診断コマンド
- Claude CodeとCodex CLIの判定仕様の差を `--host` で吸収

## 判定の流れ

1. denyルールを確認
2. シェル構文を解析
3. 保護ブランチへのpushを確認
4. askルールを確認（Claude Codeでは確認要求、Codexではdenyへ変換）
5. パス範囲、機微パス、保護パスを確認
6. 各サブコマンドをallowルールで監査分類
7. 一致しなければ `unknown.action` に従う

明示的なdenyが最優先です。既定では不明なコマンドを拒否せず、ホスト側の通常の承認フローへ委ねます。

## 必要環境

- Go 1.26
- Claude CodeまたはCodex CLIのPreToolUse hooks

fixture/goldenテストの互換性基準（2026-08-11時点）：

| ホスト | ローカル確認バージョン |
| --- | --- |
| Codex CLI | 0.147.0 |
| Claude Code | 2.1.220 |

実ホストの仕様変更に備え、入力fixtureと返却JSONのgoldenテストをCIで実行します。

現時点の実行サポート対象はmacOSとLinuxです。WindowsはCIでビルドと単体テストを行いますが、PowerShellツール入力への対応が完了するまでは実験的サポートです。

## クイックスタート

### 1. ビルド

```bash
go build -o policygate ./cmd/policygate
sudo install -m 0755 policygate /usr/local/bin/policygate
```

タグ付きリリース後はGo経由でもインストールできます。`GOBIN`または`GOPATH/bin`に配置された実際の絶対パスをhook設定へ指定してください。

```bash
go install github.com/nobuo-miura/policyapprovalgate/cmd/policygate@latest
```

### 2. 設定ファイルを作成

```bash
policygate init
```

既定では `~/.policygate/config.yaml` を作成します。別の場所を使う場合は `POLICYGATE_CONFIG` を指定してください。既存ファイルは上書きしません。

以前の設定へ新しい既定保護をマージする場合は、次を実行します。

```bash
policygate init --upgrade
policygate check-config
```

`--upgrade`は既存ファイルと同じディレクトリへ`config.yaml.bak.*`を作成してから、原子的に置き換えます。

ユーザー設定のリスト項目（`deny`、`ask`、`allow`、`sensitive_paths.patterns`、`protected_paths.patterns`）は、読み込み時に既定値とマージされず設定側で置き換わります。そのため`--upgrade`は、設定に無い組み込みルールを`pattern`で照合して追記し、追記したルールを警告として一覧表示します。意図的に外していたルールが戻る場合があるので、警告を確認して不要なものは再度削除してください。

### 3. ホストへ登録

#### Claude Code

`.claude/settings.json` に登録します。完全な例は [configs/claude-code.settings.example.json](configs/claude-code.settings.example.json) を参照してください。

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/usr/local/bin/policygate --host claude"
          }
        ]
      }
    ]
  }
}
```

#### Codex CLI

`~/.codex/config.toml` に登録します。完全な例は [configs/codex-config.example.toml](configs/codex-config.example.toml) を参照してください。

```toml
[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/usr/local/bin/policygate --host codex"
```

Codex hooksは既定で有効です。`codex_hooks` は非推奨の別名で、現在の正式な機能キーは `hooks` です。詳細は [Codex Hooks公式ドキュメント](https://learn.chatgpt.com/docs/hooks) を確認してください。

登録後にCodexで`/hooks`を実行し、表示されたコマンド定義をreviewしてtrustしてください。未trustまたは変更後のhookは実行されません。

## ホストごとの判定

| PolicyApprovalGateの判定 | Claude Code | Codex CLI |
| --- | --- | --- |
| `deny` | 拒否 | 拒否 |
| `ask` | ユーザーへ確認 | 単独のaskに未対応のため、`--host codex` ではdenyへ変換 |
| 判定なし | 通常の承認フローへ委譲 | 通常の承認フローへ委譲 |

`--host` を省略した場合も安全側としてClaude以外と扱い、askをdenyへ変換します。Claude Codeで使う場合は必ず `--host claude` を指定してください。

## 設定

組み込み設定の全項目と既定値は [internal/rules/default.yaml](internal/rules/default.yaml) にあります。

| セクション | 用途 |
| --- | --- |
| `config_version` | 設定スキーマのバージョン |
| `mode` | `enforce`または判定だけ記録する`observe` |
| `deny` | コマンド全体をGo RE2正規表現で照合し、拒否 |
| `ask` | 特定コマンドをClaude Codeでは確認要求へ回し、Codexではdenyへ変換（既定は空。git/ghの書き込み系など任意で追加） |
| `allow` | 既知の低リスクコマンドとして監査分類。承認は省略しない |
| `protected_branches` | 保護ブランチへのpushを制御 |
| `path_scope` | プロジェクト外のread / write / deleteを制御 |
| `sensitive_paths` | `.env`、SSH鍵、認証情報などへのアクセスを制御 |
| `protected_paths` | policygate設定やフック登録へのwrite / deleteを常に拒否 |
| `unknown` | どのルールにも一致しない場合の `defer` / `deny` |
| `parse_error` | シェル構文を解析できない場合の `defer` / `deny` |
| `audit` | 保存先、コマンド記録方式、ローテーション設定 |

allowルールは既知の低リスクコマンドを監査上分類するためのもので、ホストの承認を省略しません。`find -exec`、`xargs`、`awk system()`のように引数から別プログラムを起動できるコマンドは、監査分類を誤解させるため追加しないでください。

明示的に指定した設定ファイルが読めない、または不正な場合、`enforce`実行は組み込み既定値へ黙って戻らず、そのBash呼び出しをdenyします。`policygate observe`だけは診断用途のため非ブロッキングを維持します。

## パス判定

`mvdan.cc/sh` でシェル構文を解析し、対応コマンドの引数をread / write / deleteへ分類します。次のケースも考慮します。

- `cd /tmp && rm -rf target` のような先行cd
- プロジェクト内から外部を指す既存シンボリックリンク
- `ln -s /outside escape && ...` のような同一チェーン内のリンク作成
- `ln -s SRC EXISTING_DIR` や `ln -s -t DIR SRC` の実際のリンク配置
- `cp -t DIR SRC`、`install --target-directory=DIR SRC`の書き込み先
- `env`、`command`、`nohup`などの透過wrapper
- スペースを含む引用符付きパス
- 未解決変数や `cd -` を含む確定できないパス
- pipeline、subshell、コマンド置換、バックグラウンド、条件分岐の中で実行される `cd`。この場合、以降のコマンドのCWDを不確定として安全側に判定します
- ディレクトリを変更するループ本体（`for` / `while`）内のコマンド

不確定になるのは`cd`そのものが不確定な位置にある場合だけです。`cat a.txt | grep x > out.txt` のように`cd`を含まないpipelineや分岐は、CWDが確定しているものとして通常どおり判定します。

対象外のコマンドはパスアクセスを生成せず、ほかのルールまたは `unknown.action` へ進みます。

## 監査ログ

既定では `~/.policygate/log/audit.log` へJSON Lines形式で記録します。設定・バックアップと監査ログを分離するため、`log`ディレクトリは新規作成時に`0700`になります。

- 新規ログファイルは `0600`
- policygateが新規作成したログディレクトリは `0700`
- 既存ディレクトリの権限は変更しない
- symlink、FIFO、デバイスなど既存の非通常ファイルへの書き込みは拒否
- 最終ログファイルはsymlinkを辿らずにopen
- `max_bytes` / `max_files`によるローテーション
- プロセス間ロックによる並行書き込み・ローテーションの直列化
- `command_mode`: `redacted` / `full` / `hash` / `none`
- `redacted`は一般的なtoken代入、Authorizationヘッダー、URL userinfo、curl Basic認証、MySQL/MariaDBのpasswordフラグを認識

`redacted`のマスクは完全ではなく、通常文を過剰に隠すこともあります。コマンド本文が不要なら`hash`または`none`を使用してください。

## 運用コマンド

| コマンド | コマンド説明 | 利用例 |
| --- | --- | --- |
| `policygate check-config` | 設定ファイルを読み込み、スキーマと設定値を検証します。警告またはエラーがあれば表示します。 | 設定の作成・編集後、hookへ登録する前 |
| `policygate doctor` | バージョン、OS/アーキテクチャ、実行ファイルの場所、ホスト、設定ファイルの読込結果を表示します。 | インストールや設定の問題を切り分けるとき |
| `policygate evaluate --host codex --command 'rm -rf /'` | 指定したコマンドを**実行せずに**現在のポリシーで判定し、結果をJSONで表示します。 | ルール変更後にdeny / deferの結果を確認するとき |
| `policygate observe --host codex` | PreToolUseのJSON入力を標準入力から1件受け取り、拒否せずに判定と監査記録だけを行います。 | hook連携をブロックなしで試すとき |
| `policygate version` | PolicyApprovalGateのバージョンを表示します。 | 導入済みバージョンを確認するとき |
| `policygate help` | サブコマンドと環境変数の一覧を表示します。 | 使い方を確認するとき |

引数を付けずに実行した場合はhookモードとして標準入力を読み取ります。未知のサブコマンドやフラグは、hook呼び出しとして黙って処理せずexit code 2で報告します。

たとえば、設定変更後の確認は次の順で行えます。`evaluate`に渡した`rm -rf /`は判定対象の文字列であり、実際には実行されません。

```bash
policygate check-config
policygate doctor
policygate evaluate --host codex --command 'rm -rf /'
policygate version
```

`observe`はPreToolUse形式のJSONを標準入力から受け取るhook用モードです。通常の対話的な動作確認には`evaluate`を使用してください。

## 制限事項

- Bashツール呼び出しだけが対象です。ほかのツールや直接のファイル編集は検査しません。
- 正規表現と限定的なシェル解析のため、難読化や未対応構文を完全には扱えません。
- Gitのaliasは解決しません。`git pushf` のようにaliasへ退避したpushは保護ブランチ判定を通過します。aliasの解決には `git config` の読み取りが必要で、alias自体が任意のシェルコマンド（`!sh -c ...`）になり得るためです。保護ブランチを強制したい場合は、リモート側のbranch protectionを併用してください。
- 変数展開やコマンド置換を含むコマンド名（`$CMD -rf /` など）は解析時に確定できません。
- pipeline、subshell、条件分岐の完全な実行意味論はモデル化せず、関連コマンドをindeterminateとして安全側に扱います。
- 同一チェーン内で新規作成する通常ディレクトリは解析時点で存在しないため、後続cdを失敗とみなす場合があります。
- 内部エラー時はホストの承認フローへ委ねるフェイルオープン設計です。
- 組み込みルールは出発点です。利用環境に合わせて調整してください。

## 開発

```bash
gofmt -w .
go vet ./...
go test -race ./...
golangci-lint run ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
go build ./...
```

lint設定は [.golangci.yml](.golangci.yml) に固定しています。CI設定は [.github/workflows/ci.yml](.github/workflows/ci.yml) にあり、GitHub Actionsはtagではなくcommit SHAで固定しています。

`v*` タグをpushすると [.github/workflows/release.yml](.github/workflows/release.yml) が darwin / linux / windows の amd64・arm64 バイナリと `SHA256SUMS` を生成し、pre-releaseとして公開します。

脆弱性の非公開報告手順は [SECURITY.md](SECURITY.md) を参照してください。

## ライセンス

[MIT License](LICENSE)
