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
- ファイルシステムの大文字小文字非区別を利用した回避を防ぐため、ルール照合は常に大文字小文字を区別しない
- 配置場所によらず、自身の実行ファイルへの書き込みと削除を設定不要で常時拒否
- `install-hook` によるhook登録の自動化（絶対パスの解決、冪等、既存設定の保持）
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

`install-hook` が自身の絶対パスを解決して登録します。設定ファイルを手で編集する必要はありません。

```bash
policygate install-hook --host claude   # ./.claude/settings.json
policygate install-hook --host codex    # ~/.codex/config.toml
```

| フラグ | 説明 |
| --- | --- |
| `--user` | Claude Codeの登録先を `~/.claude/settings.json` にする（既定はプロジェクトの `.claude/settings.json`） |
| `--path PATH` | 登録先ファイルを明示指定する |
| `--dry-run` | 書き込まず、書き込む内容を表示する |

登録は冪等で、既存の設定は保持されます。書き込み前にバックアップを作成し、置き換えはアトミックに行います。解除は `uninstall-hook` です。

```bash
policygate uninstall-hook --host claude
```

Codexの登録はマーカーコメントで囲んだブロックとして追記されるため、同じファイルにある他の設定には触れません。Claude Codeの `settings.json` はJSONとして読み書きしますが、`hooks` 以外のキーとその順序は保持されます（インデントは2スペースに統一されます）。

Codex hooksは既定で有効です。`codex_hooks` は非推奨の別名で、現在の正式な機能キーは `hooks` です。詳細は [Codex Hooks公式ドキュメント](https://learn.chatgpt.com/docs/hooks) を確認してください。

**登録後にCodexで`/hooks`を実行し、表示されたコマンド定義をreviewしてtrustしてください。未trustまたは変更後のhookは実行されません。**

#### 手動で登録する場合

完全な例は [configs/claude-code.settings.example.json](configs/claude-code.settings.example.json) と [configs/codex-config.example.toml](configs/codex-config.example.toml) を参照してください。`command` にはpolicygateの絶対パスを記載します。`~` や `$HOME` は、ホストがコマンドをシェル経由で実行した場合にのみ展開されます。展開されないまま渡すとhookは動作しません。

**Windowsではパス区切りにフォワードスラッシュを使ってください**（`D:/bin/policygate.exe`）。バックスラッシュは、JSON文字列では `\b` がバックスペースとして解釈され、ホストがコマンドをシェルに渡す場合はエスケープ文字として除去されるため、どちらの経路でも壊れます。Windowsはパス区切りとしてフォワードスラッシュを受け付けます。

`install-hook` を使えば、パスの解決も区切り文字の変換も自動的に行われるため、これらの問題は起こりません。

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
| `unknown` | どのルールにも一致しない場合の `defer` / `ask` / `deny` |
| `parse_error` | シェル構文を解析できない場合の `defer` / `ask` / `deny` |
| `audit` | 保存先、コマンド記録方式、ローテーション設定 |

PolicyApprovalGateがコマンドを分類できない場合に確認を求めるには、フォールバック時の判定を`ask`に設定します。

```yaml
unknown:
  action: ask

parse_error:
  action: ask
```

Claude Codeではこれらのフォールバック時に確認を求めます。Codexは単独の`ask`に対応していないため、PolicyApprovalGateが`deny`へ変換します。

この変換の影響は大きい点に注意してください。`unknown.action: ask`はCodexでは**どのルールにも一致しないコマンドをすべて拒否**します。`go build ./...`や`npm run build`のような通常の操作も対象です。`--host`と`POLICYGATE_HOST`のどちらでもClaudeを指定していない場合、安全側としてClaude以外と扱うため結果は同じです。フォールバックを`ask`にする場合は、`--host claude`または`POLICYGATE_HOST=claude`でClaude Code向けのホストを指定してください。`policygate check-config`と`policygate doctor`は、この設定を検出して警告を表示します。

### ホストごとに設定ファイルを分ける

設定にホスト別の項目はありません。両方のホストを併用していて、Claude Codeでは`ask`、Codexでは`defer`のように挙動を変えたい場合は、フック登録ごとに`POLICYGATE_CONFIG`で別の設定ファイルを指定してください。設定はフック実行のたびに読み込まれるため、ホストごとに独立したポリシーを持てます。

Claude Code (`settings.json`):

```json
"command": "/usr/bin/env POLICYGATE_CONFIG=/absolute/home/path/.policygate/claude.yaml /usr/local/bin/policygate --host claude"
```

Codex (`~/.codex/config.toml`):

```toml
command = "/usr/bin/env POLICYGATE_CONFIG=/absolute/home/path/.policygate/codex.yaml /usr/local/bin/policygate --host codex"
```

両方のファイルはユーザーの`.policygate`ディレクトリ配下へ置き、`protected_paths`を有効にしたまま、生成された`.policygate`の項目を残してください。これにより、その配下への書き込みと削除を拒否します。上記のパスはプレースホルダーなので、`~/.policygate/claude.yaml`と`~/.policygate/codex.yaml`の絶対パスへ置き換えてください。`~`や`$HOME`はホストがコマンドをシェル経由で起動する場合しか展開されず、展開されなければ設定ファイルを読めません。別の場所へ置く必要がある場合は、フック登録前にそのパスを`protected_paths.patterns`へ追加してください。

ポリシーが2ファイルに分かれるため、denyルールなど共通部分の更新漏れに注意してください。また、指定したパスが読めない場合、`enforce`モードはそのBash呼び出しをdenyします。登録前に`policygate check-config --config <path>`で各ファイルを検証してください。

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

### 大文字小文字の扱い

ルール照合（`deny` / `ask` / `allow` / `sensitive_paths` / `protected_paths`）は、実行プラットフォームによらず**常に大文字小文字を区別しません**。

大文字小文字を区別しないファイルシステムでは、表記を変えるだけでルールを回避できてしまうためです。WindowsのNTFSとmacOSの既定のAPFS構成がこれにあたり、Linuxでもext4のcasefold、exFAT/NTFSマウント、ネットワーク共有などで同じ状況が発生します。こうした環境では次が成立します。

- `.ENV` は `.env` と同じファイルを開くため、`.env` 向けに書いたルールをすり抜けます
- コマンド名もPATH解決の時点で同一視されるため、`RM -rf /` は `rm -rf /` と同じバイナリを実行します

大文字小文字を区別するファイルシステムでは、この扱いによって「大文字小文字だけが異なる別のファイルやプログラム」を過剰に検出する可能性があります。ゲートとしては安全側の誤りであるため、この動作を採用しています。

なお、**プロジェクト内外の判定だけは**実行プラットフォームの既定のファイルシステム挙動に従うため、非標準の構成では正確でない場合があります。制限事項を参照してください。

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
| `policygate install-hook --host claude` | 自身の絶対パスを解決し、PreToolUse hookとして登録します。冪等で、既存の設定を保持します。 | 導入時、およびバイナリの移動後 |
| `policygate uninstall-hook --host claude` | 登録を解除します。ほかのhookには触れません。 | 一時的に無効化するとき、アンインストール時 |
| `policygate check-config` | 設定ファイルを読み込み、スキーマと設定値を検証します。警告またはエラーがあれば表示します。 | 設定の作成・編集後、hookへ登録する前 |
| `policygate doctor` | バージョン、OS/アーキテクチャ、実行ファイルの場所、自己保護の対象パス、ホスト、設定ファイルの読込結果を表示します。 | インストールや設定の問題を切り分けるとき |
| `policygate evaluate --host codex --command 'rm -rf /'` | 指定したコマンドを**実行せずに**現在のポリシーで判定し、結果をJSONで表示します。 | ルール変更後にdefer / ask / denyの結果を確認するとき |
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
- `ask`判定はClaude Codeでは確認を求めますが、PreToolUse hook単独の確認に対応しないCodexでは`deny`へ変換されます。そのため、同じポリシーでもClaude Codeでは確認画面が表示され、Codexではコマンドが拒否されるという操作上の違いがあります。
- 正規表現と限定的なシェル解析のため、難読化や未対応構文を完全には扱えません。
- プロジェクト内外の判定は、実行プラットフォームの既定のファイルシステム挙動に従います。大文字小文字を区別する構成で作成したmacOSボリューム上では、大文字小文字だけが異なる別ディレクトリをプロジェクト内と誤判定する場合があります。逆に大文字小文字を区別しない構成でマウントしたLinuxファイルシステム上では、プロジェクト内のパスをプロジェクト外として扱う場合があります。ルール照合そのものは前者の影響を受けません。
- Gitのaliasは解決しません。`git pushf` のようにaliasへ退避したpushは保護ブランチ判定を通過します。aliasの解決には `git config` の読み取りが必要で、alias自体が任意のシェルコマンド（`!sh -c ...`）になり得るためです。保護ブランチを強制したい場合は、リモート側のbranch protectionを併用してください。
- 変数展開やコマンド置換を含むコマンド名（`$CMD -rf /` など）は解析時に確定できません。
- pipeline、subshell、条件分岐の完全な実行意味論はモデル化せず、関連コマンドをindeterminateとして安全側に扱います。
- 同一チェーン内で新規作成する通常ディレクトリは解析時点で存在しないため、後続cdを失敗とみなす場合があります。
- 未知のコマンドと解析できないシェル構文は、それぞれ`unknown.action`と`parse_error.action`に従います。既定値はどちらも`defer`で、`ask`または`deny`へ変更できます。ほかの`ask`判定と同様に、Claude Codeでは確認を求め、Codexでは`deny`へ変換します。
- 明示的に指定したポリシー設定が不正な場合、有効なBash hook呼び出しには`deny`を返します。hook入力、判定出力、監査ログのエラーは標準エラー出力へ報告しますが、常にホスト判定を生成または置き換えられるとは限りません。
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
