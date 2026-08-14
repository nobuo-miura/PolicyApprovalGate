# PolicyApprovalGate

[English](README.md) | [日本語](README.ja.md)

[![CI](https://github.com/nobuo-miura/PolicyApprovalGate/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/nobuo-miura/PolicyApprovalGate/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/nobuo-miura/PolicyApprovalGate?include_prereleases)](https://github.com/nobuo-miura/PolicyApprovalGate/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/nobuo-miura/PolicyApprovalGate)](go.mod)
[![License](https://img.shields.io/github/license/nobuo-miura/PolicyApprovalGate)](LICENSE)

PolicyApprovalGateは、Claude CodeとCodex CLIがシェルコマンドを実行する前に、ローカルルールで内容を検査するPreToolUseフックです。

危険なコマンド、保護ブランチへのpush、プロジェクト外や機微なパスへのアクセスを検出し、判定を監査ログへ記録します。判定にAIやLLMは使わないため、同じ入力には常に同じ結果を返します。

> [!IMPORTANT]
> PolicyApprovalGateは、ホスト側の権限管理、サンドボックス、人による確認を補助するツールです。完全なシェル解析器やセキュリティ境界ではなく、単独で最後の防御線になるものではありません。

![Claude Codeが~/.sshの読み取りを遮断される様子](images/ss.gif)

上の例では、Claude Codeによる`~/.ssh`の読み取りを拒否し、その理由をホストへ返しています。

## 主な機能

- AIやLLMを使わない、ローカルでの決定論的な判定
- ルートディレクトリや現在のユーザーのホームディレクトリに対する再帰的な強制削除を常時拒否
- 設定可能なコマンドルールと、保護ブランチへのpush制御
- プロジェクト内外、機微なパス、PolicyApprovalGate自身のファイルに対する読み取り・書き込み・削除ポリシー
- `cd`、wrapper、symlinkを考慮したパス追跡と、Windows PowerShellからの限定的なパス抽出
- Claude Codeの`ask`とCodexのdeny変換をホスト別に処理
- ローテーション、ハッシュ記録、best-effortの機密情報マスキングに対応した監査と、CLIによる設定・hook管理

## 対応環境

- Claude CodeまたはCodex CLIのPreToolUse hooks
- 通常サポート: macOS、Linux
- 実験的サポート: Windows

WindowsもCIでビルドと単体テストを行っていますが、PowerShellを完全には解析できないため実験的サポートです。詳しくは「[WindowsとPowerShell](#windowsとpowershell)」を参照してください。Go 1.26が必要なのは、ソースからビルドする場合だけです。

fixture / goldenテストは、2026-08-11時点で次のバージョンを基準にしています。

| ホスト | 確認バージョン |
| --- | --- |
| Codex CLI | 0.147.0 |
| Claude Code | 2.1.220 |

## クイックスタート

### 1. インストール

インストーラは`~/.policygate/bin`へ配置し、初期設定ファイルも作成します。**管理者権限は不要です。**

```bash
curl -fsSLO https://raw.githubusercontent.com/nobuo-miura/PolicyApprovalGate/main/install.sh
less install.sh   # 中身を読んでから実行してください
sh install.sh
```

Windowsは `install.ps1` を同じ手順で使います。

```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/nobuo-miura/PolicyApprovalGate/main/install.ps1 -OutFile install.ps1
Get-Content install.ps1   # 中身を読んでから実行してください
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

| フラグ | 説明 |
| --- | --- |
| `--version TAG` / `-Version TAG` | 特定のリリースを指定（既定は最新） |
| `--dir PATH` / `-Dir PATH` | 配置先を指定（既定は `~/.policygate/bin`） |

現在のcheckoutをGo 1.26でビルドする場合は次のとおりです。

```bash
go build -o policygate ./cmd/policygate
```

Go経由でもインストールできます。

```bash
go install github.com/nobuo-miura/policyapprovalgate/cmd/policygate@latest
```

`go install`ではrelease workflowのversion情報が埋め込まれないため、`policygate version`は`dev`と表示されます。バージョン付きのrelease binaryが必要な場合は、release installerを使用してください。

以降のコマンドは、配置先が`PATH`に含まれている前提です。含まれていない場合は、installerが表示した`~/.policygate/bin/policygate`などの絶対パスを使用してください。

### 2. 設定ファイルを確認または作成

installerは`policygate init`を自動実行します。ソースからbuildした場合やGo経由でinstallした場合は、自分で実行してください。

```bash
policygate init
```

既定では`~/.policygate/config.yaml`を作成し、既存ファイルは変更しません。別の場所へ作成する場合は、実行前に`POLICYGATE_CONFIG`を指定してください。hookへ登録する前に、生成されたpolicyを確認します。

### 3. ホストへ登録

```bash
policygate install-hook --host claude   # ./.claude/settings.local.json
policygate install-hook --host codex    # ~/.codex/config.toml
```

`install-hook`は実行中のバイナリの絶対パスを登録します。何度実行しても登録は重複せず、既存設定を保持したまま原子的に更新します。既存ファイルを変更する場合は、先にバックアップを作成します。

Claude Codeの既定の登録先は`.claude/settings.local.json`です。登録内容には端末固有の絶対パスが含まれるため、共有・コミットされる`.claude/settings.json`には書き込みません。すべてのプロジェクトで使う場合は`--user`を指定してください。

```bash
policygate install-hook --host claude --user
```

Codexでは、登録後に`/hooks`を実行し、表示された定義を確認してtrustしてください。未trustまたは変更後のhookは実行されません。

### 4. 動作を確認

```bash
policygate check-config
policygate doctor
policygate evaluate --host codex --command 'rm -rf /'
```

`evaluate`は文字列を判定するだけで、指定したコマンドを実行しません。

## 判定の仕組み

PolicyApprovalGateは次の順でコマンドを確認します。

1. denyルール
2. シェル構文の解析
3. 保護ブランチへのpush
4. askルール
5. パス範囲、機微パス、保護パス
6. allowルールによる監査上の分類
7. `unknown.action`または`parse_error.action`

明示的なdenyが最優先です。allowルールは監査ログ上の分類にだけ使われ、ホスト側の承認を省略しません。どのルールにも一致しない操作は、既定ではホスト本来の承認フローへ委ねます。

### ホストごとの違い

| PolicyApprovalGateの判定 | Claude Code | Codex CLI |
| --- | --- | --- |
| `deny` | 拒否 | 拒否 |
| `ask` | ユーザーへ確認 | `deny`へ変換 |
| 判定なし | 通常の承認フローへ委譲 | 通常の承認フローへ委譲 |

CodexのPreToolUse hookは単独の`ask`に対応していないため、`--host codex`では安全側に倒して`deny`へ変換します。`--host`を省略した場合もClaude以外として扱います。Claude Codeで使う場合は、必ず`--host claude`を指定してください。

## 設定

組み込み設定の全項目と既定値は[internal/rules/default.yaml](internal/rules/default.yaml)にあります。

| セクション | 用途 |
| --- | --- |
| `config_version` | 設定スキーマのバージョン |
| `mode` | `enforce`または判定だけを記録する`observe` |
| `deny` | コマンドをGo RE2正規表現で照合して拒否 |
| `ask` | Claude Codeでは確認を求め、Codexでは拒否 |
| `allow` | 既知の低リスクコマンドとして監査上分類 |
| `protected_branches` | 保護ブランチへのpushを制御 |
| `path_scope` | プロジェクト外のread / write / deleteを制御 |
| `sensitive_paths` | `.env`、SSH鍵、認証情報などを保護 |
| `protected_paths` | 設定やhook登録へのwrite / deleteを拒否 |
| `unknown` | どのルールにも一致しない場合の動作 |
| `parse_error` | シェル構文を解析できない場合の動作 |
| `audit` | 監査ログの保存先、記録方法、ローテーション |

`unknown.action`と`parse_error.action`には`defer`、`ask`、`deny`を指定できます。

```yaml
unknown:
  action: ask

parse_error:
  action: ask
```

この設定はClaude Codeでは確認画面を表示しますが、Codexでは対象を拒否します。たとえば`unknown.action: ask`をCodexで使うと、どのルールにも一致しない通常のビルドコマンドまで拒否されます。`check-config`と`doctor`は、この組み合わせを検出して警告します。

### ホストごとに設定を分ける

Claude CodeとCodexで異なる動作が必要な場合は、別々の設定ファイルを登録できます。

```bash
policygate install-hook --host claude --config /absolute/path/.policygate/claude.yaml
policygate install-hook --host codex  --config /absolute/path/.policygate/codex.yaml
```

`--config`には絶対パスを指定してください。指定した設定を読み込めない場合、`enforce`モードは対象のシェル呼び出しを拒否します。登録前に各ファイルを検証できます。

```bash
policygate check-config --config /absolute/path/.policygate/codex.yaml
```

`POLICYGATE_CONFIG`環境変数も利用できますが、`--config`が優先されます。フックごとに設定を分ける用途では`--config`を推奨します。

> [!WARNING]
> Windowsには`/usr/bin/env`がないため、`/usr/bin/env POLICYGATE_CONFIG=... policygate`の形を使わないでください。
>
> hookを起動できなくてもtool callが続行される場合があります。Codex CLI 0.147.0 / Windows 11での実測では、PolicyApprovalGateの監査ログが作られないままコマンドが実行されました。
>
> `install-hook --config`を使うと、意図した設定でPolicyApprovalGateを直接起動できます。

設定ファイルは、既定の`protected_paths`で保護される`.policygate`ディレクトリ内へ置くことを推奨します。別の場所へ置く場合は、そのパスを`protected_paths.patterns`へ追加してください。

### 既存設定を更新する

設定ファイルとhook登録は自動更新されません。アップグレード後は、ルールと登録の両方を更新してください。

```bash
policygate init --upgrade
policygate install-hook --host claude   # --userで登録した場合は今回も--userを付ける
policygate doctor
```

`init --upgrade`は、既存ファイルと同じディレクトリに`config.yaml.bak.*`を作成してから原子的に置き換えます。

ユーザー設定の`deny`、`ask`、`allow`、`sensitive_paths.patterns`、`protected_paths.patterns`は、組み込みリストへ自動追加されるのではなく、リスト全体を置き換えます。`--upgrade`は不足している組み込みルールを追加し、その内容を警告として表示します。意図的に削除したルールが戻ることもあるため、警告を確認してください。

## パス判定

POSIXシェルでは`mvdan.cc/sh`を使って構文を解析し、対応コマンドの引数をread / write / deleteへ分類します。主に次のケースを扱います。

- `cd /tmp && rm -rf target`のような先行`cd`
- プロジェクト内から外部を指す既存symlink
- `ln -s /outside escape && ...`のように同じチェーン内で作るsymlink
- `ln -s SRC EXISTING_DIR`、`ln -s -t DIR SRC`の配置先
- `cp -t DIR SRC`、`install --target-directory=DIR SRC`の書き込み先
- `env`、`command`、`nohup`などの透過wrapper
- スペースを含む引用符付きパス
- pipeline、subshell、条件分岐、バックグラウンド、ループ内の`cd`

変数を展開しないと決まらないパスや`cd -`などは、不定なパスとして安全側に判定します。未対応コマンドはパスアクセスを生成せず、ほかのルールまたは`unknown.action`へ進みます。

### 大文字小文字

`deny`、`ask`、`allow`、`sensitive_paths`、`protected_paths`の照合は、すべてのOSで大文字小文字を区別しません。既定のmacOSやWindowsのように大文字小文字を区別しないファイルシステムで、`.ENV`や`RM`といった表記による回避を防ぐためです。

Linuxなど大文字小文字を区別する環境では、別のファイルやプログラムを過剰に検出する可能性があります。プロジェクト内外の判定だけは、実行OSの既定のファイルシステム挙動に従います。

## WindowsとPowerShell

Windowsではホストごとにシェルの扱いが異なります。

- Codex CLIはPowerShellコマンドでも`tool_name: "Bash"`として送信します
- Claude Codeは`PowerShell`ツールを持つため、登録時に`Bash`と`PowerShell`の両方を対象にします

PolicyApprovalGateはホスト、ツール名、OSから方言を判定します。判定結果は`doctor`と監査ログの`dialect`で確認でき、`POLICYGATE_SHELL=posix|powershell`で上書きできます。

PowerShellは完全な構文解析ではなく、cmdletとパラメータをトークン化してパスを抽出します。

| 機能 | POSIX | PowerShell |
| --- | --- | --- |
| `deny` / `ask` / `allow` | 対応 | 対応 |
| `path_scope` / `sensitive_paths` / `protected_paths` | 対応 | 抽出できたパスに対応 |
| `cd`追跡 | 対応 | 非対応。後続の相対パスを不定として扱う |
| symlink解決 | 対応 | 非対応 |

PowerShellでは、`-Path`、`-LiteralPath`、`-Destination`、位置指定引数、一般的なalias、カンマ区切り配列を扱います。一方、次のような対象は正確に特定できません。

- pipelineから渡される削除対象
- 変数、部分式、文字列連結で作られるパス
- `Set-Location`後の相対パス
- wildcardが展開された後の実際のパス
- バッククォートによる難読化

抽出できなかった操作は`unknown.unanalyzed_action`または`parse_error.unanalyzed_action`に従います。既定値は`ask`です。

Codex on Windowsでは`ask`が`deny`へ変換されるため、既定のままでは通常の操作まで拒否される場合があります。必要に応じてCodex専用の設定ファイルを作り、次のように変更してください。

```yaml
unknown:
  unanalyzed_action: defer
parse_error:
  unanalyzed_action: defer
```

この場合も、テキストルールと、PowerShellのトークン解析で抽出できたパスに対するポリシーは引き続き適用されます。

## 監査ログ

既定では`~/.policygate/log/audit.log`へJSON Lines形式で記録します。

- 新規ディレクトリは`0700`、新規ログファイルは`0600`
- 既存ディレクトリの権限は変更しない
- symlink、FIFO、デバイスなどの非通常ファイルを拒否
- symlinkを辿らずに最終ログファイルをopen
- プロセス間ロックで並行書き込みとローテーションを直列化
- `max_bytes` / `max_files`でローテーション
- `command_mode`: `redacted` / `full` / `hash` / `none`

`redacted`は一般的なtoken代入、Authorizationヘッダー、URL userinfo、curl Basic認証、MySQL / MariaDBのpasswordフラグをマスクします。ただし完全ではなく、通常の文字列を過剰に隠す場合もあります。コマンド本文が不要なら`hash`または`none`を使用してください。

## CLIリファレンス

| コマンド                                             | 用途 |
|------------------------------------------------------| --- |
| `policygate install-hook --host (claude or codex)`   | PreToolUse hookとして登録 |
| `policygate uninstall-hook --host (claude or codex)` | policygateの登録だけを解除 |
| `policygate check-config`                            | 設定のスキーマと値を検証 |
| `policygate doctor`                                  | バージョン、OS、設定、登録、方言、自己保護を診断 |
| `policygate evaluate --command CMD`                  | コマンドを実行せずに判定 |
| `policygate observe`                                 | 拒否せず、判定と監査記録だけを実行 |
| `policygate version`                                 | バージョンを表示 |
| `policygate help`                                    | ヘルプを表示 |

hook登録では次のフラグを利用できます。

| フラグ | 対象 | 用途 |
| --- | --- | --- |
| `--user` | 登録・解除 | Claude Codeのユーザー設定を対象にする |
| `--path PATH` | 登録・解除 | 登録先ファイルを指定 |
| `--config PATH` | 登録 | 登録するコマンドへ設定ファイルの絶対パスを追加 |
| `--dry-run` | 登録・解除 | ファイルを書き換えず、結果だけを表示 |

手動登録用の完全な例は[Claude Code設定例](configs/claude-code.settings.example.json)と[Codex設定例](configs/codex-config.example.toml)にあります。Windowsのパスは`D:/bin/policygate.exe`のようにフォワードスラッシュで記述してください。

引数なしで実行するとhookモードになり、標準入力からPreToolUse JSONを1件読み取ります。未知のサブコマンドやフラグはexit code 2で終了します。

## 非目標

PolicyApprovalGateは、次の用途を意図していません。

- **サンドボックスや権限モデルの代替** — PolicyApprovalGateは、これらの仕組みを補完するためのものです。単独で最後の防御線として使用することは想定していません。
- **AIやLLMを使った判定** — すべての判定を決定論的なルールに基づいて行い、同じ入力には常に同じ結果を返します。また、判定根拠を後から検証できることを重視しています。
- **シェルの完全なエミュレーション** — コマンドを実行せずに判定するため、実行時に初めて確定する値は設計上扱えません。
- **難読化されたコマンドの完全な検出** — あらゆる意図的な回避を防ぐものではなく、誤操作やリスクの見落としを減らすことを目的としています。
- **ネットワーク通信の監視** — コマンドが発行された時点の内容だけを検査します。
- **シェル以外のツール呼び出しの検査**（現時点） — WriteやEditなどのツールへの対応は、今後検討する可能性があります。

## 制限事項

非目標と異なり、次は現時点の実装上の制約です。

- 限定的な構文解析のため、変数、コマンド置換、未対応構文によって実行時に生成されるコマンドやパスは確定できません。
- PowerShellのpipeline、wildcard展開、`Set-Location`後の相対パスは完全には追跡できません。詳しくは「[WindowsとPowerShell](#windowsとpowershell)」を参照してください。
- Git aliasは解決しません。保護ブランチを強制する場合は、リモート側のbranch protectionも使用してください。
- pipeline、subshell、条件分岐の完全な実行意味論はモデル化しません。
- 同じチェーン内で新しく作る通常ディレクトリは解析時点に存在しないため、後続の`cd`を失敗とみなす場合があります。
- 明示した設定ファイルが不正な場合はdenyを返しますが、hook入力、出力、監査ログ自体の障害では常にホスト判定を置き換えられるとは限りません。
- 組み込みルールは出発点です。利用環境に合わせて調整してください。

## 開発

開発環境の準備、必須チェック、ルール提案、fuzz seed、Pull Requestの手順は[CONTRIBUTING.ja.md](CONTRIBUTING.ja.md)を参照してください。

Lint設定は[.golangci.yml](.golangci.yml)、CIは[.github/workflows/ci.yml](.github/workflows/ci.yml)にあります。GitHub Actionsはtagではなくcommit SHAで固定しています。

`v*`タグをpushすると[release workflow](.github/workflows/release.yml)がdarwin / linux / windows向けのamd64・arm64バイナリと`SHA256SUMS`を生成し、pre-releaseとして公開します。メンテナーは[RELEASE_CHECKLIST.ja.md](RELEASE_CHECKLIST.ja.md)を公開判定に使用します。

脆弱性の非公開報告手順は[SECURITY.md](SECURITY.md)を参照してください。

## ライセンス

[MIT License](LICENSE)
