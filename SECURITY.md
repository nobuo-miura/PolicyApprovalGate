# Security Policy

## Supported versions

Security fixes are applied to the latest tagged release and the `main` branch. Pre-release versions may change command classifications and decisions without backward-compatibility guarantees.

## Reporting a vulnerability

Please use GitHub's **Security** tab and select **Report a vulnerability** to create a private security advisory. Include the affected version, host (Claude Code or Codex CLI), configuration, reproduction command, expected decision, and actual decision. If private reporting is not available, open a public issue without sensitive details and ask the maintainer to establish a private channel.

Do not include secrets, credentials, or sensitive local paths in a public issue. Use a public issue only for non-sensitive bugs and feature requests.

PolicyApprovalGate is a defense-in-depth guardrail, not a security boundary. A vulnerability is in scope if a command that should be denied by the built-in critical-delete protection or the loaded configuration can proceed without a PolicyApprovalGate denial. This remains in scope even when the host would still show its normal approval prompt.

---

# セキュリティポリシー

## サポート対象

セキュリティ修正は、最新のタグ付きリリースと`main`ブランチへ適用します。プレリリース版では、コマンドの分類や判定結果を後方互換性の保証なく変更する場合があります。

## 脆弱性の報告

GitHubの**Security**タブから**Report a vulnerability**を選び、非公開のSecurity Advisoryとして報告してください。対象バージョン、ホスト（Claude CodeまたはCodex CLI）、設定、再現コマンド、期待した判定、実際の判定を含めてください。非公開報告が利用できない場合は、機微情報を含めずに公開Issueを作成し、非公開連絡手段の案内を依頼してください。

シークレット、認証情報、機微なローカルパスを公開Issueへ記載しないでください。公開Issueは、機微情報を含まない不具合や機能要望にのみ使用してください。

PolicyApprovalGateは多層防御のための補助的なガードレールであり、単独のセキュリティ境界ではありません。組み込みの致命的削除保護、または読み込まれた設定で拒否されるはずのコマンドが、PolicyApprovalGateに拒否されず実行可能になる問題は報告対象です。ホスト側の通常承認が残る場合も対象に含まれます。
