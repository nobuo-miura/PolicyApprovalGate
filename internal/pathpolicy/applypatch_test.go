package pathpolicy

import (
	"testing"

	"github.com/nobuo-miura/policyapprovalgate/internal/shellparse"
)

// classifyFirst parses a command and classifies its first simple command.
func classifyFirst(t *testing.T, src string) []Access {
	t.Helper()
	cmds, err := shellparse.Parse(src)
	if err != nil {
		t.Fatalf("parse %q: %v", src, err)
	}
	if len(cmds) == 0 {
		t.Fatalf("no command parsed from %q", src)
	}
	return Classify(cmds[0])
}

// The patch reaches the shell two ways and has to be read out of both. The
// heredoc body is not an argument, so an analysis that only looked at argv
// would see an apply_patch call with nothing in it.
func TestClassifyApplyPatchReadsBothDeliveryForms(t *testing.T) {
	const heredoc = `apply_patch <<'PATCH'
*** Begin Patch
*** Update File: .env
+SECRET=1
*** End Patch
PATCH`
	const argument = `apply_patch "*** Begin Patch
*** Update File: .env
+SECRET=1
*** End Patch"`

	for name, src := range map[string]string{"heredoc": heredoc, "argument": argument} {
		t.Run(name, func(t *testing.T) {
			got := classifyFirst(t, src)
			if len(got) != 1 || got[0].Path != ".env" || got[0].Op != OpWrite {
				t.Errorf("Classify() = %+v, want one write of .env", got)
			}
		})
	}
}

func TestClassifyApplyPatchMapsEveryMarker(t *testing.T) {
	src := `apply_patch <<'PATCH'
*** Begin Patch
*** Add File: added.txt
*** Delete File: removed.txt
*** Update File: changed.txt
*** End Patch
PATCH`
	want := []Access{
		{Path: "added.txt", Op: OpWrite},
		{Path: "removed.txt", Op: OpDelete},
		{Path: "changed.txt", Op: OpWrite},
	}
	got := classifyFirst(t, src)
	if len(got) != len(want) {
		t.Fatalf("Classify() = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i].Path != want[i].Path || got[i].Op != want[i].Op {
			t.Errorf("access %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// A rename leaves nothing behind at the old path, so reporting it as a write
// would describe a file that is going away as one still there.
func TestClassifyApplyPatchTreatsARenamedSourceAsADelete(t *testing.T) {
	src := `apply_patch <<'PATCH'
*** Begin Patch
*** Update File: secrets.env
*** Move to: public.txt
*** End Patch
PATCH`
	got := classifyFirst(t, src)
	if len(got) != 2 {
		t.Fatalf("Classify() = %+v, want the source and the destination", got)
	}
	if got[0].Path != "secrets.env" || got[0].Op != OpDelete {
		t.Errorf("source = %+v, want a delete of secrets.env", got[0])
	}
	if got[1].Path != "public.txt" || got[1].Op != OpWrite {
		t.Errorf("destination = %+v, want a write of public.txt", got[1])
	}
}

// Content the patch adds is prefixed with +, - or a space, so a line inside a
// hunk cannot name a file the patch does not touch. Without this, anything the
// agent writes into a file could steer the analysis.
func TestClassifyApplyPatchIgnoresMarkersInsidePatchContent(t *testing.T) {
	src := `apply_patch <<'PATCH'
*** Begin Patch
*** Update File: README.md
+*** Update File: .env
-*** Delete File: /etc/passwd
 *** Add File: ~/.ssh/id_rsa
*** End Patch
PATCH`
	got := classifyFirst(t, src)
	if len(got) != 1 || got[0].Path != "README.md" {
		t.Errorf("Classify() = %+v, want only README.md", got)
	}
}

// An unquoted heredoc expands before apply_patch runs, so the written name is
// not necessarily the name on disk.
//
// A quoted heredoc does not expand, and its $ is part of the filename - yet it
// is reported the same way. Whether an expansion happened depends on how the
// patch was delivered (a quoted delimiter against a bare one, and which
// quotes wrapped an argument). The command text retains that context, but the
// classifier deliberately does not model every delivery form. Both are
// reported as unresolved because the two mistakes do not cost the same: a
// filename containing a literal $ is examined more closely than needed, while
// an expansion read as a literal name would make the gate check the wrong path.
func TestClassifyApplyPatchMarksExpansionsIndeterminate(t *testing.T) {
	for name, src := range map[string]string{
		"unquoted heredoc expands": "apply_patch <<PATCH\n*** Begin Patch\n*** Update File: $TARGET/.env\n*** End Patch\nPATCH",
		"quoted heredoc does not":  "apply_patch <<\u0027PATCH\u0027\n*** Begin Patch\n*** Update File: $TARGET/.env\n*** End Patch\nPATCH",
	} {
		t.Run(name, func(t *testing.T) {
			got := classifyFirst(t, src)
			if len(got) != 1 {
				t.Fatalf("Classify() = %+v, want one access", got)
			}
			if !got[0].Indeterminate {
				t.Errorf("%+v is not marked indeterminate, so it would be resolved as a literal name", got[0])
			}
		})
	}
}

// The markers belong to the patch format rather than to a shell, so the same
// call has to be read on Windows, where Codex speaks PowerShell.
func TestClassifyPowerShellReadsApplyPatch(t *testing.T) {
	got := ClassifyPowerShell("apply_patch \"*** Begin Patch\n*** Update File: .env\n+X=1\n*** End Patch\"")
	if len(got) != 1 || got[0].Path != ".env" || got[0].Op != OpWrite {
		t.Errorf("ClassifyPowerShell() = %+v, want one write of .env", got)
	}
}

// Only apply_patch is read this way. A command that merely prints the same text
// is not editing anything.
func TestClassifyLeavesPatchTextAloneInOtherCommands(t *testing.T) {
	if got := classifyFirst(t, `echo "*** Update File: .env"`); len(got) != 0 {
		t.Errorf("Classify() = %+v, want nothing from an echo", got)
	}
	if isApplyPatch("applypatch") || isApplyPatch("apply-patch") {
		t.Error("a spelling Codex rejects was treated as the tool")
	}
	if !isApplyPatch("apply_patch") {
		t.Error("apply_patch was not recognized")
	}
}
