//go:build windows || darwin

package paths

// FSIgnoresCase is true here because NTFS and the default APFS configuration
// resolve paths without regard to case: C:\Users\x\.SSH and .ssh name the same
// file. A case-sensitive APFS volume is possible but unusual, and treating it
// as insensitive only widens what the path rules match, so the mistake costs a
// false positive rather than a missed secret.
const FSIgnoresCase = true
