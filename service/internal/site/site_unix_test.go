//go:build unix

package site

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The installer runs as root in a container whose umask it does not choose;
// edge, another user, has to be able to read what it leaves.
func TestInstalledFilesAreReadableWhateverTheUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	for _, keep := range []bool{false, true} {
		dest := t.TempDir()
		if err := os.Chmod(dest, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := Install(makeZip(t,
			member{name: "index.html", body: "home"},
			member{name: "css/deep/site.css", body: "css"},
		), dest, Options{Keep: keep}); err != nil {
			t.Fatal(err)
		}
		for rel, want := range map[string]fs.FileMode{"index.html": 0o644, "css": 0o755, "css/deep": 0o755, "css/deep/site.css": 0o644} {
			st, err := os.Stat(filepath.Join(dest, rel))
			if err != nil || st.Mode().Perm() != want {
				t.Errorf("keep=%v: %s has mode %v, want %v (%v)", keep, rel, st.Mode().Perm(), want, err)
			}
		}
	}
}
