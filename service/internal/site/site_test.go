package site

import (
	"archive/zip"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// member is one entry of a test archive.
type member struct {
	name string
	body string
	mode fs.FileMode // 0 for an ordinary file
	raw  func(*zip.FileHeader)
}

func makeZip(t *testing.T, members ...member) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, m := range members {
		h := &zip.FileHeader{Name: m.name, Method: zip.Deflate}
		if m.mode != 0 {
			h.SetMode(m.mode)
		}
		if m.raw != nil {
			m.raw(h)
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(m.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "site.zip")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// tree lists every path under dir with its content ("<dir>" for folders,
// "-> target" for links), so a test can compare the whole folder.
func tree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == "." {
			return nil
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			target, _ := os.Readlink(p)
			out[rel] = "-> " + target
		case d.IsDir():
			out[rel] = "<dir>"
		default:
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			out[rel] = string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func sameTree(t *testing.T, what string, got, want map[string]string) {
	t.Helper()
	keys := map[string]bool{}
	for k := range got {
		keys[k] = true
	}
	for k := range want {
		keys[k] = true
	}
	var names []string
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if got[k] != want[k] {
			t.Errorf("%s: %q is %q, want %q", what, k, got[k], want[k])
		}
	}
}

func write(t *testing.T, dir, rel, body string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestInstallReplacesTheSite(t *testing.T) {
	dest := t.TempDir()
	write(t, dest, "index.html", "old")
	write(t, dest, "old/page.html", "old page")
	write(t, dest, ".well-known/security.txt", "old contact")
	// Leftovers of an install that was interrupted.
	write(t, dest, ".incoming/half.html", "half")
	write(t, dest, ".outgoing/gone.html", "gone")

	// An umask that would make the files unreadable to edge must not.
	rep, err := Install(makeZip(t,
		member{name: "index.html", body: "<h1>new</h1>"},
		member{name: "css/", mode: fs.ModeDir | 0o700},
		member{name: "css/site.css", body: "body{}", mode: 0o600},
		member{name: "img/deep/bg.jpg", body: "JPEG"},
		member{name: "empty/", mode: fs.ModeDir | 0o755},
	), dest, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Files != 3 || rep.Bytes != int64(len("<h1>new</h1>body{}JPEG")) || rep.Removed != 3 || rep.Kept || rep.Wrapper != "" {
		t.Errorf("report: %+v", rep)
	}
	sameTree(t, "site", tree(t, dest), map[string]string{
		"index.html":      "<h1>new</h1>",
		"css":             "<dir>",
		"css/site.css":    "body{}",
		"img":             "<dir>",
		"img/deep":        "<dir>",
		"img/deep/bg.jpg": "JPEG",
		"empty":           "<dir>",
	})
	for rel, want := range map[string]fs.FileMode{"index.html": 0o644, "css/site.css": 0o644, "css": 0o755, "img/deep": 0o755} {
		st, err := os.Stat(filepath.Join(dest, rel))
		if err != nil || st.Mode().Perm() != want {
			t.Errorf("%s has mode %v, want %v (%v)", rel, st.Mode().Perm(), want, err)
		}
	}
	if !Present(dest) {
		t.Error("Present is false after an install")
	}
}

func TestInstallKeepingExistingFiles(t *testing.T) {
	dest, outside := t.TempDir(), t.TempDir()
	write(t, dest, "index.html", "old index")
	write(t, dest, "about.html", "about")
	write(t, dest, "css/site.css", "old css")
	write(t, dest, "css/print.css", "print")
	write(t, dest, "was-file", "a file where the archive has a folder")
	write(t, dest, "was-dir/inner.txt", "a folder where the archive has a file")
	// A link someone put there by hand, where the archive has a folder.
	// Nothing may be written through it.
	if err := os.Symlink(outside, filepath.Join(dest, "assets")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "target.txt"), filepath.Join(dest, "linked.txt")); err != nil {
		t.Fatal(err)
	}

	rep, err := Install(makeZip(t,
		member{name: "index.html", body: "new index"},
		member{name: "css/site.css", body: "new css"},
		member{name: "was-file/now.txt", body: "now a folder"},
		member{name: "was-dir", body: "now a file"},
		member{name: "assets/app.js", body: "js"},
		member{name: "linked.txt", body: "a real file"},
	), dest, Options{Keep: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Files != 6 || !rep.Kept || rep.Removed != 0 {
		t.Errorf("report: %+v", rep)
	}
	sameTree(t, "site", tree(t, dest), map[string]string{
		"index.html":       "new index",
		"about.html":       "about",
		"css":              "<dir>",
		"css/site.css":     "new css",
		"css/print.css":    "print",
		"was-file":         "<dir>",
		"was-file/now.txt": "now a folder",
		"was-dir":          "now a file",
		"assets":           "<dir>",
		"assets/app.js":    "js",
		"linked.txt":       "a real file",
	})
	if left := tree(t, outside); len(left) != 0 {
		t.Errorf("files were written through a link, outside the site folder: %v", left)
	}
}

// What Finder and Explorer produce when a folder is compressed.
func TestWrappingFolderAndClutter(t *testing.T) {
	dest := t.TempDir()
	rep, err := Install(makeZip(t,
		member{name: "My Site/", mode: fs.ModeDir | 0o755},
		member{name: "My Site/index.html", body: "home"},
		member{name: "My Site/img/logo.png", body: "PNG"},
		member{name: "My Site/.DS_Store", body: "x"},
		member{name: "My Site/img/Thumbs.db", body: "x"},
		member{name: "My Site/desktop.ini", body: "x"},
		member{name: "My Site/.well-known/security.txt", body: "Contact: mailto:me@example.com"},
		member{name: "__MACOSX/My Site/._index.html", body: "x"},
		member{name: "__MACOSX/My Site/img/._logo.png", body: "x"},
		member{name: ".DS_Store", body: "x"},
	), dest, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Wrapper != "My Site" || rep.Files != 3 || rep.SkippedHidden != 6 {
		t.Errorf("report: %+v", rep)
	}
	sameTree(t, "site", tree(t, dest), map[string]string{
		"index.html":               "home",
		"img":                      "<dir>",
		"img/logo.png":             "PNG",
		".well-known":              "<dir>",
		".well-known/security.txt": "Contact: mailto:me@example.com",
	})
}

// A zipped project folder must not publish what scanners look for.
func TestHiddenFilesAreLeftOut(t *testing.T) {
	dest := t.TempDir()
	rep, err := Install(makeZip(t,
		member{name: "index.html", body: "home"},
		member{name: ".env", body: "SECRET=1"},
		member{name: ".git/config", body: "[core]"},
		member{name: ".git/objects/ab/cdef", body: "blob"},
		member{name: "docs/.htaccess", body: "deny"},
		member{name: "docs/.well-known/nested.txt", body: "only the top-level one is allowed"},
		member{name: ".well-known/.hidden", body: "hidden inside the allowed folder"},
		member{name: ".well-known/security.txt", body: "ok"},
		member{name: "docs/guide.html", body: "guide"},
	), dest, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Files != 3 || rep.SkippedHidden != 6 {
		t.Errorf("report: %+v", rep)
	}
	sameTree(t, "site", tree(t, dest), map[string]string{
		"index.html":               "home",
		"docs":                     "<dir>",
		"docs/guide.html":          "guide",
		".well-known":              "<dir>",
		".well-known/security.txt": "ok",
	})
}

func TestLinksAndSpecialFilesAreLeftOut(t *testing.T) {
	dest := t.TempDir()
	rep, err := Install(makeZip(t,
		member{name: "index.html", body: "home"},
		member{name: "passwd", body: "/etc/passwd", mode: fs.ModeSymlink | 0o777},
		member{name: "up", body: "../..", mode: fs.ModeSymlink | 0o777},
		member{name: "pipe", mode: fs.ModeNamedPipe | 0o644},
		member{name: "dev", mode: fs.ModeDevice | 0o644},
	), dest, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Files != 1 || rep.SkippedSpecial != 4 {
		t.Errorf("report: %+v", rep)
	}
	sameTree(t, "site", tree(t, dest), map[string]string{"index.html": "home"})
}

// Finder writes a file twice when a folder and the files inside it were both
// selected before choosing Compress (found with the first real archive,
// 2026-11-18). As with unzip, the later entry stands; it is unpacked and
// counted once, and only it counts toward the limits.
func TestTheSamePathTwice(t *testing.T) {
	dest := t.TempDir()
	rep, err := Install(makeZip(t,
		member{name: "index.html", body: "home"},
		member{name: "fonts/", mode: fs.ModeDir | 0o755},
		member{name: "fonts/a.woff2", body: "first copy, longer than the second"},
		member{name: "fonts/OFL.txt", body: "license"},
		member{name: "fonts/a.woff2", body: "second"},
		member{name: "./fonts/OFL.txt", body: "license"},
		member{name: "index.html", body: "home, again"},
	), dest, Options{MaxFiles: 3, MaxBytes: int64(len("home, again") + len("second") + len("license"))})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Files != 3 || rep.Bytes != int64(len("home, again")+len("second")+len("license")) {
		t.Errorf("report: %+v", rep)
	}
	sameTree(t, "site", tree(t, dest), map[string]string{
		"index.html":    "home, again",
		"fonts":         "<dir>",
		"fonts/a.woff2": "second",
		"fonts/OFL.txt": "license",
	})
}

// Some Windows tools write backslashes; they are separators, and the
// result is checked like any other path.
func TestBackslashNames(t *testing.T) {
	dest := t.TempDir()
	rep, err := Install(makeZip(t,
		member{name: `site\index.html`, body: "home"},
		member{name: `site\css\a.css`, body: "css"},
	), dest, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Wrapper != "site" || rep.Files != 2 {
		t.Errorf("report: %+v", rep)
	}
	sameTree(t, "site", tree(t, dest), map[string]string{"index.html": "home", "css": "<dir>", "css/a.css": "css"})
}

// Every archive that is refused leaves the site exactly as it was.
func TestRefusedArchivesChangeNothing(t *testing.T) {
	index := member{name: "index.html", body: "home"}
	many := []member{index}
	for i := 0; i < 5; i++ {
		many = append(many, member{name: "f" + string(rune('a'+i)) + ".txt", body: "x"})
	}
	for _, tc := range []struct {
		name    string
		members []member
		opts    Options
		want    string
	}{
		{"parent path", []member{index, {name: "../evil.html", body: "x"}}, Options{}, "outside the archive"},
		{"parent path in the middle", []member{index, {name: "a/../../evil.html", body: "x"}}, Options{}, "outside the archive"},
		{"parent path with backslashes", []member{index, {name: `a\..\..\evil.html`, body: "x"}}, Options{}, "outside the archive"},
		{"absolute path", []member{index, {name: "/etc/cron.d/evil", body: "x"}}, Options{}, "absolute path"},
		{"drive path", []member{index, {name: `C:\Windows\evil`, body: "x"}}, Options{}, "absolute path"},
		{"control character", []member{index, {name: "a\nb.html", body: "x"}}, Options{}, "control character"},
		{"NUL in a name", []member{index, {name: "a\x00.html", body: "x"}}, Options{}, "control character"},
		{"invalid UTF-8", []member{index, {name: "a\xff.html", body: "x", raw: func(h *zip.FileHeader) { h.NonUTF8 = true }}}, Options{}, "not valid UTF-8"},
		{"a name too long", []member{index, {name: strings.Repeat("a", 256) + ".html", body: "x"}}, Options{}, "longer than 255"},
		{"a file that is also a folder", []member{index, {name: "a", body: "1"}, {name: "a/b.html", body: "2"}}, Options{}, "both a file and a folder"},
		{"no index", []member{{name: "home.html", body: "x"}}, Options{}, "no index.html at the top level"},
		{"index two folders down", []member{{name: "a/b/index.html", body: "x"}}, Options{}, "no index.html at the top level"},
		{"index in one of two folders", []member{{name: "a/index.html", body: "x"}, {name: "b/other.html", body: "x"}}, Options{}, "no index.html at the top level"},
		{"index is a folder", []member{{name: "index.html/", mode: fs.ModeDir | 0o755}, {name: "index.html/x", body: "x"}}, Options{}, "no index.html at the top level"},
		{"only hidden files", []member{{name: ".git/index.html", body: "x"}}, Options{}, "no index.html at the top level"},
		{"too many files", many, Options{MaxFiles: 5}, "the most a site may have is 5"},
		{"too large unpacked", []member{index, {name: "big.bin", body: strings.Repeat("A", 4096)}}, Options{MaxBytes: 4000}, "unpacks to more than"},
		{"password-protected", []member{{name: "index.html", body: "x", raw: func(h *zip.FileHeader) { h.Flags |= 0x1 }}}, Options{}, "password-protected"},
		{"archive too large", []member{index}, Options{MaxArchive: 10}, "the archive is larger than"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dest := t.TempDir()
			write(t, dest, "index.html", "the site that is live")
			write(t, dest, "img/a.png", "PNG")
			before := tree(t, dest)
			_, err := Install(makeZip(t, tc.members...), dest, tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want one containing %q", err, tc.want)
			}
			sameTree(t, "site after a refused archive", tree(t, dest), before)
		})
	}

	t.Run("not a zip", func(t *testing.T) {
		dest := t.TempDir()
		write(t, dest, "index.html", "live")
		before := tree(t, dest)
		p := filepath.Join(t.TempDir(), "site.zip")
		if err := os.WriteFile(p, []byte("<html>this is not an archive</html>"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Install(p, dest, Options{}); err == nil || !strings.Contains(err.Error(), "not a zip archive") {
			t.Fatalf("error %v", err)
		}
		if _, err := Install(filepath.Join(t.TempDir(), "missing.zip"), dest, Options{}); err == nil {
			t.Fatal("a missing archive was accepted")
		}
		sameTree(t, "site", tree(t, dest), before)
	})
	t.Run("no site folder", func(t *testing.T) {
		if _, err := Install(makeZip(t, index), filepath.Join(t.TempDir(), "nope"), Options{}); err == nil {
			t.Fatal("installed into a folder that does not exist")
		}
	})
}

// The unpacked size is bounded by what comes out, not by what the archive
// says will.
func TestWriteStopsAtTheLimit(t *testing.T) {
	p := makeZip(t, member{name: "index.html", body: strings.Repeat("A", 100_000)})
	zr, err := zip.OpenReader(p)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	target := filepath.Join(t.TempDir(), "out")
	if n, err := writeFile(zr.File[0], target, 99_999); err != errTooLarge || n > 100_000 {
		t.Fatalf("wrote %d bytes, err %v; want errTooLarge", n, err)
	}
	if n, err := writeFile(zr.File[0], target+"2", 100_000); err != nil || n != 100_000 {
		t.Fatalf("exactly at the limit: %d %v", n, err)
	}
	// It never writes over something that is already there.
	if _, err := writeFile(zr.File[0], target+"2", 1<<20); err == nil {
		t.Fatal("wrote over an existing file")
	}
}

func TestRemove(t *testing.T) {
	dest := t.TempDir()
	write(t, dest, "index.html", "home")
	write(t, dest, "img/a.png", "PNG")
	write(t, dest, "img/deep/b.png", "PNG")
	write(t, dest, ".well-known/security.txt", "x")
	write(t, dest, ".incoming/half.html", "leftover")
	n, err := Remove(dest)
	if err != nil || n != 4 {
		t.Fatalf("removed %d, err %v; want 4", n, err)
	}
	if left := tree(t, dest); len(left) != 0 {
		t.Errorf("left behind: %v", left)
	}
	if st, err := os.Stat(dest); err != nil || !st.IsDir() {
		t.Error("the site folder itself must stay: it is a mount point")
	}
	if Present(dest) {
		t.Error("Present is true for an empty folder")
	}
	if n, err := Remove(dest); err != nil || n != 0 {
		t.Errorf("removing an empty site: %d %v", n, err)
	}
}

func TestServed(t *testing.T) {
	for p, want := range map[string]bool{
		"/":                          true,
		"/index.html":                true,
		"/img/logo.png":              true,
		"/.well-known/security.txt":  true,
		"/.well-known":               true,
		"/a.b/c.d.html":              true,
		"/.env":                      false,
		"/.git/config":               false,
		"/.incoming/index.html":      false,
		"/.outgoing/index.html":      false,
		"/docs/.htaccess":            false,
		"/docs/.well-known/x":        false,
		"/.well-known/.hidden":       false,
		"//.env":                     false,
		"/img/../.env":               false,
		"/..":                        false,
		"/.":                         false,
		"/...":                       false,
		"/img/.DS_Store":             false,
		"/.well-known/acme/../../.x": false,
	} {
		if got := Served(p); got != want {
			t.Errorf("Served(%q) = %v, want %v", p, got, want)
		}
	}
}
