// Package site installs and removes the optional static site that edge
// serves at the root of the public domain.
//
// The operator uploads one zip archive through a StartOS action. This
// package is what turns that archive into files, and it treats the archive
// as hostile: a zip is a list of names and bytes chosen by whoever made it,
// and the files it produces are served to the internet. So nothing is
// written outside the site folder, nothing but regular files and folders is
// created, the unpacked size and the number of files are bounded by what is
// read rather than by what the archive claims, and hidden files are left
// out, because the folder an operator zips is often a project folder with a
// .git or a .env in it and those are exactly what scanners ask for.
//
// It runs as a one-off command (`edge site ...`) in a throwaway container
// that mounts the upload and site folders and nothing else. No daemon
// parses an upload.
package site

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// Limits. The archive's own size is bounded by StartOS when it is uploaded
// and checked again here.
const (
	DefaultMaxArchive = 50 << 20  // bytes of zip
	DefaultMaxBytes   = 200 << 20 // bytes unpacked
	DefaultMaxFiles   = 2000      // files unpacked
	maxEntries        = 20000     // entries listed in the archive, whatever becomes of them
	maxNameLen        = 1024
	maxSegmentLen     = 255

	// Work folders inside the site folder. Edge never serves a hidden
	// path, so nothing in them is reachable while an install is under way.
	incomingDir = ".incoming"
	outgoingDir = ".outgoing"

	indexFile = "index.html"
	wellKnown = ".well-known"
)

// Options for Install. Zero limits mean the defaults.
type Options struct {
	// Keep leaves the files already in the site folder in place and adds
	// the archive's on top, replacing those with the same path. Without
	// it the archive becomes the whole site.
	Keep       bool
	MaxArchive int64
	MaxBytes   int64
	MaxFiles   int
}

// Report says what an install did.
type Report struct {
	Files          int    `json:"files"`           // files installed
	Bytes          int64  `json:"bytes"`           // their total size
	Wrapper        string `json:"wrapper"`         // top-level folder the archive wrapped everything in, removed
	SkippedHidden  int    `json:"skipped_hidden"`  // hidden files and system clutter left out
	SkippedSpecial int    `json:"skipped_special"` // links and other non-files left out
	Removed        int    `json:"removed"`         // files of the previous site removed (replace only)
	Kept           bool   `json:"kept"`            // existing files were kept
}

// entry is one archive member as the planner sees it.
type entry struct {
	name    string // as written in the archive
	dir     bool
	special bool // symlink, device, pipe: anything that is not a file or a folder
	size    uint64
	index   int // position in the archive
}

// item is one thing to create.
type item struct {
	rel   string // slash-separated, relative to the site root
	dir   bool
	index int    // which archive member to unpack
	size  uint64 // what that member says it unpacks to
}

// cleanName splits an archive member's name into path segments, or says why
// the name cannot be trusted. Backslashes are separators too: some Windows
// tools write them.
func cleanName(raw string) ([]string, error) {
	if raw == "" {
		return nil, errors.New("an entry has no name")
	}
	if len(raw) > maxNameLen {
		return nil, fmt.Errorf("an entry's name is longer than %d bytes", maxNameLen)
	}
	if !utf8.ValidString(raw) {
		return nil, fmt.Errorf("the name %q is not valid UTF-8", raw)
	}
	name := strings.ReplaceAll(raw, `\`, "/")
	if strings.HasPrefix(name, "/") {
		return nil, fmt.Errorf("%q is an absolute path", raw)
	}
	var segs []string
	for _, seg := range strings.Split(name, "/") {
		switch seg {
		case "", ".":
			continue
		case "..":
			return nil, fmt.Errorf("%q points outside the archive", raw)
		}
		if len(seg) > maxSegmentLen {
			return nil, fmt.Errorf("a name in %q is longer than %d bytes", raw, maxSegmentLen)
		}
		for _, r := range seg {
			if r < 0x20 || r == 0x7f {
				return nil, fmt.Errorf("the name %q contains a control character", raw)
			}
		}
		segs = append(segs, seg)
	}
	if len(segs) > 0 && len(segs[0]) == 2 && segs[0][1] == ':' {
		return nil, fmt.Errorf("%q is an absolute path", raw)
	}
	return segs, nil
}

// clutter reports files that operating systems add to folders and archives
// and that are never part of a site.
func clutter(segs []string) bool {
	for _, s := range segs {
		if s == "__MACOSX" {
			return true
		}
	}
	switch strings.ToLower(segs[len(segs)-1]) {
	case "thumbs.db", "desktop.ini":
		return true
	}
	return false
}

// hidden reports whether a path relative to the site root has a hidden
// segment. One is allowed: a top-level .well-known folder, which is where
// standards put files such as security.txt.
func hidden(segs []string) bool {
	for i, s := range segs {
		if strings.HasPrefix(s, ".") && !(i == 0 && s == wellKnown) {
			return true
		}
	}
	return false
}

// Served reports whether edge may serve this URL path from the site folder.
// It is the same rule the installer applies, enforced again at request time
// because the folder can also be filled by hand.
func Served(urlPath string) bool {
	var segs []string
	for _, s := range strings.Split(urlPath, "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}
	return !hidden(segs)
}

// plan decides what an archive's entries become, without touching a disk.
func plan(entries []entry, o Options) ([]item, Report, error) {
	var rep Report
	if len(entries) > maxEntries {
		return nil, rep, fmt.Errorf("the archive lists more than %d entries", maxEntries)
	}
	type cand struct {
		segs []string
		e    entry
	}
	var cands []cand
	for _, e := range entries {
		segs, err := cleanName(e.name)
		if err != nil {
			return nil, rep, err
		}
		if len(segs) == 0 {
			continue
		}
		if clutter(segs) || strings.HasPrefix(segs[0], ".") && segs[0] != wellKnown {
			if !e.dir {
				rep.SkippedHidden++
			}
			continue
		}
		cands = append(cands, cand{segs, e})
	}

	// Compressing a folder in Finder or Explorer puts the folder itself at
	// the top of the archive. If everything sits in one folder and the
	// index is in it, that folder is packaging, not part of the site.
	rootIndex, common, wrapped := false, "", true
	for _, c := range cands {
		if len(c.segs) == 1 && !c.e.dir && c.segs[0] == indexFile {
			rootIndex = true
		}
		if common == "" {
			common = c.segs[0]
		} else if c.segs[0] != common {
			wrapped = false
		}
	}
	if !rootIndex && wrapped && common != "" && common != wellKnown {
		for _, c := range cands {
			if len(c.segs) == 2 && !c.e.dir && c.segs[1] == indexFile {
				rep.Wrapper = common
				break
			}
		}
	}

	files := map[string]int{} // path -> position in items
	dirs := map[string]bool{}
	var items []item
	var total uint64
	for _, c := range cands {
		segs := c.segs
		if rep.Wrapper != "" {
			segs = segs[1:]
			if len(segs) == 0 {
				continue // the wrapping folder's own entry
			}
		}
		if hidden(segs) {
			if !c.e.dir {
				rep.SkippedHidden++
			}
			continue
		}
		if c.e.special {
			rep.SkippedSpecial++
			continue
		}
		rel := strings.Join(segs, "/")
		for i := 1; i < len(segs); i++ {
			dirs[strings.Join(segs[:i], "/")] = true
		}
		if c.e.dir {
			dirs[rel] = true
			items = append(items, item{rel: rel, dir: true, index: c.e.index})
			continue
		}
		// The same path twice is ordinary, not an attack: Finder writes a
		// file twice when a folder and the files inside it were both
		// selected. As unzip does, the later one stands, and it is counted
		// and unpacked once.
		if at, again := files[rel]; again {
			total += c.e.size - items[at].size
			items[at].index, items[at].size = c.e.index, c.e.size
			continue
		}
		files[rel] = len(items)
		total += c.e.size
		items = append(items, item{rel: rel, index: c.e.index, size: c.e.size})
	}
	for f := range files {
		if dirs[f] {
			return nil, rep, fmt.Errorf("%q is both a file and a folder in the archive", f)
		}
	}
	if _, ok := files[indexFile]; !ok {
		return nil, rep, fmt.Errorf("there is no %s at the top level of the archive", indexFile)
	}
	maxFiles, maxBytes := o.MaxFiles, o.MaxBytes
	if maxFiles <= 0 {
		maxFiles = DefaultMaxFiles
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if len(files) > maxFiles {
		return nil, rep, fmt.Errorf("the archive holds %d files; the most a site may have is %d", len(files), maxFiles)
	}
	if total > uint64(maxBytes) {
		return nil, rep, fmt.Errorf("the archive unpacks to more than %s", megabytes(maxBytes))
	}
	// Folders first, then files in the archive's order.
	sort.SliceStable(items, func(i, j int) bool { return items[i].dir && !items[j].dir })
	return items, rep, nil
}

func megabytes(n int64) string { return fmt.Sprintf("%d MB", n>>20) }

// Install unpacks the zip at archive into the site folder dest. Nothing in
// dest changes unless the whole archive unpacked cleanly.
func Install(archive, dest string, o Options) (Report, error) {
	maxArchive, maxBytes := o.MaxArchive, o.MaxBytes
	if maxArchive <= 0 {
		maxArchive = DefaultMaxArchive
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	st, err := os.Lstat(archive)
	if err != nil {
		return Report{}, errors.New("the uploaded archive is missing")
	}
	if !st.Mode().IsRegular() {
		return Report{}, errors.New("the uploaded archive is not a file")
	}
	if st.Size() > maxArchive {
		return Report{}, fmt.Errorf("the archive is larger than %s", megabytes(maxArchive))
	}
	if dst, err := os.Stat(dest); err != nil || !dst.IsDir() {
		return Report{}, errors.New("the site folder is missing")
	}
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return Report{}, errors.New("the file is not a zip archive, or it is damaged")
	}
	defer zr.Close()

	entries := make([]entry, 0, len(zr.File))
	for i, f := range zr.File {
		if f.Flags&0x1 != 0 {
			return Report{}, errors.New("the archive is password-protected, which is not supported")
		}
		mode := f.Mode()
		isDir := mode.IsDir() || strings.HasSuffix(f.Name, "/") || strings.HasSuffix(f.Name, `\`)
		entries = append(entries, entry{
			name:    f.Name,
			dir:     isDir,
			special: !isDir && mode&fs.ModeType != 0,
			size:    f.UncompressedSize64,
			index:   i,
		})
	}
	items, rep, err := plan(entries, o)
	if err != nil {
		return rep, err
	}

	incoming := filepath.Join(dest, incomingDir)
	if err := os.RemoveAll(incoming); err != nil {
		return rep, fmt.Errorf("clear work folder: %w", err)
	}
	if err := os.Mkdir(incoming, 0o755); err != nil {
		return rep, fmt.Errorf("create work folder: %w", err)
	}
	fail := func(err error) (Report, error) {
		_ = os.RemoveAll(incoming)
		return rep, err
	}
	left := maxBytes // what may still be written; a header's claimed size is not trusted
	for _, it := range items {
		target := filepath.Join(incoming, filepath.FromSlash(it.rel))
		if it.dir {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fail(fmt.Errorf("create folder %q: %w", it.rel, err))
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fail(fmt.Errorf("create folder for %q: %w", it.rel, err))
		}
		n, err := writeFile(zr.File[it.index], target, left)
		if err != nil {
			if errors.Is(err, errTooLarge) {
				return fail(fmt.Errorf("the archive unpacks to more than %s", megabytes(maxBytes)))
			}
			return fail(fmt.Errorf("unpack %q: %w", it.rel, err))
		}
		left -= n
		rep.Bytes += n
		rep.Files++
	}

	// Whatever umask this ran under, edge (another user) has to read these.
	if err := normalize(incoming); err != nil {
		return fail(fmt.Errorf("set permissions: %w", err))
	}

	if o.Keep {
		rep.Kept = true
		if err := mergeInto(incoming, dest); err != nil {
			return fail(fmt.Errorf("install files: %w", err))
		}
	} else {
		removed, err := swapIn(incoming, dest)
		rep.Removed = removed
		if err != nil {
			return fail(fmt.Errorf("install files: %w", err))
		}
	}
	if err := os.RemoveAll(incoming); err != nil {
		return rep, fmt.Errorf("clear work folder: %w", err)
	}
	return rep, nil
}

var errTooLarge = errors.New("too large")

// writeFile writes one archive member to a new file and returns its size.
// It stops as soon as more than limit bytes have come out of it.
func writeFile(f *zip.File, target string, limit int64) (int64, error) {
	rc, err := f.Open()
	if err != nil {
		if errors.Is(err, zip.ErrAlgorithm) {
			return 0, errors.New("it is compressed in a way that is not supported")
		}
		return 0, err
	}
	defer rc.Close()
	// O_EXCL: the work folder was empty and only this function creates
	// files in it, so anything already at the path is a bug, not a file to
	// write through.
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(out, io.LimitReader(rc, limit+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return n, err
	}
	if n > limit {
		return n, errTooLarge
	}
	return n, nil
}

// normalize makes every folder under dir 0755 and every file 0644.
func normalize(dir string) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Chmod(p, 0o755)
		}
		return os.Chmod(p, 0o644)
	})
}

// countFiles counts the regular files under dir.
func countFiles(dir string) int {
	n := 0
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			n++
		}
		return nil
	})
	return n
}

// swapIn makes the contents of incoming the whole site: what was there is
// moved aside first and deleted afterwards, so the site is never a mixture
// of old and new for longer than the renames take.
func swapIn(incoming, dest string) (removed int, err error) {
	outgoing := filepath.Join(dest, outgoingDir)
	if err := os.RemoveAll(outgoing); err != nil {
		return 0, err
	}
	if err := os.Mkdir(outgoing, 0o755); err != nil {
		return 0, err
	}
	old, err := os.ReadDir(dest)
	if err != nil {
		return 0, err
	}
	for _, e := range old {
		if e.Name() == incomingDir || e.Name() == outgoingDir {
			continue
		}
		if err := os.Rename(filepath.Join(dest, e.Name()), filepath.Join(outgoing, e.Name())); err != nil {
			return 0, err
		}
	}
	// From here a failure must not leave the old site stranded in the
	// work folder: put back whatever the new one did not replace.
	restore := func(cause error) (int, error) {
		for _, e := range old {
			back := filepath.Join(dest, e.Name())
			if _, err := os.Lstat(back); errors.Is(err, fs.ErrNotExist) {
				_ = os.Rename(filepath.Join(outgoing, e.Name()), back)
			}
		}
		_ = os.RemoveAll(outgoing)
		return 0, cause
	}
	fresh, err := os.ReadDir(incoming)
	if err != nil {
		return restore(err)
	}
	for _, e := range fresh {
		if err := os.Rename(filepath.Join(incoming, e.Name()), filepath.Join(dest, e.Name())); err != nil {
			return restore(err)
		}
	}
	removed = countFiles(outgoing)
	return removed, os.RemoveAll(outgoing)
}

// mergeInto moves the contents of incoming over what is in dest, replacing
// files at the same path and leaving everything else. Whatever stands where
// a folder is needed and is not a folder (a file, or a link someone put
// there by hand) is replaced by a real folder, so nothing is ever written
// through a link.
func mergeInto(incoming, dest string) error {
	return filepath.WalkDir(incoming, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(incoming, p)
		if err != nil || rel == "." {
			return err
		}
		target := filepath.Join(dest, rel)
		st, lerr := os.Lstat(target)
		if d.IsDir() {
			if lerr == nil && !st.IsDir() {
				if err := os.RemoveAll(target); err != nil {
					return err
				}
				lerr = fs.ErrNotExist
			}
			if lerr != nil {
				if err := os.Mkdir(target, 0o755); err != nil {
					return err
				}
				return os.Chmod(target, 0o755)
			}
			return nil
		}
		if lerr == nil && st.IsDir() {
			if err := os.RemoveAll(target); err != nil {
				return err
			}
		}
		return os.Rename(p, target)
	})
}

// Remove empties the site folder, work folders included, and returns how
// many files it removed. The folder itself stays: it is a mount point.
func Remove(dest string) (int, error) {
	entries, err := os.ReadDir(dest)
	if err != nil {
		return 0, fmt.Errorf("read the site folder: %w", err)
	}
	removed := 0
	for _, e := range entries {
		p := filepath.Join(dest, e.Name())
		if e.Name() != incomingDir && e.Name() != outgoingDir {
			if e.IsDir() {
				removed += countFiles(p)
			} else {
				removed++
			}
		}
		if err := os.RemoveAll(p); err != nil {
			return removed, fmt.Errorf("remove %q: %w", e.Name(), err)
		}
	}
	return removed, nil
}

// Present reports whether dir holds a site: an index.html that is a file.
func Present(dir string) bool {
	st, err := os.Stat(filepath.Join(dir, indexFile))
	return err == nil && st.Mode().IsRegular()
}
