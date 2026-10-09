package tokens

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DropinName is the folder next to the tokens file whose files add tokens in
// the same line format. A provisioning tool owns them: a rebuilt VM gets its
// tokens back, and removing a file or a line takes the access away.
const DropinName = "tokens.d"

const (
	maxDropinFiles = 1000
	maxDropinSize  = 1 << 20
)

// DropinDir is the drop-in folder that belongs to the tokens file at path.
func DropinDir(path string) string { return filepath.Join(filepath.Dir(path), DropinName) }

// Refused is something the store ignored on purpose, and why.
type Refused struct {
	File   string // file name inside the drop-in folder, or "" for the folder itself
	Reason string
	sum    [32]byte // of the file's content, so a log line repeats only when the file changed
}

func (r Refused) String() string {
	if r.File == "" {
		return DropinName + ": " + r.Reason
	}
	return DropinName + "/" + r.File + ": " + r.Reason
}

type dropFile struct {
	name    string
	sum     [32]byte
	entries []Entry
}

// readDropins returns the usable files of dir in file-name order. Every file
// stands on its own: a file that is a symlink, has the wrong mode or owner,
// cannot be read or does not parse is refused and the others keep working. A
// folder that others can write to is refused as a whole, because anyone could
// add a file.
func readDropins(dir string) ([]dropFile, []Refused) {
	di, err := os.Lstat(dir)
	if err != nil {
		return nil, nil // no folder: nothing to read
	}
	if !di.IsDir() {
		return nil, []Refused{{Reason: "is not a folder (a symlink or a file); ignored"}}
	}
	if di.Mode().Perm()&0o022 != 0 {
		return nil, []Refused{{Reason: "is writable by group or others; ignored (chmod 700)"}}
	}
	if !ownerOK(di) {
		return nil, []Refused{{Reason: "belongs to another user; ignored"}}
	}
	names, err := os.ReadDir(dir)
	if err != nil {
		return nil, []Refused{{Reason: "cannot be read: " + err.Error()}}
	}
	sort.Slice(names, func(i, j int) bool { return names[i].Name() < names[j].Name() })
	var files []dropFile
	var refused []Refused
	for i, de := range names {
		name := de.Name()
		if strings.HasPrefix(name, ".") || strings.HasSuffix(name, "~") {
			continue // editor and temp files
		}
		if i >= maxDropinFiles {
			refused = append(refused, Refused{File: name, Reason: "too many files; ignored"})
			continue
		}
		f, why := readDropin(filepath.Join(dir, name), name)
		if why != "" {
			refused = append(refused, Refused{File: name, Reason: why, sum: f.sum})
			continue
		}
		files = append(files, f)
	}
	return files, refused
}

// readDropin reads one file; the second result is why it was refused, if so.
func readDropin(path, name string) (dropFile, string) {
	if !nameRe.MatchString(name) {
		return dropFile{}, "name must be 1-64 chars of letters, digits, . _ @ -; ignored"
	}
	li, err := os.Lstat(path)
	if err != nil {
		return dropFile{}, "cannot be read: " + err.Error()
	}
	if !li.Mode().IsRegular() {
		return dropFile{}, "is not a regular file (a symlink?); ignored"
	}
	if li.Mode().Perm()&0o077 != 0 {
		return dropFile{}, fmt.Sprintf("mode %04o lets group or others in; ignored (chmod 600)", li.Mode().Perm())
	}
	if !ownerOK(li) {
		return dropFile{}, "belongs to another user; ignored (it must belong to root or to the gateway's user)"
	}
	f, err := os.Open(path)
	if err != nil {
		return dropFile{}, "cannot be read: " + err.Error() + " (it must belong to the user the gateway runs as)"
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !os.SameFile(li, fi) {
		return dropFile{}, "changed while it was being read; ignored"
	}
	if fi.Size() > maxDropinSize {
		return dropFile{}, "is too big; ignored"
	}
	b, err := io.ReadAll(io.LimitReader(f, maxDropinSize+1))
	if err != nil {
		return dropFile{}, "cannot be read: " + err.Error()
	}
	sum := sha256.Sum256(b)
	entries, err := Parse(b, name)
	if err != nil {
		return dropFile{sum: sum}, "does not parse (" + err.Error() + "); ignored"
	}
	for i := range entries {
		entries[i].Source = DropinName + "/" + name
	}
	return dropFile{name: name, sum: sum, entries: entries}, ""
}

// merge puts the drop-in entries after the entries of the main file. The
// first entry with a name or a hash wins; a later one is refused, so a drop-in
// can never shadow another entry.
func merge(main []Entry, files []dropFile) ([]Entry, []Refused) {
	out := append([]Entry(nil), main...)
	names := map[string]bool{}
	hashes := map[[32]byte]bool{}
	for _, e := range out {
		names[e.Name], hashes[e.Hash] = true, true
	}
	var refused []Refused
	for _, f := range files {
		for _, e := range f.entries {
			switch {
			case names[e.Name]:
				refused = append(refused, Refused{File: f.name, sum: f.sum, Reason: fmt.Sprintf("token %q is already defined elsewhere; this line is ignored", e.Name)})
			case hashes[e.Hash]:
				refused = append(refused, Refused{File: f.name, sum: f.sum, Reason: fmt.Sprintf("the token of %q is already used by another entry; this line is ignored", e.Name)})
			default:
				names[e.Name], hashes[e.Hash] = true, true
				out = append(out, e)
			}
		}
	}
	return out, refused
}

// LoadAll is Load plus the drop-in folder: every entry with the file it came
// from, and what was ignored. Meant for people (`token ls`), not for the
// gateway.
func LoadAll(path string) ([]Entry, []Refused, error) {
	main, err := Load(path)
	if err != nil && !isNotExist(err) {
		return nil, nil, err
	}
	files, refused := readDropins(DropinDir(path))
	entries, dup := merge(main, files)
	return entries, append(refused, dup...), nil
}

func isNotExist(err error) bool { return os.IsNotExist(err) }

// dropinSource names the drop-in file that defines name, if one does.
func dropinSource(path, name string) (string, bool) {
	files, _ := readDropins(DropinDir(path))
	for _, f := range files {
		for _, e := range f.entries {
			if e.Name == name {
				return e.Source, true
			}
		}
	}
	return "", false
}
