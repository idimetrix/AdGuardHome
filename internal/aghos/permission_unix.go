//go:build unix

package aghos

import (
	"io/fs"
	"os"
)

// chmod is a Unix implementation of [Chmod].
func chmod(name string, perm fs.FileMode) (err error) {
	return os.Chmod(name, perm)
}

// mkdir is a Unix implementation of [Mkdir].
func mkdir(name string, perm fs.FileMode) (err error) {
	return os.Mkdir(name, perm)
}

// mkdirAll is a Unix implementation of [MkdirAll].
func mkdirAll(path string, perm fs.FileMode) (err error) {
	return os.MkdirAll(path, perm)
}

// writeFile is a Unix implementation of [WriteFile].
func writeFile(filename string, data []byte, perm fs.FileMode) (err error) {
	return os.WriteFile(filename, data, perm)
}

// stat is a Unix implementation of [Stat].
func stat(name string) (fi os.FileInfo, err error) {
	return os.Stat(name)
}
