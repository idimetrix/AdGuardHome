//go:build !windows

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
