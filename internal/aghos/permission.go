package aghos

import "io/fs"

// Chmod is an extension for [os.Chmod] that properly handles Windows access
// rights.
//
// TODO(e.burkov):  !! use.
func Chmod(name string, perm fs.FileMode) (err error) {
	return chmod(name, perm)
}

// Mkdir is an extension for [os.Chmod] that properly handles Windows access
// rights.
//
// TODO(e.burkov):  !! use.
func Mkdir(name string, perm fs.FileMode) (err error) {
	return mkdir(name, perm)
}

// Stat is an extension for [os.Stat] that properly handles Windows access
// rights.
//
// TODO(e.burkov):  !! use.
func Stat(name string) (fi fs.FileInfo, err error) {
	return stat(name)
}

// TODO(e.burkov):  !! add tests.
