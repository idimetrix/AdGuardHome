package aghos

import "io/fs"

// TODO(e.burkov):  Add platform-independent tests.

// Chmod is an extension for [os.Chmod] that properly handles Windows access
// rights.
func Chmod(name string, perm fs.FileMode) (err error) {
	return chmod(name, perm)
}

// Mkdir is an extension for [os.Mkdir] that properly handles Windows access
// rights.
func Mkdir(name string, perm fs.FileMode) (err error) {
	return mkdir(name, perm)
}

// MkdirAll is an extension for [os.MkdirAll] that properly handles Windows
// access rights.
func MkdirAll(path string, perm fs.FileMode) (err error) {
	return mkdirAll(path, perm)
}

// WriteFile is an extension for [os.WriteFile] that properly handles Windows
// access rights.
func WriteFile(filename string, data []byte, perm fs.FileMode) (err error) {
	return writeFile(filename, data, perm)
}

// Stat is an extension for [os.Stat] that properly handles Windows access
// rights.
func Stat(name string) (fi fs.FileInfo, err error) {
	return stat(name)
}
