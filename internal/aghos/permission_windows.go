//go:build windows

package aghos

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"golang.org/x/sys/windows"
)

// fileInfo is a Windows implementation of [fs.FileInfo], that contains the
// filemode converted from the security descriptor.
type fileInfo struct {
	// fs.FileInfo is embedded to provide the default implementations and info
	// successfully retrieved by [os.Stat].
	fs.FileInfo

	// mode is the file mode converted from the security descriptor.
	mode fs.FileMode
}

// type check
var _ fs.FileInfo = (*fileInfo)(nil)

// Mode implements [fs.FileInfo.Mode] for [*fileInfo].
func (fi *fileInfo) Mode() (mode fs.FileMode) { return fi.mode }

// stat is a Windows implementation of [Stat].
func stat(name string) (fi os.FileInfo, err error) {
	fi, err = os.Stat(name)
	if err != nil {
		return nil, err
	}

	const objectType windows.SE_OBJECT_TYPE = windows.SE_FILE_OBJECT

	secInfo := windows.SECURITY_INFORMATION(
		windows.OWNER_SECURITY_INFORMATION |
			windows.GROUP_SECURITY_INFORMATION |
			windows.DACL_SECURITY_INFORMATION |
			windows.PROTECTED_DACL_SECURITY_INFORMATION,
	)

	sd, err := windows.GetNamedSecurityInfo(fi.Name(), objectType, secInfo)
	if err != nil {
		return nil, fmt.Errorf("getting security descriptor: %w", err)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, fmt.Errorf("getting discretionary access control list: %w", err)
	}

	owner, _, err := sd.Owner()
	if err != nil {
		return nil, fmt.Errorf("getting owner sid: %w", err)
	}

	group, _, err := sd.Group()
	if err != nil {
		return nil, fmt.Errorf("getting group sid: %w", err)
	}

	var ownerMask, groupMask, otherMask windows.ACCESS_MASK
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		err = windows.GetAce(dacl, i, &ace)
		if err != nil {
			return nil, fmt.Errorf("getting access control entry at index %d: %w", i, err)
		}

		entrySid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case entrySid.Equals(owner):
			ownerMask |= ace.Mask
		case entrySid.Equals(group):
			groupMask |= ace.Mask
		default:
			otherMask = ace.Mask
		}
	}

	mode := masksToPerm(ownerMask, groupMask, otherMask) | (fi.Mode().Perm() & ^fs.ModePerm)

	return &fileInfo{
		FileInfo: fi,
		mode:     mode,
	}, nil
}

// chmod is a Windows implementation of [Chmod].
func chmod(name string, perm fs.FileMode) (err error) {
	const objectType windows.SE_OBJECT_TYPE = windows.SE_FILE_OBJECT

	fi, err := os.Stat(name)
	if err != nil {
		return fmt.Errorf("getting file info: %w", err)
	}

	entries := make([]windows.EXPLICIT_ACCESS, 0, 3)
	creatorMask, groupMask, worldMask := permToMasks(perm, fi.IsDir())

	sidMasks := container.KeyValues[windows.WELL_KNOWN_SID_TYPE, windows.ACCESS_MASK]{{
		Key:   windows.WinCreatorOwnerSid,
		Value: creatorMask,
	}, {
		Key:   windows.WinCreatorGroupSid,
		Value: groupMask,
	}, {
		Key:   windows.WinWorldSid,
		Value: worldMask,
	}}

	var errs []error
	for _, sidMask := range sidMasks {
		if sidMask.Value == 0 {
			continue
		}

		var trustee *windows.TRUSTEE
		trustee, err = newWellKnownTrustee(sidMask.Key)
		if err != nil {
			errs = append(errs, err)

			continue
		}

		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: sidMask.Value,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee:           *trustee,
		})
	}

	if err = errors.Join(errs...); err != nil {
		return fmt.Errorf("creating access control entries: %w", err)
	}

	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("creating access control list: %w", err)
	}

	secInfo := windows.SECURITY_INFORMATION(
		windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION,
	)

	err = windows.SetNamedSecurityInfo(name, objectType, secInfo, nil, nil, acl, nil)
	if err != nil {
		return fmt.Errorf("setting security descriptor: %w", err)
	}

	return nil
}

// mkdir is a Windows implementation of [Mkdir].
//
// TODO(e.burkov):  Consider using [windows.CreateDirectory] instead of
// [os.Mkdir] to reduce the number of syscalls.
func mkdir(name string, perm os.FileMode) (err error) {
	name, err = filepath.Abs(name)
	if err != nil {
		return fmt.Errorf("computing absolute path: %w", err)
	}

	err = os.Mkdir(name, perm)
	if err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	defer func() {
		if err != nil {
			err = errors.WithDeferred(err, os.Remove(name))
		}
	}()

	return chmod(name, perm)
}

// mkdirAll is a Windows implementation of [MkdirAll].
func mkdirAll(path string, perm os.FileMode) (err error) {
	parent, _ := filepath.Split(path)

	err = os.MkdirAll(parent, perm)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("creating parent directories: %w", err)
	}

	err = mkdir(path, perm)
	if errors.Is(err, os.ErrExist) {
		return nil
	}

	return err
}

// writeFile is a Windows implementation of [WriteFile].
func writeFile(filename string, data []byte, perm os.FileMode) (err error) {
	file, err := openFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, file.Close()) }()

	_, err = file.Write(data)
	if err != nil {
		return fmt.Errorf("writing data: %w", err)
	}

	return nil
}

// openFile is a Windows implementation of [OpenFile].
func openFile(name string, flag int, perm os.FileMode) (file *os.File, err error) {
	// Only change permissions if the file not yet exists, but should be
	// created.
	if flag&os.O_CREATE == 0 {
		return os.OpenFile(name, flag, perm)
	}

	_, err = stat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			defer func() { err = errors.WithDeferred(err, chmod(name, perm)) }()
		} else {
			return nil, fmt.Errorf("getting file info: %w", err)
		}
	}

	return os.OpenFile(name, flag, perm)
}

// newWellKnownTrustee returns a trustee for a well-known SID.
func newWellKnownTrustee(stype windows.WELL_KNOWN_SID_TYPE) (t *windows.TRUSTEE, err error) {
	sid, err := windows.CreateWellKnownSid(stype)
	if err != nil {
		return nil, fmt.Errorf("creating sid for type %d: %w", stype, err)
	}

	return &windows.TRUSTEE{
		TrusteeForm:  windows.TRUSTEE_IS_SID,
		TrusteeValue: windows.TrusteeValueFromSID(sid),
	}, nil
}

// Constants reflecting the UNIX permission bits.
const (
	ownerWrite = 0b010_000_000
	groupWrite = 0b000_010_000
	worldWrite = 0b000_000_010

	ownerRead = 0b100_000_000
	groupRead = 0b000_100_000
	worldRead = 0b000_000_100

	ownerAll = 0b111_000_000
	groupAll = 0b000_111_000
	worldAll = 0b000_000_111
)

// Constants reflecting the number of bits to shift the UNIX permission bits to
// convert them to the generic access rights used by Windows, see
// https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/access-mask.
const (
	genericOwner = 23
	genericGroup = 26
	genericWorld = 29
)

// Constants reflecting the number of bits to shift the UNIX write permission
// bits to convert them to the access rights used by Windows.
const (
	deleteOwner = 9
	deleteGroup = 12
	deleteWorld = 15

	listDirOwner = 7
	listDirGroup = 10
	listDirWorld = 13

	traverseOwner = 2
	traverseGroup = 5
	traverseWorld = 8

	writeEAOwner = 2
	writeEAGroup = 1
	writeEAWorld = 4

	deleteChildOwner = 1
	deleteChildGroup = 4
	deleteChildWorld = 7
)

// permToMasks converts a UNIX file mode permissions to the corresponding
// Windows access masks.  The [isDir] argument is used to set specific access
// bits for directories.
func permToMasks(fm os.FileMode, isDir bool) (owner, group, world windows.ACCESS_MASK) {
	mask := windows.ACCESS_MASK(fm.Perm())

	owner = ((mask & ownerAll) << genericOwner) | ((mask & ownerWrite) << deleteOwner)
	group = ((mask & groupAll) << genericGroup) | ((mask & groupWrite) << deleteGroup)
	world = ((mask & worldAll) << genericWorld) | ((mask & worldWrite) << deleteWorld)

	if isDir {
		owner |= (mask & ownerRead) << listDirOwner
		group |= (mask & groupRead) << listDirGroup
		world |= (mask & worldRead) << listDirWorld

		owner |= (mask & ownerRead) << traverseOwner
		group |= (mask & groupRead) << traverseGroup
		world |= (mask & worldRead) << traverseWorld

		owner |= (mask & ownerWrite) << deleteChildOwner
		group |= (mask & groupWrite) << deleteChildGroup
		world |= (mask & worldWrite) << deleteChildWorld

		owner |= (mask & ownerWrite) >> writeEAOwner
		group |= (mask & groupWrite) << writeEAGroup
		world |= (mask & worldWrite) << writeEAWorld
	}

	return owner, group, world
}

// masksToPerm converts Windows access masks to the corresponding UNIX file
// mode permission bits.
func masksToPerm(u, g, o windows.ACCESS_MASK) (perm os.FileMode) {
	perm |= os.FileMode(((u >> genericOwner) & ownerAll) | ((u >> deleteOwner) & ownerWrite))
	perm |= os.FileMode(((g >> genericGroup) & groupAll) | ((g >> deleteGroup) & groupWrite))
	perm |= os.FileMode(((o >> genericWorld) & worldAll) | ((o >> deleteWorld) & worldWrite))

	return perm
}
