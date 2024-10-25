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

	secInfo := windows.SECURITY_INFORMATION(0 |
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

	return &fileInfo{
		FileInfo: fi,
		mode:     masksToPerm(ownerMask, groupMask, otherMask),
	}, nil
}

// chmod is a Windows implementation of [Chmod].
func chmod(name string, perm fs.FileMode) (err error) {
	const objectType windows.SE_OBJECT_TYPE = windows.SE_FILE_OBJECT

	entries := make([]windows.EXPLICIT_ACCESS, 0, 3)
	creatorMask, groupMask, worldMask := modeToMasks(perm)

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
	ownerWrite = 0b010000000
	groupWrite = 0b000100000
	worldWrite = 0b000000100

	ownerAll = 0b111000000
	groupAll = 0b000111000
	worldAll = 0b000000111
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
// bits to convert them to the delete access rights used by Windows.
const (
	deleteOwner = 9
	deleteGroup = 12
	deleteWorld = 15
)

// modeToMasks converts a UNIX file mode to the corresponding Windows access
// masks.
func modeToMasks(fm os.FileMode) (owner, group, world windows.ACCESS_MASK) {
	mask := windows.ACCESS_MASK(fm.Perm())

	owner = ((mask & ownerAll) << genericOwner) | ((mask & ownerWrite) << deleteOwner)
	group = ((mask & groupAll) << genericGroup) | ((mask & groupWrite) << deleteGroup)
	world = ((mask & worldAll) << genericWorld) | ((mask & worldWrite) << deleteWorld)

	return owner, group, world
}

// masksToPerm converts Windows access masks to the corresponding UNIX file
// mode.
func masksToPerm(u, g, o windows.ACCESS_MASK) (perm os.FileMode) {
	perm |= os.FileMode(((u >> genericOwner) & ownerAll) | ((u >> deleteOwner) & ownerWrite))
	perm |= os.FileMode(((g >> genericGroup) & groupAll) | ((g >> deleteGroup) & groupWrite))
	perm |= os.FileMode(((o >> genericWorld) & worldAll) | ((o >> deleteWorld) & worldWrite))

	return perm
}
