//go:build windows

package aghos

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// chmod is a Windows implementation of [Chmod].
func chmod(name string, perm fs.FileMode) (err error) {
	const objectType windows.SE_OBJECT_TYPE = windows.SE_FILE_OBJECT

	entries := make([]windows.EXPLICIT_ACCESS, 0, 3)
	creatorMask, groupMask, worldMask := modeToMasks(perm.Perm())

	if creatorMask > 0 {
		var creator *windows.TRUSTEE
		creator, err = newWellKnownTrustee(windows.WinCreatorOwnerSid)
		if err != nil {
			return fmt.Errorf("creating owner trustee: %w", err)
		}

		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: creatorMask,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee:           *creator,
		})
	}

	if groupMask > 0 {
		var group *windows.TRUSTEE
		group, err = newWellKnownTrustee(windows.WinCreatorGroupSid)
		if err != nil {
			return fmt.Errorf("creating group trustee: %w", err)
		}

		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: groupMask,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee:           *group,
		})
	}

	if worldMask > 0 {
		var world *windows.TRUSTEE
		world, err = newWellKnownTrustee(windows.WinWorldSid)
		if err != nil {
			return fmt.Errorf("creating everyone trustee: %w", err)
		}

		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: worldMask,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee:           *world,
		})
	}

	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("creating acl: %w", err)
	}

	secInfo := windows.SECURITY_INFORMATION(
		windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION,
	)

	err = windows.SetNamedSecurityInfo(name, objectType, secInfo, nil, nil, acl, nil)
	if err != nil {
		return fmt.Errorf("setting security information: %w", err)
	}

	return nil
}

// mkdir is a Windows implementation of [Mkdir].
func mkdir(name string, perm os.FileMode) (err error) {
	name, err = filepath.Abs(name)
	if err != nil {
		return fmt.Errorf("computing absolute path: %w", err)
	}

	entries := make([]windows.EXPLICIT_ACCESS, 0, 3)
	creatorMask, groupMask, worldMask := modeToMasks(perm.Perm())

	if creatorMask > 0 {
		var creator *windows.TRUSTEE
		creator, err = currentUserTrustee()
		if err != nil {
			return fmt.Errorf("creating owner trustee: %w", err)
		}

		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: creatorMask,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee:           *creator,
		})
	}

	if groupMask > 0 {
		var group *windows.TRUSTEE
		group, err = currentUserGroupTrustee()
		if err != nil {
			return fmt.Errorf("creating group trustee: %w", err)
		}

		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: groupMask,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee:           *group,
		})
	}

	if worldMask > 0 {
		var world *windows.TRUSTEE
		world, err = newWellKnownTrustee(windows.WinWorldSid)
		if err != nil {
			return fmt.Errorf("creating everyone trustee: %w", err)
		}

		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: worldMask,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee:           *world,
		})
	}

	secAttrs, err := newSecAttr(entries)
	if err != nil {
		return fmt.Errorf("creating security attributes: %w", err)
	}

	namePntr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("converting string: %w", err)
	}

	return windows.CreateDirectory(namePntr, secAttrs)
}

// newSecAttr creates a new security attributes structure with the specified
// explicit access entries.
func newSecAttr(entries []windows.EXPLICIT_ACCESS) (sa *windows.SecurityAttributes, err error) {
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, fmt.Errorf("failed to create security descriptor: %v", err)
	}

	if len(entries) > 0 {
		var acl *windows.ACL
		acl, err = windows.ACLFromEntries(entries, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create ACL from explicit access entries: %v", err)
		}

		err = sd.SetDACL(acl, true, false)
		if err != nil {
			return nil, fmt.Errorf("failed to configure DACL for security desctriptor: %v", err)
		}
	}

	err = sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED)
	if err != nil {
		return nil, fmt.Errorf("failed to configure protected DACL for security descriptor: %v", err)
	}

	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
		InheritHandle:      0,
	}, nil
}

// currentUserTrustee returns a trustee for the current user.
func currentUserTrustee() (t *windows.TRUSTEE, err error) {
	token := windows.GetCurrentProcessToken()
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}

	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		// Don't wrap the error here, as we can't add any additional context.
		return nil, err
	}

	sid := tokenUser.User.Sid
	trusteeType := windows.TRUSTEE_TYPE(windows.TRUSTEE_IS_USER)
	// TODO(e.burkov):  !! consider using IsElevated()
	if ok, err := token.IsMember(admins); err == nil && ok {
		sid = admins
		trusteeType = windows.TRUSTEE_IS_GROUP
	}

	return &windows.TRUSTEE{
		TrusteeForm:  windows.TRUSTEE_IS_SID,
		TrusteeType:  trusteeType,
		TrusteeValue: windows.TrusteeValueFromSID(sid),
	}, nil
}

// currentUserGroupTrustee returns a trustee for the current user's primary
// group.
func currentUserGroupTrustee() (t *windows.TRUSTEE, err error) {
	token := windows.GetCurrentProcessToken()
	group, err := token.GetTokenPrimaryGroup()
	if err != nil {
		return nil, err
	}

	return &windows.TRUSTEE{
		TrusteeForm:  windows.TRUSTEE_IS_SID,
		TrusteeType:  windows.TRUSTEE_IS_GROUP,
		TrusteeValue: windows.TrusteeValueFromSID(group.PrimaryGroup),
	}, nil
}

// newWellKnownTrustee returns a trustee for a well-known SID.
func newWellKnownTrustee(stype windows.WELL_KNOWN_SID_TYPE) (t *windows.TRUSTEE, err error) {
	sid, err := windows.CreateWellKnownSid(stype)
	if err != nil {
		// Don't wrap the error here, as we can't add any additional context.
		return nil, err
	}

	return &windows.TRUSTEE{
		TrusteeForm:  windows.TRUSTEE_IS_SID,
		TrusteeValue: windows.TrusteeValueFromSID(sid),
	}, nil
}

// modeToMasks converts a UNIX file mode to the corresponding Windows access
// masks.
func modeToMasks(fm os.FileMode) (owner, group, world windows.ACCESS_MASK) {
	mask := windows.ACCESS_MASK(fm.Perm())

	// Constants reflecting the UNIX permission bits.
	const (
		ownerWrite = 0o200
		groupWrite = 0o020
		worldWrite = 0o002

		ownerAll = 0o700
		groupAll = 0o070
		worldAll = 0o007
	)

	// Constants reflecting the number of bits to shift the UNIX permission bits
	// to convert them to the generic access rights used by Windows, see
	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/access-mask.
	const (
		genericOwner = 23
		genericGroup = 26
		genericWorld = 29
	)

	// Constants reflecting the number of bits to shift the UNIX write
	// permission bits to convert them to the delete access rights used by
	// Windows.
	const (
		deleteOwner = 9
		deleteGroup = 12
		deleteWorld = 15
	)

	owner = ((mask & ownerAll) << genericOwner) | ((mask & ownerWrite) << deleteOwner)
	group = ((mask & groupAll) << genericGroup) | ((mask & groupWrite) << deleteGroup)
	world = ((mask & worldAll) << genericWorld) | ((mask & worldWrite) << deleteWorld)

	return owner, group, world
}
