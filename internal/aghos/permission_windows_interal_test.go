//go:build windows

package aghos

import (
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/windows"
)

// Common test constants for the Windows access masks.
const (
	winAccessWrite = windows.GENERIC_WRITE | windows.DELETE
	winAccessFull  = windows.GENERIC_READ | windows.GENERIC_EXECUTE | winAccessWrite
)

func TestPermToMasks(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		perm      fs.FileMode
		wantUser  windows.ACCESS_MASK
		wantGroup windows.ACCESS_MASK
		wantOther windows.ACCESS_MASK
	}{{
		name:      "all",
		perm:      0b111_111_111,
		wantUser:  winAccessFull,
		wantGroup: winAccessFull,
		wantOther: winAccessFull,
	}, {
		name:      "user_write",
		perm:      0o010_000_000,
		wantUser:  winAccessWrite,
		wantGroup: 0,
		wantOther: 0,
	}, {
		name:      "group_read",
		perm:      0o000_010_000,
		wantUser:  0,
		wantGroup: windows.GENERIC_READ,
		wantOther: 0,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			user, group, other := permToMasks(tc.perm)
			assert.Equal(t, tc.wantUser, user)
			assert.Equal(t, tc.wantGroup, group)
			assert.Equal(t, tc.wantOther, other)
		})
	}
}

func TestMasksToPerm(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		user     windows.ACCESS_MASK
		group    windows.ACCESS_MASK
		other    windows.ACCESS_MASK
		wantPerm fs.FileMode
	}{{
		name:     "all",
		user:     winAccessFull,
		group:    winAccessFull,
		other:    winAccessFull,
		wantPerm: 0b111_111_111,
	}, {
		name:     "user_write",
		user:     winAccessWrite,
		group:    0,
		other:    0,
		wantPerm: 0o010_000_000,
	}, {
		name:     "group_read",
		user:     0,
		group:    windows.GENERIC_READ,
		other:    0,
		wantPerm: 0o000_010_000,
	}, {
		name:     "no_access",
		user:     0,
		group:    0,
		other:    0,
		wantPerm: 0,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.wantPerm, masksToPerm(tc.user, tc.group, tc.other))
		})
	}
}
