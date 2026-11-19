//go:build !linux

package guard

import "errors"

// DropPrivileges is Linux-only; the guard never runs as root elsewhere.
func DropPrivileges(uid, gid uint32) error {
	return errors.New("privilege drop is only implemented on Linux")
}
