//go:build linux

package guard

import (
	"fmt"
	"os"
	"syscall"
)

// DropPrivileges switches the whole process to uid/gid for good. Go applies
// setuid/setgid to every thread (since 1.16), so this is safe to call after
// the runtime has started. A no-op when not running as root.
func DropPrivileges(uid, gid uint32) error {
	if os.Getuid() != 0 {
		return nil
	}
	if err := syscall.Setgroups([]int{}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(int(gid)); err != nil {
		return fmt.Errorf("setgid %d: %w", gid, err)
	}
	if err := syscall.Setuid(int(uid)); err != nil {
		return fmt.Errorf("setuid %d: %w", uid, err)
	}
	if os.Getuid() != int(uid) || os.Geteuid() != int(uid) {
		return fmt.Errorf("privilege drop did not take: uid %d euid %d", os.Getuid(), os.Geteuid())
	}
	// Prove it is irreversible: regaining root must fail.
	if err := syscall.Setuid(0); err == nil {
		return fmt.Errorf("privilege drop is reversible; refusing to run")
	}
	return nil
}
