// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"os"
	"syscall"
)

// exitWithParent asks the kernel to SIGTERM us when OpenConnect (our parent,
// since the tun script execs us) exits, and covers the race where it already has.
func exitWithParent() {
	_, _, _ = syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_PDEATHSIG, uintptr(syscall.SIGTERM), 0)
	if os.Getppid() == 1 {
		os.Exit(0)
	}
}
