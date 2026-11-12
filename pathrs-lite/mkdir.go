// SPDX-License-Identifier: MPL-2.0

//go:build linux

// Copyright (C) 2024-2025 Aleksa Sarai <cyphar@cyphar.com>
// Copyright (C) 2024-2025 SUSE LLC
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package pathrs

import (
	"os"

	"golang.org/x/sys/unix"
)

// MkdirAll is a race-safe alternative to the [os.MkdirAll] function,
// where the new directory is guaranteed to be within the root directory (if an
// attacker can move directories from inside the root to outside the root, the
// created directory tree might be outside of the root but the key constraint
// is that at no point will we walk outside of the directory tree we are
// creating).
//
// Effectively, MkdirAll(root, unsafePath, mode) is equivalent to
//
//	path, _ := securejoin.SecureJoin(root, unsafePath)
//	err := os.MkdirAll(path, mode)
//
// But is much safer. The above implementation is unsafe because if an attacker
// can modify the filesystem tree between [SecureJoin] and [os.MkdirAll], it is
// possible for MkdirAll to resolve unsafe symlink components and create
// directories outside of the root.
//
// If you plan to open the directory after you have created it or want to use
// an open directory handle as the root, you should use [MkdirAllHandle] instead.
// This function is a wrapper around [MkdirAllHandle].
//
// [SecureJoin]: https://pkg.go.dev/github.com/cyphar/filepath-securejoin#SecureJoin
func MkdirAll(root, unsafePath string, mode os.FileMode) error {
	rootDir, err := os.OpenFile(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer rootDir.Close() //nolint:errcheck // close failures aren't critical here

	f, err := MkdirAllHandle(rootDir, unsafePath, mode)
	if err != nil {
		return err
	}
	_ = f.Close()
	return nil
}

// MkdirAllNoSymlinks is like [MkdirAll] except that no symlink components in
// unsafePath are followed -- if any component of unsafePath is a symlink
// (even a dangling one), an error is returned. Similarly, a non-directory
// component in the middle of the path results in an error.
//
// This is primarily useful for callers that require the parent chain of the
// new directory to only contain real directories (for instance, when
// unpacking an archive into a directory tree where symlinks could be used to
// redirect where entries get created). As with [MkdirAll], at no point will
// any directories be created outside of the root.
//
// If you plan to open the directory after you have created it or want to use
// an open directory handle as the root, you should use
// [MkdirAllHandleNoSymlinks] instead. This function is a wrapper around
// [MkdirAllHandleNoSymlinks].
func MkdirAllNoSymlinks(root, unsafePath string, mode os.FileMode) error {
	rootDir, err := os.OpenFile(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer rootDir.Close() //nolint:errcheck // close failures aren't critical here

	f, err := MkdirAllHandleNoSymlinks(rootDir, unsafePath, mode)
	if err != nil {
		return err
	}
	_ = f.Close()
	return nil
}
