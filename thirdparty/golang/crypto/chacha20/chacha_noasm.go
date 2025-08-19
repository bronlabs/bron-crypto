// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (!arm64 && !s390x && !ppc64le) || !gc || purego

package chacha20

const bufSize = blockSize

func (s *Cipher) xorKeyStreamBlocks(dst, src []byte, key *[8]uint32) {
	// CUSTOM: expose key choice
	s.xorKeyStreamBlocksGeneric(dst, src, key)
}
