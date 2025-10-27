package internal

import (
	"crypto"
	"crypto/hmac"
	"encoding/binary"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
)

type KDFID uint16

// https://www.rfc-editor.org/rfc/rfc9180.html#name-key-derivation-functions-kd
const (
	KDF_HKDF_RESERVED KDFID = 0x0000
	KDF_HKDF_SHA256   KDFID = 0x0001
	KDF_HKDF_SHA512   KDFID = 0x0003
)

//nolint:exhaustive // reserved will not have have parameters below.
var (
	// https://www.rfc-editor.org/rfc/rfc9180.html#name-key-derivation-functions-kd
	nhs = map[KDFID]int{
		KDF_HKDF_SHA256: 32,
		KDF_HKDF_SHA512: 64,
	}
	kdfs = map[KDFID]*KDFScheme{
		KDF_HKDF_SHA256: NewKDFSHA256(),
		KDF_HKDF_SHA512: NewKDFSHA512(),
	}
)

type KDFScheme struct {
	hash crypto.Hash
}

// NewKDF returns a KDFScheme corresponding to the given KDFID.
func NewKDF(id KDFID) (*KDFScheme, error) {
	kdf, exists := kdfs[id]
	if !exists {
		return nil, errs.NewType("KDF with ID %d is not supported", id)
	}

	return kdf, nil
}

// NewKDFSHA256 returns an instantiation of HKDF-SHA256 scheme.
func NewKDFSHA256() *KDFScheme {
	return &KDFScheme{
		hash: crypto.SHA256,
	}
}

// NewKDFSHA512 returns an instantiation of HKDF-SHA512 scheme.
func NewKDFSHA512() *KDFScheme {
	return &KDFScheme{
		hash: crypto.SHA512,
	}
}

// ID returns the KDF ID as per https://www.rfc-editor.org/rfc/rfc9180.html#name-key-derivation-functions-kd
func (s *KDFScheme) ID() KDFID {
	switch s.hash { //nolint:exhaustive // intentional, for readability.
	case crypto.SHA256:
		return KDF_HKDF_SHA256
	case crypto.SHA512:
		return KDF_HKDF_SHA512
	default:
		panic(errs.NewType("hash %s is not supported", s.hash.String()))
	}
}

// Hash hashes messages using the underlying hash function of the kdf.
func (s *KDFScheme) Hash(messages ...[]byte) ([]byte, error) {
	digest, err := hashing.Hash(s.hash.New, messages...)
	if err != nil {
		return nil, errs.WrapHashing(err, "could not hash via %s", s.hash.String())
	}

	return digest, nil
}

// Extract extracts a pseudorandom key of fixed length Nh bytes from input keying material ikm and an optional byte string salt.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.2.2.1
func (s *KDFScheme) Extract(salt, ikm []byte) []byte {
	h := hmac.New(s.hash.New, salt) // salt optional
	h.Write(ikm)
	return h.Sum(nil)
}

// Expand expands a pseudorandom key prk using optional string info into L bytes of output keying material.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.2.2.2
func (s *KDFScheme) Expand(prk, info []byte, L int) []byte {
	out := []byte{}
	T := []byte{}
	i := byte(1)
	for len(out) < L {
		block := slices.Concat(T, info) // info is optional
		block = append(block, i)

		h := hmac.New(s.hash.New, prk)
		h.Write(block)

		T = h.Sum(nil)
		out = append(out, T...)
		i++
	}

	return out[:L]
}

// Nh returns the output size of the Extract() function in bytes.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.2.2.3
func (s *KDFScheme) Nh() int {
	return nhs[s.ID()]
}

// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-10
func (s *KDFScheme) labeledExtract(suiteId, salt, label, ikm []byte) []byte {
	labeledIkm := slices.Concat(
		[]byte(version), suiteId, label, ikm,
	)
	return s.Extract(salt, labeledIkm)
}

// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-10
func (s *KDFScheme) labeledExpand(suiteId, prk, label, info []byte, L int) []byte {
	if L > (1 << 16) {
		panic("Expand length cannot be larger than 2^16")
	}

	lengthBuffer := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBuffer, uint16(L))
	labeledInfo := slices.Concat(
		lengthBuffer, []byte(version), suiteId, label, info,
	)
	return s.Expand(prk, labeledInfo, L)
}
