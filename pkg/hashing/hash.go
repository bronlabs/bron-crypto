package hashing

import (
	"crypto/hmac"
	"hash"

	"github.com/bronlabs/bron-crypto/pkg/base/utils/ioutils"
	"github.com/bronlabs/bron-crypto/pkg/hashing/kmac"
	"github.com/bronlabs/errs-go/errs"
)

// Hash iteratively writes all the inputs to the given hash function and returns the result.
func Hash[H hash.Hash](hashFunc func() H, xs ...[]byte) ([]byte, error) {
	h := hashFunc()
	if _, err := ioutils.WriteConcat(h, xs...); err != nil {
		return nil, errs.Wrap(err).WithMessage("could not hash input")
	}

	digest := h.Sum(nil)
	return digest, nil
}

// HashIndexLengthPrefixed hashes the inputs after encoding each with its index and length prefix.
// This encoding ensures that different input sequences produce distinct hash inputs.
func HashIndexLengthPrefixed[H hash.Hash](hashFunc func() H, xs ...[]byte) ([]byte, error) {
	h := hashFunc()
	if _, err := ioutils.WriteIndexLengthPrefixed(h, xs...); err != nil {
		return nil, errs.Wrap(err).WithMessage("could not hash input")
	}

	digest := h.Sum(nil)
	return digest, nil
}

// HashChain computes an iterated hash where each input is hashed together with the previous output.
// It starts with a zero-initialised buffer and iteratively computes H(previous || input) for each input.
func HashChain[H hash.Hash](hashFunc func() H, xs ...[]byte) ([]byte, error) {
	h := hashFunc()
	var err error
	out := make([]byte, h.Size())
	for i, x := range xs {
		out, err = Hash(hashFunc, out, x)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not compute hash for input %d", i)
		}
	}
	return out, nil
}

// Hmac iteratively writes all the inputs to an hmac (defined by the hash function and the key) and returns the result.
func Hmac[H hash.Hash](key []byte, hashFunc func() H, xs ...[]byte) ([]byte, error) {
	hmacFunc := func() hash.Hash { return hmac.New(HashFuncTypeErase(hashFunc), key) }
	out, err := Hash(hmacFunc, xs...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("computing hmac")
	}
	return out, nil
}

// HmacIndexLengthPrefixed computes an HMAC over the inputs after encoding each with its index and length prefix.
func HmacIndexLengthPrefixed[H hash.Hash](key []byte, hashFunc func() H, xs ...[]byte) ([]byte, error) {
	hmacFunc := func() hash.Hash { return hmac.New(HashFuncTypeErase(hashFunc), key) }
	out, err := HashIndexLengthPrefixed(hmacFunc, xs...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("computing hmac")
	}
	return out, nil
}

// Kmac computes a KMAC (Keccak Message Authentication Code) over the inputs using a cSHAKE function.
// The key must be at least half the output size to meet the security level requirements.
func Kmac(key, customizationString []byte, tagSize int, h func(key []byte, tagSize int, customizationString []byte) (*kmac.Kmac, error), xs ...[]byte) ([]byte, error) {
	k, err := h(key, tagSize, customizationString)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("error creating KMAC instance")
	}
	if len(key) < k.Size()/2 {
		return nil, kmac.ErrInvalidKeyLength.WithMessage("key length does not meet %d-bit security level", k.Size()*4)
	}

	if _, err := ioutils.WriteConcat(k, xs...); err != nil {
		return nil, errs.Wrap(err).WithMessage("could not write inputs into internal state")
	}
	return k.Sum(nil), nil
}

// KmacIndexLengthPrefixed computes a KMAC over the inputs after encoding each with its index and length prefix.
func KmacIndexLengthPrefixed(key, customizationString []byte, tagSize int, h func(key []byte, tagSize int, customizationString []byte) (*kmac.Kmac, error), xs ...[]byte) ([]byte, error) {
	k, err := h(key, tagSize, customizationString)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("error creating KMAC instance")
	}
	if len(key) < k.Size()/2 {
		return nil, kmac.ErrInvalidKeyLength.WithMessage("key length does not meet %d-bit security level", k.Size()*4)
	}

	if _, err = ioutils.WriteIndexLengthPrefixed(k, xs...); err != nil {
		return nil, errs.Wrap(err).WithMessage("could not write into internal state")
	}
	return k.Sum(nil), nil
}

// HashFuncTypeErase converts a generic hash constructor to a non-generic one returning hash.Hash.
// This is useful when interfacing with APIs that require func() hash.Hash, such as crypto/hmac.
func HashFuncTypeErase[H hash.Hash](hashFunc func() H) func() hash.Hash {
	return func() hash.Hash {
		return hashFunc()
	}
}
