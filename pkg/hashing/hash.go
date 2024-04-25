package hashing

import (
	"crypto/hmac"
	"hash"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

// Hash iteratively writes all the inputs to the given hash function and returns the result.
func Hash(h func() hash.Hash, xs ...[]byte) ([]byte, error) {
	H := h()
	for i, x := range xs {
		if _, err := H.Write(x); err != nil {
			return nil, errs.WrapFailed(err, "could not write to H for input %d", i)
		}
	}
	digest := H.Sum(nil)
	return digest, nil
}

func HashChain(h func() hash.Hash, xs ...[]byte) ([]byte, error) {
	H := h()
	var err error
	out := make([]byte, H.Size())
	for i, x := range xs {
		out, err = Hash(h, out, x)
		if err != nil {
			return nil, errs.WrapHashing(err, "could not compute hash for input %d", i)
		}
	}
	return out, nil
}

// Hmac iteratively writes all the inputs to an hmac (defined by the hash function and the key) and returns the result.
func Hmac(key []byte, h func() hash.Hash, xs ...[]byte) ([]byte, error) {
	hmacFunc := func() hash.Hash { return hmac.New(h, key) }
	out, err := Hash(hmacFunc, xs...)
	if err != nil {
		return nil, errs.WrapHashing(err, "computing hmac")
	}
	return out, nil
}

func HmacChain(key []byte, h func() hash.Hash, xs ...[]byte) ([]byte, error) {
	hmacFunc := func() hash.Hash { return hmac.New(h, key) }
	var err error
	out := make([]byte, hmacFunc().Size())
	for i, x := range xs {
		out, err = Hash(hmacFunc, out, x)
		if err != nil {
			return nil, errs.WrapHashing(err, "computing hmac chain for iter=%d", i)
		}
	}
	return out, nil
}
