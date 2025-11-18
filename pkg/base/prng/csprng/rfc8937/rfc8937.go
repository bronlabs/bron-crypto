package rfc8937

import (
	"crypto/hkdf"
	"crypto/sha3"
	"fmt"
	"io"
	"slices"
	"sync/atomic"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

// hashFunc implies L = 32 bytes
var hashFunc = sha3.New256

type WrappedReader struct {
	salt    []byte
	counter atomic.Uint64
	wrapee  io.Reader
}

func Wrap[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](prng io.Reader, signer *ecdsa.Signer[P, B, S], uniqueDeviceId []byte) (*WrappedReader, error) {
	if !signer.IsDeterministic() {
		return nil, errs2.Wrap(ErrSignerDeterminism)
	}

	sig, err := signer.Sign(uniqueDeviceId)
	if err != nil {
		return nil, errs2.Wrap(ErrUniqueDeviceIDSignature)
	}
	salt, err := hashing.Hash(hashFunc, slices.Concat(sig.R().Bytes(), sig.S().Bytes()))
	if err != nil {
		return nil, errs2.Wrap(ErrHashingUniqueDeviceID)
	}

	return &WrappedReader{
		salt:   salt,
		wrapee: prng,
	}, nil
}

func (r *WrappedReader) Read(p []byte) (n int, err error) {
	l := hashFunc().Size()
	g := make([]byte, l)
	_, err = io.ReadFull(r.wrapee, g)
	if err != nil {
		return n, errs2.Wrap(ErrRandomSample)
	}
	key, err := hkdf.Extract(hashFunc, g, r.salt)
	if err != nil {
		return 0, errs2.Wrap(ErrExtractKey)
	}

	tag2 := r.counter.Add(1)
	gPrime, err := hkdf.Expand(hashFunc, key, fmt.Sprintf("%d", tag2), len(p))
	if err != nil {
		return 0, errs2.Wrap(ErrExpandKey)
	}
	copy(p, gPrime)
	return len(gPrime), nil
}

var (
	ErrSignerDeterminism       = errs2.New("signer must be deterministic")
	ErrUniqueDeviceIDSignature = errs2.New("could not sign unique device id")
	ErrHashingUniqueDeviceID   = errs2.New("could not hash signed unique device id")
	ErrRandomSample            = errs2.New("could not read from wrapped reader")
	ErrExtractKey              = errs2.New("could not extract key")
	ErrExpandKey               = errs2.New("could not expand key")
)
