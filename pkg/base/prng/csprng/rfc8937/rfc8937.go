package rfc8937

import (
	"encoding/binary"
	"io"
	"slices"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

const (
	// pseudo random key length. Should be L >= n - L'.
	L      = base.ComputationalSecurityBits
	LBytes = base.ComputationalSecurityBytesCeil

	// block of generated random bytes. Should be L >= n - L'.
	N      = base.ComputationalSecurityBits
	NBytes = base.ComputationalSecurityBytesCeil

	// counter. Should be L >= n - L'.
	LPrime      = base.ComputationalSecurityBits
	LPrimeBytes = base.ComputationalSecurityBytesCeil
)

var BlockHasher = sha3.NewShake128

type Signer = ecdsa.DeterministicSigner

type WrappedReader struct {
	// should be key for a **deterministic** signature scheme.
	signer *Signer
	// Extract(H(Sig(sk, tag1)), ikm) where tag1 is bounded to the device
	prk []byte
	// a unique nonce for each sample. Should be of size less than n + L.
	// since L'=128, we can use a uint64. This will be the unit timestamp.
	tag2 uint64
}

func (wr *WrappedReader) Counter() uint64 {
	return wr.tag2
}

func NewWrappedReader(prng io.Reader, signer *Signer, keyId []byte) (*WrappedReader, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	if signer == nil {
		return nil, errs.NewIsNil("signer is nil")
	}
	tag1 := keyId
	signedTag1, err := signer.Sign(tag1)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not sign tag1")
	}
	salt, err := hashing.Hash(sha3.New256, slices.Concat(signedTag1.R().Bytes(), signedTag1.S().Bytes()))
	if err != nil {
		return nil, errs.WrapHashing(err, "could not hash signed tag1")
	}

	var ikm [LBytes]byte
	if _, err := io.ReadFull(prng, ikm[:]); err != nil {
		return nil, errs.WrapRandomSample(err, "could not sample ikm")
	}

	prk := hkdf.Extract(sha3.New256, ikm[:], salt)

	counter := time.Now().UnixNano()

	return &WrappedReader{
		signer: signer,
		prk:    prk,
		tag2:   uint64(counter),
	}, nil
}

func (wr *WrappedReader) Read(p []byte) (n int, err error) {
	shaker := BlockHasher()
	blockCount := utils.CeilDiv(len(p), NBytes)
	for i := range blockCount {
		var block [NBytes]byte
		expander := hkdf.Expand(sha3.New256, wr.prk, binary.BigEndian.AppendUint64(nil, wr.tag2+1))
		if _, err := io.ReadFull(expander, block[:]); err != nil {
			return -1, errs.WrapRandomSample(err, "couldn't expand for block %d", i)
		}
		if _, err := shaker.Write(block[:]); err != nil {
			return -1, errs.WrapFailed(err, "couldn't write block %d to shaker", i)
		}
		wr.tag2++
	}
	n, err = shaker.Read(p)
	if err != nil {
		return n, errs.WrapFailed(err, "couldn't read from shaker")
	}
	return n, nil
}
