package randwrap

import (
	"encoding/json"
	"io"
	"reflect"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/internal"
	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/uint2k/uint128"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

const (
	// pseudo random key length. Should be L >= n - L'.
	L      = base.ComputationalSecurity
	LBytes = L / 8

	// block of generated random bytes. Should be L >= n - L'.
	N      = base.ComputationalSecurity
	NBytes = N / 8

	// counter. Should be L >= n - L'.
	LPrime      = base.ComputationalSecurity
	LPrimeBytes = LPrime / 8
)

var BlockHasher = sha3.NewShake128

type Counter = uint128.Uint128

var _ io.Reader = (*WrappedReader)(nil)

type WrappedReader struct {
	// should be key for a **deterministic** signature scheme.
	deviceRandomnessDeterministicWrappingKey types.AuthKey
	// Extract(H(Sig(sk, tag1)), ikm) where tag1 is bounded to the device
	prk []byte
	// a unique nonce for each sample. Should be of size less than n + L.
	// since L'=128, we can use a uint128.
	tag2 Counter
}

func NewWrappedReader(prng io.Reader, deterministicWrappingKey types.AuthKey) (*WrappedReader, error) {
	if err := validateInputs(prng, deterministicWrappingKey); err != nil {
		return nil, errs.WrapArgument(err, "input validation failed")
	}
	tag1, err := bindDevice(prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not read device info")
	}

	signedTag1 := deterministicWrappingKey.Sign(tag1)
	salt, err := hashing.Hash(base.RandomOracleHashFunction, signedTag1)
	if err != nil {
		return nil, errs.WrapHashing(err, "could not hash signed tag1")
	}

	var ikm [LBytes]byte
	if _, err := io.ReadFull(prng, ikm[:]); err != nil {
		return nil, errs.WrapRandomSample(err, "could not sample ikm")
	}

	prk := hkdf.Extract(base.RandomOracleHashFunction, ikm[:], salt)

	var tag2Sample [LPrimeBytes]byte
	if _, err := io.ReadFull(prng, tag2Sample[:]); err != nil {
		return nil, errs.WrapRandomSample(err, "could not sample tag2 as a nonce")
	}

	tag2 := uint128.NewFromBytesBE(tag2Sample[:])

	return &WrappedReader{
		deviceRandomnessDeterministicWrappingKey: deterministicWrappingKey,
		prk:                                      prk,
		tag2:                                     tag2,
	}, nil
}

func (wr *WrappedReader) Read(p []byte) (n int, err error) {
	shaker := BlockHasher()
	blockCount := utils.CeilDiv(len(p), NBytes)
	for i := 0; i < blockCount; i++ {
		var block [NBytes]byte
		var tag2Bytes [LPrimeBytes]byte
		wr.tag2.PutBytesBE(tag2Bytes[:])
		expander := hkdf.Expand(base.RandomOracleHashFunction, wr.prk, tag2Bytes[:])
		if _, err := io.ReadFull(expander, block[:]); err != nil {
			return -1, errs.WrapRandomSample(err, "couldn't expand for block %d", i)
		}
		if _, err := shaker.Write(block[:]); err != nil {
			return -1, errs.WrapFailed(err, "couldn't write block %d to shaker", i)
		}
		wr.tag2 = wr.tag2.Add(uint128.One)
	}
	n, err = shaker.Read(p)
	if err != nil {
		return n, errs.WrapFailed(err, "couldn't read from shaker")
	}
	return n, nil
}

func validateInputs(prng io.Reader, deterministicWrappingKey types.AuthKey) error {
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	if deterministicWrappingKey == nil {
		return errs.NewIsNil("deterministic wrapping key is nil")
	}
	if !types.AuthKeyIsDeterministic(deterministicWrappingKey) {
		return errs.NewType("wrapping key is not deterministic")
	}
	return nil
}

func bindDevice(prng io.Reader) ([]byte, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	deviceProfile, err := internal.GetDeviceProfile()
	if err != nil {
		return nil, errs.WrapFailed(err, "could not get device profile")
	}
	marshaledProfile, err := json.Marshal(deviceProfile)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not json marshal device profile")
	}
	info := hashing.HashPrefixedLength(base.RandomOracleHashFunction, marshaledProfile, []byte(reflect.TypeOf(prng).String()))
	return info, nil
}
