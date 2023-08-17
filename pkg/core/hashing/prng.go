package hashing

import (
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

const (
	// Kappa is the bit-length of the seeds, the computational security parameter.
	Kappa      = 256
	KappaBytes = Kappa / 8
)

// PRG generates a pseudorandom bit sequence of byteLength bits from seeds of
// size [κ], expanding each κ-bit seed to byteLength*8 bits. sid is used as a salt.
func PRG(sid, seed []byte, byteLength int) (bufferOut []byte, err error) {
	bufferOut = make([]byte, byteLength)
	if len(seed) != KappaBytes {
		return nil, errs.NewInvalidArgument("invalid seed length (%d, should be %d)", len(seed), KappaBytes)
	}
	// Use the uniqueSessionId as the "domain separator", and the seed as the input
	shake := sha3.NewCShake256(sid, []byte("Copper_Knox_PRG"))
	if _, err = shake.Write(seed); err != nil {
		return nil, errs.WrapFailed(err, "writing seed into shake for PRG extension")
	}
	// This is the core pseudorandom expansion of the seeds
	if _, err = shake.Read(bufferOut); err != nil {
		return nil, errs.WrapFailed(err, "reading from shake in PRG expansion")
	}
	return bufferOut, nil
}
