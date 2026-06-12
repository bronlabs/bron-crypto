package enc

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
)

func intToPlaintext[EK paillier.EncryptionKey[EK]](v *num.Int, paillierKey EK) (*paillier.Plaintext, error) {
	out, err := paillier.NewPlaintextSymmetric(v, paillierKey.PlaintextGroup().Modulus())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create signed Paillier plaintext")
	}
	return out, nil
}

func intRandomBitsSymmetric(bits int, prng io.Reader) (*num.Int, error) {
	if bits%8 != 0 {
		return nil, ErrInvalidArgument.WithMessage("bits must be a multiple of 8")
	}
	outBytes := make([]byte, bits/8+1)
	if _, err := io.ReadFull(prng, outBytes); err != nil {
		return nil, errs.Wrap(err).WithMessage("could not read random bytes")
	}
	outBytes[0] = byte(int8(outBytes[0]) >> 7)
	out, err := num.Z().FromTwosComplementBytesBE(outBytes)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not parse signed integer")
	}
	return out, nil
}

func inSignedBitRange(v *num.Int, bits int) bool {
	// Conservatively reject -2^bits even though intRandomBitsSymmetric can
	// sample it with probability 2^-(bits+1), which is negligible here.
	return v.Abs().TrueLen() <= bits
}

func signedBoundFitsPaillier[EK paillier.EncryptionKey[EK]](bits int, paillierKey EK) error {
	modulus := paillierKey.PlaintextGroup().Modulus()
	bound := num.Z().One().Lsh(uint(bits))
	halfModulus := modulus.Rsh(1).Lift()
	if !bound.IsLessThanOrEqual(halfModulus) {
		return ErrInvalidArgument.WithMessage("2^%d must fit in the Paillier symmetric plaintext range", bits)
	}
	return nil
}
