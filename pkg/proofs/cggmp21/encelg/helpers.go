package encelg

import (
	"io"
	"math/big"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
)

func intSampleRangeSymmetricBits(bitLen int, prngReader io.Reader) (*num.Int, error) {
	buf := make([]byte, bitLen/8)
	if _, err := io.ReadFull(prngReader, buf); err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample integer bytes")
	}

	out, err := num.Z().FromTwosComplementBytesBE(buf)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not parse sampled integer")
	}
	return out, nil
}

func intInSignedBitRange(v *num.Int, bitLen int) bool {
	return v.Abs().TrueLen() < bitLen
}

func intToPlaintext(v *num.Int, paillierKey *paillier.PublicKey) (*paillier.Plaintext, error) {
	out, err := paillier.NewPlaintextSymmetric(v, paillierKey.PlaintextGroup().Modulus())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create signed Paillier plaintext")
	}
	return out, nil
}

func intToScalar[S algebra.PrimeFieldElement[S]](v *num.Int, scalarField algebra.PrimeField[S]) (S, error) {
	var nilS S
	if v == nil {
		return nilS, ErrInvalidArgument.WithMessage("integer must not be nil")
	}
	if scalarField == nil {
		return nilS, ErrInvalidArgument.WithMessage("scalar field must not be nil")
	}

	modulus := scalarField.Order().Big()
	reduced := new(big.Int).Mod(v.Big(), modulus)
	if reduced.Sign() == 0 {
		return scalarField.FromUint64(0), nil
	}
	out, err := scalarField.FromBytesBEReduce(reduced.Bytes())
	if err != nil {
		return nilS, errs.Wrap(err).WithMessage("could not reduce integer to scalar")
	}
	return out, nil
}

func signedBoundFitsPaillier(bits int, paillierKey *paillier.PublicKey) error {
	if paillierKey == nil {
		return ErrInvalidArgument.WithMessage("Paillier key must not be nil")
	}
	modulus := paillierKey.PlaintextGroup().Modulus()
	bound := num.Z().One().Lsh(uint(bits))
	halfModulus := modulus.Rsh(1).Lift()
	if !bound.IsLessThanOrEqual(halfModulus) {
		return ErrValidationFailed.WithMessage("2^%d must fit in the Paillier symmetric plaintext range", bits)
	}
	return nil
}
