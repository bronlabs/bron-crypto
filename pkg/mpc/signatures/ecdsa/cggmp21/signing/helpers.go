package signing

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
)

func paillierEncryptScalar[K paillier.EncryptionKey[K], S algebra.PrimeFieldElement[S]](key K, scalar S, prng io.Reader) (*paillier.Ciphertext, *paillier.Nonce, error) {
	i, err := num.Z().FromUnsignedNumeric(scalar)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot convert scalar to integer")
	}
	return paillierEncryptInt(key, i, prng)
}

func paillierEncryptInt[K paillier.EncryptionKey[K]](key K, i *num.Int, prng io.Reader) (*paillier.Ciphertext, *paillier.Nonce, error) {
	plaintext, err := paillier.NewPlaintextSymmetric(i, key.PlaintextGroup().Modulus())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create Paillier plaintext")
	}
	ciphertext, nonce, err := encryption.Encrypt(plaintext, key, prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot encrypt Paillier plaintext")
	}
	return ciphertext, nonce, nil
}

func paillierMaskedProduct[S algebra.PrimeFieldElement[S]](
	key *paillier.PublicKey,
	ciphertext *paillier.Ciphertext,
	scalar S,
	mask *num.Int,
	prng io.Reader,
) (bigD, bigF *paillier.Ciphertext, r, s *paillier.Nonce, err error) {
	affineMask := mask.Neg()
	bigF, s, err = paillierEncryptInt(key, mask, prng)
	if err != nil {
		return nil, nil, nil, nil, errs.Wrap(err).WithMessage("cannot encrypt mask")
	}
	t0, r, err := paillierEncryptInt(key, affineMask, prng)
	if err != nil {
		return nil, nil, nil, nil, errs.Wrap(err).WithMessage("cannot encrypt negated mask")
	}
	t1, err := encryption.CiphertextScalarOpUnsignedNumeric(key, ciphertext, scalar)
	if err != nil {
		return nil, nil, nil, nil, errs.Wrap(err).WithMessage("cannot multiply Paillier ciphertext by scalar")
	}
	bigD, err = key.CiphertextOp(t0, t1)
	if err != nil {
		return nil, nil, nil, nil, errs.Wrap(err).WithMessage("cannot combine masked Paillier product")
	}
	return bigD, bigF, r, s, nil
}

func sampleMask(lPrime int, prng io.Reader) (*num.Int, error) {
	buf := make([]byte, lPrime/8+1)
	if _, err := io.ReadFull(prng, buf); err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot sample mask")
	}
	buf[0] = byte(int8(buf[0]) >> 7)
	out, err := num.Z().FromTwosComplementBytesBE(buf)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot parse sampled mask")
	}
	return out, nil
}

func paillierPlaintextToScalar[S algebra.PrimeFieldElement[S]](plaintext *paillier.Plaintext, scalarField algebra.PrimeField[S]) (S, error) {
	p := plaintext.Normalise()
	pAbs := p.Abs()
	scalar, err := scalarField.FromBytesBEReduce(pAbs.Big().Bytes())
	if err != nil {
		return *new(S), errs.Wrap(err).WithMessage("cannot convert Paillier plaintext to scalar")
	}
	if p.IsNegative() {
		return scalar.Neg(), nil
	} else {
		return scalar, nil
	}
}

func intToScalar[S algebra.PrimeFieldElement[S]](i *num.Int, scalarField algebra.PrimeField[S]) (S, error) {
	iAbs := i.Abs()
	scalar, err := scalarField.FromBytesBEReduce(iAbs.Big().Bytes())
	if err != nil {
		return *new(S), errs.Wrap(err).WithMessage("cannot convert integer to scalar")
	}
	if i.IsNegative() {
		return scalar.Neg(), nil
	} else {
		return scalar, nil
	}
}
