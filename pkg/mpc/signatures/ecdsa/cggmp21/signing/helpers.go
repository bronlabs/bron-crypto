package signing

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
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
	productKey *paillier.PublicKey,
	maskKey *paillier.PublicKey,
	ciphertext *paillier.Ciphertext,
	scalar S,
	mask *num.Int,
	prng io.Reader,
) (bigD, bigF *paillier.Ciphertext, s, r *paillier.Nonce, err error) {
	affineMask := mask.Neg()
	bigF, r, err = paillierEncryptInt(maskKey, mask, prng)
	if err != nil {
		return nil, nil, nil, nil, errs.Wrap(err).WithMessage("cannot encrypt mask")
	}
	t0, s, err := paillierEncryptInt(productKey, affineMask, prng)
	if err != nil {
		return nil, nil, nil, nil, errs.Wrap(err).WithMessage("cannot encrypt negated mask")
	}
	t1, err := encryption.CiphertextScalarOpUnsignedNumeric(productKey, ciphertext, scalar)
	if err != nil {
		return nil, nil, nil, nil, errs.Wrap(err).WithMessage("cannot multiply Paillier ciphertext by scalar")
	}
	bigD, err = productKey.CiphertextOp(t0, t1)
	if err != nil {
		return nil, nil, nil, nil, errs.Wrap(err).WithMessage("cannot combine masked Paillier product")
	}
	return bigD, bigF, s, r, nil
}

func sampleMask(lPrime int, prng io.Reader) (*num.Int, error) {
	buf := make([]byte, lPrime/8)
	if _, err := io.ReadFull(prng, buf); err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot sample mask")
	}

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

func paillierPublicKeyFor[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	signer *Signer[P, B, S],
	id sharing.ID,
) (*paillier.PublicKey, error) {
	if id == signer.ctx.HolderID() {
		return signer.shard.AuxInfo().PaillierSecretKey().Public(), nil
	}
	publicKey, ok := signer.shard.AuxInfo().PaillierPublicKey(id)
	if !ok {
		return nil, cggmp21.ErrValidationFailed.WithMessage("missing Paillier public key for %d", id)
	}
	return publicKey, nil
}
