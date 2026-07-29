package signing

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

// CalcC3 calculates a ciphertext whose plaintext reduces modulo q to
// k2^(-1)(m' + r * (x1 + x2)). The primary MSP share is converted by applying
// its reconstruction coefficient to each encrypted component separately. The
// two zero-refreshed additive contributions are reduced in the scalar field and
// freshly encrypted before they are added.
//
// An honestly generated encryptedPrimaryShares plaintext is the DKG
// representative in [0, 3q), or the trusted-dealer representative in [0, q).
// To prevent a Paillier wrap from changing the final signed reduction, CalcC3
// enforces 2*(q^3 + 3*d*q^2 + 2q) < N, where d is the number of primary
// components. The DKG range proof's malicious-prover soundness guarantees only
// [0, 4q), so deployments relying on that guarantee must independently ensure
// the stronger bound 2*(q^3 + 4*d*q^2 + 2q) < N. prng must be
// cryptographically secure.
func CalcC3[S algebra.PrimeFieldElement[S]](
	k2, mPrime, r, refreshedSecondaryShare, primaryZeroShare S,
	curveOrder algebra.Cardinal,
	pk *paillier.PublicKey,
	encryptedPrimaryShares []*paillier.Ciphertext,
	primaryReconstructionCoefficients []S,
	prng io.Reader,
) (c3 *paillier.Ciphertext, err error) {
	if utils.IsNil(k2) || utils.IsNil(mPrime) || utils.IsNil(r) ||
		utils.IsNil(refreshedSecondaryShare) || utils.IsNil(primaryZeroShare) ||
		curveOrder == nil || pk == nil || prng == nil {

		return nil, ErrInvalidArgument.WithMessage("CalcC3 arguments must not be nil")
	}
	if len(encryptedPrimaryShares) == 0 {
		return nil, ErrInvalidArgument.WithMessage("encrypted primary share must have at least one component")
	}
	if len(encryptedPrimaryShares) != len(primaryReconstructionCoefficients) {
		return nil, ErrInvalidArgument.WithMessage(
			"encrypted primary share has %d components but reconstruction vector has %d coefficients",
			len(encryptedPrimaryShares),
			len(primaryReconstructionCoefficients),
		)
	}
	if !k2.Structure().Order().Equal(curveOrder) {
		return nil, ErrInvalidArgument.WithMessage("curve order does not match signing scalar field")
	}
	scalarFieldName := k2.Structure().Name()
	for name, scalar := range map[string]S{
		"message":                   mPrime,
		"r":                         r,
		"refreshed secondary share": refreshedSecondaryShare,
		"primary zero share":        primaryZeroShare,
	} {
		if scalar.Structure().Name() != scalarFieldName {
			return nil, ErrInvalidArgument.WithMessage("%s uses a different scalar field", name)
		}
	}
	for i, coefficient := range primaryReconstructionCoefficients {
		if utils.IsNil(coefficient) {
			return nil, ErrInvalidArgument.WithMessage("primary reconstruction coefficient %d is nil", i)
		}
		if coefficient.Structure().Name() != scalarFieldName {
			return nil, ErrInvalidArgument.WithMessage("primary reconstruction coefficient %d uses a different scalar field", i)
		}
		encryptedShare := encryptedPrimaryShares[i]
		if encryptedShare == nil || !pk.CiphertextGroup().Contains(encryptedShare.Value()) {
			return nil, ErrInvalidArgument.WithMessage("encrypted primary share component %d is not in the Paillier ciphertext group", i)
		}
	}

	k2Inv, err := k2.TryInv()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot get k2 inverse")
	}

	qNat, err := num.NPlus().FromCardinal(curveOrder)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert q to Nat")
	}
	zModQ2, err := num.NewZMod(qNat.Square())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create ZMod q^2")
	}
	qInt, err := num.Z().FromNatPlus(qNat)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert q to integer")
	}
	qSquared := qInt.Square()
	componentCount := num.Z().FromUint64(uint64(len(encryptedPrimaryShares)))
	fullSigningBound := qSquared.Mul(qInt).
		Add(qSquared.Mul(num.Z().FromUint64(3)).Mul(componentCount)).
		Add(qInt.Mul(num.Z().FromUint64(2)))
	if !fullSigningBound.Mul(num.Z().FromUint64(2)).Compare(pk.Group().N().Lift()).IsLessThan() {
		return nil, ErrInvalidArgument.WithMessage(
			"Paillier modulus is too small for %d encrypted primary share components",
			len(encryptedPrimaryShares),
		)
	}

	// c1 = Enc(ρq + k2^(-1) * m')
	rho, err := zModQ2.Random(prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot generate random int")
	}
	rhoInt, err := num.Z().FromUint(rho)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert rho to integer")
	}
	mPrimeInt, err := num.Z().FromUnsignedNumeric(k2Inv.Mul(mPrime))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert message term to integer")
	}
	c1Message, err := paillier.NewPlaintextSymmetric(rhoInt.Mul(qInt).Add(mPrimeInt), pk.PlaintextGroup().Modulus())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create masked message plaintext")
	}
	c1, _, err := encryption.Encrypt(c1Message, pk, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot encrypt c1")
	}

	// Fuse each reconstruction coefficient with k2^(-1)r before the Paillier
	// scalar operation. Aggregating the lifted components first and then raising
	// the aggregate could multiply an extra q-lift into the Paillier modulus.
	scale := k2Inv.Mul(r)
	var encryptedPrimaryTerm *paillier.Ciphertext
	for i, encryptedShare := range encryptedPrimaryShares {
		exponent, err := num.Z().FromUnsignedNumeric(scale.Mul(primaryReconstructionCoefficients[i]))
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot convert primary component %d exponent to integer", i)
		}
		scaledComponent, err := pk.CiphertextScalarOp(encryptedShare, exponent)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot scale encrypted primary share component %d", i)
		}
		if encryptedPrimaryTerm == nil {
			encryptedPrimaryTerm = scaledComponent
			continue
		}
		encryptedPrimaryTerm, err = pk.CiphertextOp(encryptedPrimaryTerm, scaledComponent)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot combine encrypted primary share component %d", i)
		}
	}

	// Keep the complementary primary zero share and the refreshed secondary
	// share as separate, field-reduced terms. This preserves the effective
	// additive shares while avoiding multiplication of either integer lift.
	encryptedPrimaryZeroTerm, err := encryptReducedScalarTerm(scale.Mul(primaryZeroShare), pk, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot encrypt primary zero-share contribution")
	}
	encryptedSecondaryTerm, err := encryptReducedScalarTerm(scale.Mul(refreshedSecondaryShare), pk, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot encrypt refreshed secondary-share contribution")
	}

	c3, err = pk.CiphertextOp(c1, encryptedPrimaryTerm, encryptedPrimaryZeroTerm, encryptedSecondaryTerm)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot combine encrypted signing terms")
	}

	return c3, nil
}

func encryptReducedScalarTerm[S algebra.PrimeFieldElement[S]](
	term S,
	pk *paillier.PublicKey,
	prng io.Reader,
) (*paillier.Ciphertext, error) {
	termInt, err := num.Z().FromUnsignedNumeric(term)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert reduced scalar term to integer")
	}
	plaintext, err := paillier.NewPlaintextSymmetric(termInt, pk.PlaintextGroup().Modulus())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create reduced scalar plaintext")
	}
	ciphertext, _, err := encryption.Encrypt(plaintext, pk, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot encrypt reduced scalar term")
	}
	return ciphertext, nil
}

func paillierPlaintextToScalar[S algebra.PrimeFieldElement[S]](plaintext *paillier.Plaintext, scalarField algebra.PrimeField[S]) (S, error) {
	if plaintext == nil || scalarField == nil {
		return *new(S), ErrInvalidArgument.WithMessage("plaintext and scalar field must not be nil")
	}
	integer := plaintext.Normalise()
	scalar, err := scalarField.FromBytesBEReduce(integer.Abs().BytesBE())
	if err != nil {
		return *new(S), errs.Wrap(err).WithMessage("cannot reduce Paillier plaintext to scalar")
	}
	if integer.IsNegative() {
		return scalar.Neg(), nil
	}
	return scalar, nil
}

// MessageToScalar hashes a message into a curve scalar. It returns
// ErrInvalidArgument if cipherSuite is nil.
func MessageToScalar[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](cipherSuite *ecdsa.Suite[P, B, S], message []byte) (S, error) {
	if cipherSuite == nil {
		return *new(S), ErrInvalidArgument.WithMessage("suite must not be nil")
	}
	messageHash, err := hashing.Hash(cipherSuite.HashFunc(), message)
	if err != nil {
		return *new(S), errs.Wrap(err).WithMessage("cannot hash message")
	}
	sc, err := ecdsa.DigestToScalar(cipherSuite.ScalarField(), messageHash)
	if err != nil {
		return *new(S), errs.Wrap(err).WithMessage("cannot convert digest to scalar")
	}
	return sc, nil
}
