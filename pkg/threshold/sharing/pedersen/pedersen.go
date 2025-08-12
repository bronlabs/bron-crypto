package pedersen

import (
	"io"
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	pedcom "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
)

type (
	ScalarField[FE Scalar[FE]] = interface {
		shamir.PrimeField[FE]
		pedcom.ScalarField[FE]
	}
	Scalar[FE algebra.PrimeFieldElement[FE]] = interface {
		shamir.FieldElement[FE]
		pedcom.Scalar[FE]
	}

	Group[E GroupElement[E, FE], FE Scalar[FE]]               = pedcom.Group[E, FE]
	GroupElement[E pedcom.GroupElement[E, FE], FE Scalar[FE]] = pedcom.GroupElement[E, FE]

	DealerFunc[S Scalar[S]]                               = *polynomials.DirectSumOfPolynomials[S]
	VerificationVector[E GroupElement[E, S], S Scalar[S]] = polynomials.ModuleValuedPolynomial[E, S]
	AccessStructure                                       = shamir.AccessStructure
)

const Name sharing.Name = "Pedersen Verifiable Secret Sharing Scheme"

var NewAccessStructure = shamir.NewAccessStructure

func NewScheme[E GroupElement[E, S], S Scalar[S]](key *pedcom.Key[E, S], threshold uint, shareholders ds.Set[sharing.ID]) (*Scheme[E, S], error) {
	pedcomScheme, err := pedcom.NewScheme(key)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create pedersen scheme")
	}
	field := key.G().Structure().(algebra.Module[E, S]).ScalarStructure().(algebra.PrimeField[S])
	shamirSSS, err := shamir.NewScheme(field, threshold, shareholders)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create shamir scheme")
	}
	return &Scheme[E, S]{
		key:              key,
		commitmentScheme: pedcomScheme,
		shamirSSS:        shamirSSS,
	}, nil
}

type Scheme[E GroupElement[E, S], S Scalar[S]] struct {
	key              *pedcom.Key[E, S]
	commitmentScheme commitments.Scheme[*pedcom.Witness[S], *pedcom.Message[S], *pedcom.Commitment[E, S]]
	shamirSSS        *shamir.Scheme[S]
}

func (s *Scheme[E, S]) Name() sharing.Name {
	return Name
}

func (s *Scheme[E, S]) AccessStructure() *AccessStructure {
	return s.shamirSSS.AccessStructure()
}

func (s *Scheme[E, S]) dealAllNonZeroShares(secret *Secret[S], prng io.Reader) (*shamir.DealerOutput[S], *shamir.Secret[S], shamir.DealerFunc[S], error) {
	if prng == nil {
		return nil, nil, nil, errs.NewIsNil("prng is nil")
	}
	var shamirShares *shamir.DealerOutput[S]
	var secretPoly shamir.DealerFunc[S]
	var err error
	for shamirShares == nil || sliceutils.Any(
		shamirShares.Shares().Values(), func(share *shamir.Share[S]) bool { return share.Value().IsZero() },
	) {
		if secret != nil {
			shamirShares, secretPoly, err = s.shamirSSS.DealAndRevealDealerFunc(secret, prng)
		} else {
			shamirShares, secret, secretPoly, err = s.shamirSSS.DealRandomAndRevealDealerFunc(prng)
		}
		if err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "could not deal shares")
		}
	}
	return shamirShares, secret, secretPoly, nil
}

func (s *Scheme[E, S]) DealAndRevealDealerFunc(secret *Secret[S], prng io.Reader) (*DealerOutput[E, S], DealerFunc[S], error) {
	if secret == nil {
		return nil, nil, errs.NewIsNil("secret is nil")
	}
	// Deal secret shares (can be zero)
	shamirShares, secretPoly, err := s.shamirSSS.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not deal secret shares")
	}
	// Deal blinding shares (must be non-zero for witness creation)
	blindingShares, _, blindingPoly, err := s.dealAllNonZeroShares(nil, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not deal blinding shares")
	}
	dealerFuncRing, err := polynomials.NewDirectSumOfPolynomialRings(s.shamirSSS.PolynomialRing(), 2)
	if err != nil {
		return nil, nil, errs.WrapSerialisation(err, "could not create direct sum polynomial ring")
	}
	dealerFunc, err := dealerFuncRing.New(secretPoly, blindingPoly)
	if err != nil {
		return nil, nil, errs.WrapSerialisation(err, "could not create direct sum polynomial")
	}
	dealerFuncInTheExponent, err := polynomials.LiftDirectSumOfPolynomialsToExponent(dealerFunc, s.key.G(), s.key.H())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not lift direct sum of polynomials to exponent")
	}
	verificationVector := dealerFuncInTheExponent.CoDiagonal()
	shares := hashmap.NewComparableFromNativeLike(
		maps.Collect(
			iterutils.Map2(
				shamirShares.Shares().Iter(),
				func(id sharing.ID, shamirShare *shamir.Share[S]) (sharing.ID, *Share[S]) {
					blindingShare, _ := blindingShares.Shares().Get(id)
					message := pedcom.NewMessage(shamirShare.Value())
					witness, _ := pedcom.NewWitness(blindingShare.Value())
					share, _ := NewShare(id, message, witness, nil)
					return id, share
				},
			),
		),
	)
	return &DealerOutput[E, S]{
		shares: shares.Freeze(),
		v:      verificationVector,
	}, dealerFunc, nil
}

func (s *Scheme[E, S]) Deal(secret *Secret[S], prng io.Reader) (*DealerOutput[E, S], error) {
	shares, _, err := s.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not deal shares")
	}
	return shares, nil
}

func (s *Scheme[E, S]) DealRandomAndRevealDealerFunc(prng io.Reader) (*DealerOutput[E, S], *Secret[S], DealerFunc[S], error) {
	if prng == nil {
		return nil, nil, nil, errs.NewIsNil("prng is nil")
	}
	value, err := s.shamirSSS.Field().Random(prng)
	if err != nil {
		return nil, nil, nil, errs.WrapRandomSample(err, "could not sample random field element")
	}
	secret := NewSecret(value)
	shares, poly, err := s.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "could not create shares")
	}
	return shares, secret, poly, nil
}

func (s *Scheme[E, S]) DealRandom(prng io.Reader) (*DealerOutput[E, S], *Secret[S], error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng is nil")
	}
	shares, secret, _, err := s.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not deal random shares")
	}
	return shares, secret, nil
}

func (s *Scheme[E, S]) Reconstruct(shares ...*Share[S]) (*Secret[S], error) {
	shamirShares, _ := sliceutils.MapErrFunc(shares, func(sh *Share[S]) (*shamir.Share[S], error) { return shamir.NewShare(sh.ID(), sh.secret.Value(), nil) })
	secret, err := s.shamirSSS.Reconstruct(shamirShares...)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not reconstruct secret from shares")
	}
	return secret, nil
}

func (s *Scheme[E, S]) ReconstructAndVerify(vector VerificationVector[E, S], shares ...*Share[S]) (*Secret[S], error) {
	reconstructed, err := s.Reconstruct(shares...)
	if err != nil {
		return nil, err
	}
	for i, share := range shares {
		if err := s.Verify(share, vector); err != nil {
			return nil, errs.WrapVerification(err, "verification failed for share %d", i)
		}
	}
	return reconstructed, nil
}

func (s *Scheme[E, S]) Verify(share *Share[S], vector VerificationVector[E, S]) error {
	if vector == nil {
		return errs.NewIsNil("verification vector is nil")
	}
	commitment, err := pedcom.NewCommitment(vector.Eval(s.shamirSSS.SharingIDToLagrangeNode(share.ID())))
	if err != nil {
		return errs.WrapSerialisation(err, "could not create commitment from recomputed value")
	}
	verifier := s.commitmentScheme.Verifier()
	if err := verifier.Verify(commitment, share.secret, share.blinding); err != nil {
		return errs.WrapVerification(err, "could not verify commitment")
	}
	return nil
}

func NewShare[S Scalar[S]](id sharing.ID, secret *pedcom.Message[S], blinding *pedcom.Witness[S], ac *AccessStructure) (*Share[S], error) {
	if secret == nil {
		return nil, errs.NewIsNil("secret cannot be nil")
	}
	if blinding == nil {
		return nil, errs.NewIsNil("blinding cannot be nil")
	}
	if ac != nil && !ac.Shareholders().Contains(id) {
		return nil, errs.NewMembership("share ID %d is not a valid shareholder", id)
	}
	return &Share[S]{
		id:       id,
		secret:   secret,
		blinding: blinding,
	}, nil
}

type Share[S Scalar[S]] struct {
	id       sharing.ID
	secret   *pedcom.Message[S]
	blinding *pedcom.Witness[S]
}

func (s *Share[S]) ID() sharing.ID {
	return s.id
}

func (s *Share[S]) Value() S {
	return s.secret.Value()
}

func (s *Share[S]) Blinding() *pedcom.Witness[S] {
	if s == nil {
		return nil
	}
	return s.blinding
}

func (s *Share[S]) Secret() *pedcom.Message[S] {
	if s == nil {
		return nil
	}
	return s.secret
}

func (s *Share[S]) Op(other *Share[S]) *Share[S] {
	return &Share[S]{
		id:       s.id,
		secret:   s.secret.Op(other.secret),
		blinding: s.blinding.Op(other.blinding),
	}
}

func (s *Share[S]) Add(other *Share[S]) *Share[S] {
	return s.Op(other)
}

func (s *Share[S]) ScalarOp(scalar S) *Share[S] {
	// Special case: multiplying by zero is not supported in Pedersen VSS
	// because it would require a zero blinding factor, which is not allowed
	if scalar.IsZero() {
		panic(errs.NewIsZero("cannot multiply Pedersen share by zero - zero blinding factors are not allowed"))
	}
	
	w2, err := pedcom.NewWitness(scalar)
	if err != nil {
		panic(errs.WrapFailed(err, "could not create witness from scalar"))
	}
	m2 := pedcom.NewMessage(scalar)
	return &Share[S]{
		id:       s.id,
		secret:   s.secret.Mul(m2),
		blinding: s.blinding.Mul(w2),
	}
}

func (s *Share[S]) ScalarMul(scalar S) *Share[S] {
	return s.ScalarOp(scalar)
}

func (s *Share[S]) HashCode() base.HashCode {
	return s.secret.HashCode() ^ s.blinding.HashCode()
}

func (s *Share[S]) Equal(other *Share[S]) bool {
	if s == nil || other == nil {
		return s == other
	}
	return s.secret.Equal(other.secret) && s.blinding.Equal(other.blinding)
}

func (s *Share[S]) Bytes() []byte {
	return slices.Concat(
		s.secret.Value().Bytes(),
		s.blinding.Value().Bytes(),
	)
}

func (s *Share[S]) ToAdditive(qualifiedSet sharing.MinimalQualifiedAccessStructure) (*additive.Share[S], error) {
	ss, err := shamir.NewShare(s.id, s.secret.Value(), nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create shamir share from share")
	}
	return ss.ToAdditive(qualifiedSet)
}

func NewSecret[S Scalar[S]](value S) *Secret[S] {
	return shamir.NewSecret(value)
}

type Secret[S Scalar[S]] = shamir.Secret[S]

type DealerOutput[E GroupElement[E, S], S Scalar[S]] struct {
	shares ds.Map[sharing.ID, *Share[S]]
	v      VerificationVector[E, S]
}

func (d *DealerOutput[E, S]) Shares() ds.Map[sharing.ID, *Share[S]] {
	if d == nil {
		return nil
	}
	return d.shares
}

func (d *DealerOutput[E, S]) VerificationVector() VerificationVector[E, S] {
	if d == nil {
		return nil
	}
	return d.v
}

func _[E GroupElement[E, S], S Scalar[S]]() {
	var (
		_ sharing.Share[*Share[S]]                                                   = (*Share[S])(nil)
		_ sharing.LinearShare[*Share[S], S, *additive.Share[S], S, *AccessStructure] = (*Share[S])(nil)
		_ sharing.LinearlyShareableSecret[*Secret[S], S]                             = (*Secret[S])(nil)

		_ sharing.ThresholdSSS[*Share[S], *Secret[S], *DealerOutput[E, S], *AccessStructure]                                  = (*Scheme[E, S])(nil)
		_ sharing.VSSS[*Share[S], *Secret[S], VerificationVector[E, S], *DealerOutput[E, S], *AccessStructure]                = (*Scheme[E, S])(nil)
		_ sharing.LSSS[*Share[S], S, *additive.Share[S], *Secret[S], S, *DealerOutput[E, S], *AccessStructure, DealerFunc[S]] = (*Scheme[E, S])(nil)
	)
}
