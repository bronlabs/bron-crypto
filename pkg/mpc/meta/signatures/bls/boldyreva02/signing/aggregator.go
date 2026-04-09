package signing

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/bls/boldyreva02"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
)

// Aggregator collects and combines partial BLS signatures from multiple cosigners
// into a single signature. It verifies each partial signature before aggregation.
type Aggregator[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	publicMaterial    *boldyreva02.PublicMaterial[PK, PKFE, SG, SGFE, E, S]
	targetRogueKeyAlg bls.RogueKeyPreventionAlgorithm
	targetDst         string
	scheme            *bls.Scheme[PK, PKFE, SG, SGFE, E, S]
	feldmanScheme     *feldman.Scheme[SG, S]
}

// PublicKeyMaterial returns the public cryptographic material used for verification.
// Returns nil if the receiver is nil.
func (A *Aggregator[PK, PKFE, SG, SGFE, E, S]) PublicKeyMaterial() *boldyreva02.PublicMaterial[PK, PKFE, SG, SGFE, E, S] {
	if A == nil {
		return nil
	}
	return A.publicMaterial
}

// NewShortKeyAggregator creates a new Aggregator for the short key variant of BLS signatures.
// In this variant, public keys are in G1 (smaller) and signatures are in G2 (larger).
func NewShortKeyAggregator[
	P1 curves.PairingFriendlyPoint[P1, FE1, P2, FE2, E, S], FE1 algebra.FieldElement[FE1],
	P2 curves.PairingFriendlyPoint[P2, FE2, P1, FE1, E, S], FE2 algebra.FieldElement[FE2],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	curveFamily curves.PairingFriendlyFamily[P1, FE1, P2, FE2, E, S],
	publicMaterial *boldyreva02.PublicMaterial[P1, FE1, P2, FE2, E, S],
	rogueKeyAlg bls.RogueKeyPreventionAlgorithm,
) (*Aggregator[P1, FE1, P2, FE2, E, S], error) {
	if curveFamily == nil {
		return nil, ErrInvalidArgument.WithMessage("curveFamily is nil")
	}
	scheme, err := bls.NewShortKeyScheme(curveFamily, bls.POP)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create BLS short key scheme")
	}
	out, err := newAggregator(scheme, publicMaterial, curveFamily.TwistedSubGroup(), rogueKeyAlg, bls.ShortKey)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create short key aggregator")
	}
	return out, nil
}

// NewLongKeyAggregator creates a new Aggregator for the long key variant of BLS signatures.
// In this variant, public keys are in G2 (larger) and signatures are in G1 (smaller).
func NewLongKeyAggregator[
	P1 curves.PairingFriendlyPoint[P1, FE1, P2, FE2, E, S], FE1 algebra.FieldElement[FE1],
	P2 curves.PairingFriendlyPoint[P2, FE2, P1, FE1, E, S], FE2 algebra.FieldElement[FE2],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	curveFamily curves.PairingFriendlyFamily[P1, FE1, P2, FE2, E, S],
	publicMaterial *boldyreva02.PublicMaterial[P2, FE2, P1, FE1, E, S],
	rogueKeyAlg bls.RogueKeyPreventionAlgorithm,
) (*Aggregator[P2, FE2, P1, FE1, E, S], error) {
	if curveFamily == nil {
		return nil, ErrInvalidArgument.WithMessage("curveFamily is nil")
	}
	scheme, err := bls.NewLongKeyScheme(curveFamily, bls.POP)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create BLS long key scheme")
	}
	out, err := newAggregator(scheme, publicMaterial, curveFamily.SourceSubGroup(), rogueKeyAlg, bls.LongKey)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create long key aggregator")
	}
	return out, nil
}

func newAggregator[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	scheme *bls.Scheme[PK, PKFE, SG, SGFE, E, S],
	publicMaterial *boldyreva02.PublicMaterial[PK, PKFE, SG, SGFE, E, S],
	signatureSubGroup curves.PairingFriendlyCurve[SG, SGFE, PK, PKFE, E, S],
	rogueKeyAlg bls.RogueKeyPreventionAlgorithm,
	variant bls.Variant,
) (*Aggregator[PK, PKFE, SG, SGFE, E, S], error) {
	if !bls.RogueKeyPreventionAlgorithmIsSupported(rogueKeyAlg) {
		return nil, ErrInvalidArgument.WithMessage("rogue key prevention algorithm %d is not supported", rogueKeyAlg)
	}
	blsDst, err := scheme.CipherSuite().GetDst(rogueKeyAlg, variant)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to get BLS destination for rogue key prevention algorithm")
	}
	kwScheme, err := kw.NewInducedScheme(publicMaterial.MSP())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create KW scheme")
	}
	feldmanScheme, err := feldman.NewSchemeFromKW(signatureSubGroup, kwScheme)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create Feldman scheme from KW scheme")
	}
	return &Aggregator[PK, PKFE, SG, SGFE, E, S]{
		scheme:            scheme,
		targetRogueKeyAlg: rogueKeyAlg,
		targetDst:         blsDst,
		publicMaterial:    publicMaterial,
		feldmanScheme:     feldmanScheme,
	}, nil
}

// Aggregate combines partial signatures from multiple cosigners into a single signature.
// It verifies each partial signature against the corresponding partial public key before aggregation.
// For POP algorithm, it also verifies the proof-of-possession signatures.
//
// Parameters:
//   - partialSigs: The collection of partial signatures from cosigners
//   - message: The original message that was signed
//
// Returns the aggregated BLS signature, or an error if verification fails or
// the partial signatures are not from an authorized quorum.
func (A *Aggregator[PK, PKFE, SG, SGFE, E, S]) Aggregate(
	partialSigs ds.Map[sharing.ID, *boldyreva02.PartialSignature[SG, SGFE, PK, PKFE, E, S]],
	message []byte,
) (*bls.Signature[SG, SGFE, PK, PKFE, E, S], error) {
	if utils.IsNil(partialSigs) {
		return nil, ErrInvalidArgument.WithMessage("partialSigs is nil")
	}
	if len(message) == 0 {
		return nil, ErrInvalidArgument.WithMessage("message cannot be empty")
	}
	if !A.publicMaterial.MSP().Accepts(partialSigs.Keys()...) {
		return nil, ErrInvalidArgument.WithMessage("partial signatures are not authorized in the access structure")
	}
	partialSignatureVerifier, err := A.scheme.Verifier(bls.VerifyWithCustomDST[PK](A.targetDst))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create verifier for partial signature")
	}
	publicKeyShares := A.PublicKeyMaterial().PublicKeyShares()
	n := partialSigs.Size()
	sigShares := make([]*feldman.LiftedShare[SG, S], 0, n)
	popShares := make([]*feldman.LiftedShare[SG, S], 0, n)
	for sender, psig := range partialSigs.Iter() {
		if err := psig.Validate(A.targetRogueKeyAlg); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, sender).WithMessage("invalid partial signature from sender %d", sender)
		}

		publicKeyShare, exists := publicKeyShares.Get(sender)
		if !exists {
			return nil, ErrInvalidArgument.WithMessage("partial public key for sender %d does not exist in public material", sender)
		}

		if len(psig.SigmaI) != len(publicKeyShare.Value()) {
			return nil, ErrInvalidArgument.WithTag(base.IdentifiableAbortPartyIDTag, sender).
				WithMessage("partial signature SigmaI length %d does not match expected %d for sender %d",
					len(psig.SigmaI), len(publicKeyShare.Value()), sender)
		}

		partialPublicKey := make([]*bls.PublicKey[PK, PKFE, SG, SGFE, E, S], len(publicKeyShare.Value()))
		for i, shareValue := range publicKeyShare.Value() {
			partialPublicKey[i], err = bls.NewPublicKey(shareValue)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("failed to create partial public key for sender %d", sender)
			}
		}
		var internalMessage []byte
		switch A.targetRogueKeyAlg {
		case bls.Basic:
			internalMessage = message
		case bls.MessageAugmentation:
			internalMessage, err = bls.AugmentMessage(message, A.PublicKeyMaterial().PublicKeyValue())
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("failed to augment message for sender %d", sender)
			}
		case bls.POP:
			internalMessage = message
			internalPopMessage := A.publicMaterial.PublicKey().Bytes()
			popDst := A.scheme.CipherSuite().GetPopDst(A.scheme.Variant())
			popVerifier, err := A.scheme.Verifier(bls.VerifyWithCustomDST[PK](popDst))
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("failed to create verifier for POP")
			}
			for i, pki := range partialPublicKey {
				if err := popVerifier.Verify(psig.SigmaPopI[i], pki, internalPopMessage); err != nil {
					return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, sender).WithMessage("failed to verify POP signature for component %d", i)
				}
			}
		default:
			return nil, ErrInvalidArgument.WithMessage("unsupported rogue key prevention algorithm: %d", A.scheme.RogueKeyPreventionAlgorithm())
		}
		for i, pki := range partialPublicKey {
			if err := partialSignatureVerifier.Verify(psig.SigmaI[i], pki, internalMessage); err != nil {
				return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, sender).WithMessage("failed to verify partial signature for component %d", i)
			}
		}

		sigShare, err := feldman.NewLiftedShare(sender, sliceutils.Map(psig.SigmaI, func(sigma *bls.Signature[SG, SGFE, PK, PKFE, E, S]) SG {
			return sigma.Value()
		})...)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create lifted share from partial signature for sender %d", sender)
		}
		sigShares = append(sigShares, sigShare)
		if A.targetRogueKeyAlg == bls.POP {
			popShare, err := feldman.NewLiftedShare(sender, sliceutils.Map(psig.SigmaPopI, func(sigmaPop *bls.Signature[SG, SGFE, PK, PKFE, E, S]) SG {
				return sigmaPop.Value()
			})...)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("failed to create lifted share from POP partial signature for sender %d", sender)
			}
			popShares = append(popShares, popShare)
		}
	}

	reconstructedSignature, err := A.feldmanScheme.ReconstructInTheExponent(sigShares...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to reconstruct aggregated signature value from shares")
	}
	if A.targetRogueKeyAlg == bls.POP {
		reconstructedPop, err := A.feldmanScheme.ReconstructInTheExponent(popShares...)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to reconstruct aggregated POP value from shares")
		}
		pop, err := bls.NewProofOfPossession(reconstructedPop.Value())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create POP from aggregated value")
		}
		sig, err := bls.NewSignature(reconstructedSignature.Value(), pop)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create signature from aggregated value")
		}
		return sig, nil
	} else {
		sig, err := bls.NewSignature(reconstructedSignature.Value(), nil)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create signature from aggregated value")
		}
		return sig, nil
	}
}
