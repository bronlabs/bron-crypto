package signing

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tbls/boldyreva02"
)

// Aggregator collects and combines partial BLS signatures from multiple cosigners
// into a single threshold signature. It verifies each partial signature before aggregation.
type Aggregator[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	publicMaterial    *boldyreva02.PublicMaterial[PK, PKFE, SG, SGFE, E, S]
	targetRogueKeyAlg bls.RogueKeyPreventionAlgorithm
	targetDst         string
	scheme            *bls.Scheme[PK, PKFE, SG, SGFE, E, S]
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
//
// Parameters:
//   - curveFamily: The pairing-friendly curve family to use
//   - publicMaterial: The public cryptographic material for the threshold scheme
//   - rogueKeyAlg: The rogue key prevention algorithm (Basic, MessageAugmentation, or POP)
//
// Returns an error if any parameter is invalid.
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
	if !bls.RogueKeyPreventionAlgorithmIsSupported(rogueKeyAlg) {
		return nil, ErrInvalidArgument.WithMessage("rogue key prevention algorithm %d is not supported", rogueKeyAlg)
	}
	scheme, err := bls.NewShortKeyScheme(curveFamily, bls.POP)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create BLS short key scheme")
	}
	blsDst, err := scheme.CipherSuite().GetDst(rogueKeyAlg, bls.ShortKey)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to get BLS destination for rogue key prevention algorithm")
	}
	return &Aggregator[P1, FE1, P2, FE2, E, S]{
		scheme:            scheme,
		targetRogueKeyAlg: rogueKeyAlg,
		targetDst:         blsDst,
		publicMaterial:    publicMaterial,
	}, nil
}

// NewLongKeyAggregator creates a new Aggregator for the long key variant of BLS signatures.
// In this variant, public keys are in G2 (larger) and signatures are in G1 (smaller).
//
// Parameters:
//   - curveFamily: The pairing-friendly curve family to use
//   - publicMaterial: The public cryptographic material for the threshold scheme
//   - rogueKeyAlg: The rogue key prevention algorithm (Basic, MessageAugmentation, or POP)
//
// Returns an error if any parameter is invalid.
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
	if !bls.RogueKeyPreventionAlgorithmIsSupported(rogueKeyAlg) {
		return nil, ErrInvalidArgument.WithMessage("rogue key prevention algorithm %d is not supported", rogueKeyAlg)
	}
	scheme, err := bls.NewLongKeyScheme(curveFamily, bls.POP)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create BLS long key scheme")
	}
	blsDst, err := scheme.CipherSuite().GetDst(rogueKeyAlg, bls.LongKey)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to get BLS destination for rogue key prevention algorithm")
	}
	return &Aggregator[P2, FE2, P1, FE1, E, S]{
		scheme:            scheme,
		targetRogueKeyAlg: rogueKeyAlg,
		targetDst:         blsDst,
		publicMaterial:    publicMaterial,
	}, nil
}

// Aggregate combines partial signatures from multiple cosigners into a single threshold signature.
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
	partialSigs network.RoundMessages[*boldyreva02.PartialSignature[SG, SGFE, PK, PKFE, E, S]],
	message []byte,
) (*bls.Signature[SG, SGFE, PK, PKFE, E, S], error) {
	if partialSigs == nil {
		return nil, ErrInvalidArgument.WithMessage("partialSigs is nil")
	}
	if len(message) == 0 {
		return nil, ErrInvalidArgument.WithMessage("message cannot be empty")
	}
	if !A.publicMaterial.AccessStructure().IsAuthorized(partialSigs.Keys()...) {
		return nil, ErrInvalidArgument.WithMessage("partial signatures are not authorized in the access structure")
	}
	partialSignatureVerifier, err := A.scheme.Verifier(bls.VerifyWithCustomDST[PK](A.targetDst))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create verifier for partial signature")
	}
	sigShares := feldman.SharesInExponent[SG, S]{}
	popShares := feldman.SharesInExponent[SG, S]{}
	for sender, psig := range partialSigs.Iter() {
		partialPublicKey, exists := A.publicMaterial.PartialPublicKeys().Get(sender)
		if !exists {
			return nil, ErrInvalidArgument.WithMessage("partial public key for sender %d does not exist in public material", sender)
		}
		var err error
		var internalMessage []byte
		switch A.targetRogueKeyAlg {
		case bls.Basic:
			internalMessage = message
		case bls.MessageAugmentation:
			internalMessage, err = bls.AugmentMessage(message, A.publicMaterial.PublicKey().Value())
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
			if err := popVerifier.Verify(psig.SigmaPopI, partialPublicKey, internalPopMessage); err != nil {
				return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, sender).WithMessage("failed to verify POP signature")
			}
		default:
			return nil, ErrInvalidArgument.WithMessage("unsupported rogue key prevention algorithm: %d", A.scheme.RogueKeyPreventionAlgorithm())
		}
		if err := partialSignatureVerifier.Verify(psig.SigmaI, partialPublicKey, internalMessage); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, sender).WithMessage("failed to verify partial signature")
		}
		shareInExponent, err := feldman.NewLiftedShare(sender, psig.SigmaI.Value())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create additive share for sender %d", sender)
		}
		sigShares = append(sigShares, shareInExponent)
		if A.targetRogueKeyAlg == bls.POP {
			popShareInExponent, err := feldman.NewLiftedShare(sender, psig.SigmaPopI.Value())
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("failed to create additive share for POP signature for sender %d", sender)
			}
			popShares = append(popShares, popShareInExponent)
		}
	}

	reconstructedSignatureValue, err := sigShares.ReconstructAsAdditive()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to reconstruct signature value from shares")
	}
	var pop *bls.ProofOfPossession[SG, SGFE, PK, PKFE, E, S]
	if A.targetRogueKeyAlg == bls.POP {
		reconstructedPopValue, err := popShares.ReconstructAsAdditive()
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to reconstruct POP value from shares")
		}
		pop, err = bls.NewProofOfPossession(reconstructedPopValue)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create POP from reconstructed value")
		}
	}
	aggregatedSignature, err := bls.NewSignature(reconstructedSignatureValue, pop)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create signature from reconstructed value")
	}
	return aggregatedSignature, nil
}
