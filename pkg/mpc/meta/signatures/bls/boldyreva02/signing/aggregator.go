package signing

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/bls/boldyreva02"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
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
	feldmanScheme     *feldman.Scheme[PK, S]
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
	kwScheme, err := kw.NewInducedScheme(publicMaterial.MSP())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create KW scheme")
	}
	feldmanScheme, err := feldman.NewSchemeFromKW(curveFamily.SourceSubGroup(), kwScheme)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create Feldman scheme from KW scheme")
	}

	return &Aggregator[P1, FE1, P2, FE2, E, S]{
		scheme:            scheme,
		targetRogueKeyAlg: rogueKeyAlg,
		targetDst:         blsDst,
		publicMaterial:    publicMaterial,
		feldmanScheme:     feldmanScheme,
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
	kwScheme, err := kw.NewInducedScheme(publicMaterial.MSP())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create KW scheme")
	}
	feldmanScheme, err := feldman.NewSchemeFromKW(curveFamily.TwistedSubGroup(), kwScheme)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create Feldman scheme from KW scheme")
	}
	return &Aggregator[P2, FE2, P1, FE1, E, S]{
		scheme:            scheme,
		targetRogueKeyAlg: rogueKeyAlg,
		targetDst:         blsDst,
		publicMaterial:    publicMaterial,
		feldmanScheme:     feldmanScheme,
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
	quorum, err := unanimity.NewUnanimityAccessStructure(hashset.NewComparable(partialSigs.Keys()...).Freeze())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create unanimity access structure")
	}
	publicKeyShares := A.PublicKeyMaterial().PublicKeyShares()
	sigShares := []SG{}
	popShares := []SG{}
	for sender, psig := range partialSigs.Iter() {
		if err := psig.Validate(A.targetRogueKeyAlg); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, sender).WithMessage("invalid partial signature from sender %d", sender)
		}

		publicKeyShare, exists := publicKeyShares.Get(sender)
		if !exists {
			return nil, ErrInvalidArgument.WithMessage("partial public key for sender %d does not exist in public material", sender)
		}
		additivePublicKeyShare, err := A.feldmanScheme.ConvertLiftedShareToAdditive(publicKeyShare, quorum)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to convert lifted share to additive share for sender %d", sender)
		}
		partialPublicKey, err := bls.NewPublicKey(additivePublicKeyShare.Value().Op(psig.ZeroPublicKeyShift))
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create partial public key for sender %d", sender)
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
			if err := popVerifier.Verify(psig.SigmaPopI, partialPublicKey, internalPopMessage); err != nil {
				return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, sender).WithMessage("failed to verify POP signature")
			}
		default:
			return nil, ErrInvalidArgument.WithMessage("unsupported rogue key prevention algorithm: %d", A.scheme.RogueKeyPreventionAlgorithm())
		}
		if err := partialSignatureVerifier.Verify(psig.SigmaI, partialPublicKey, internalMessage); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, sender).WithMessage("failed to verify partial signature")
		}
		sigShares = append(sigShares, psig.SigmaI.Value())
		if A.targetRogueKeyAlg == bls.POP {
			popShares = append(popShares, psig.SigmaPopI.Value())
		}
	}

	aggregatedSignatureValue := algebrautils.Fold(sigShares[0], sigShares[1:]...)
	if A.targetRogueKeyAlg == bls.POP {
		aggregatedPopValue := algebrautils.Fold(popShares[0], popShares[1:]...)
		pop, err := bls.NewProofOfPossession(aggregatedPopValue)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create POP from aggregated value")
		}
		sig, err := bls.NewSignature(aggregatedSignatureValue, pop)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create signature from aggregated value")
		}
		return sig, nil
	}

	sig, err := bls.NewSignature(aggregatedSignatureValue, nil)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create signature from aggregated value")
	}
	return sig, nil
}
