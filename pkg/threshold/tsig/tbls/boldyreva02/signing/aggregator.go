package signing

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tbls/boldyreva02"
)

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

func (A *Aggregator[PK, PKFE, SG, SGFE, E, S]) PublicKeyMaterial() *boldyreva02.PublicMaterial[PK, PKFE, SG, SGFE, E, S] {
	if A == nil {
		return nil
	}
	return A.publicMaterial
}

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
		return nil, errs.NewIsNil("curveFamily")
	}
	if !bls.RogueKeyPreventionAlgorithmIsSupported(rogueKeyAlg) {
		return nil, errs.NewType("rogue key prevention algorithm %d is not supported", rogueKeyAlg)
	}
	scheme, err := bls.NewShortKeyScheme(curveFamily, bls.POP)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create BLS short key scheme")
	}
	blsDst, err := scheme.CipherSuite().GetDst(rogueKeyAlg, bls.ShortKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to get BLS destination for rogue key prevention algorithm")
	}
	return &Aggregator[P1, FE1, P2, FE2, E, S]{
		scheme:            scheme,
		targetRogueKeyAlg: rogueKeyAlg,
		targetDst:         blsDst,
		publicMaterial:    publicMaterial,
	}, nil
}

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
		return nil, errs.NewIsNil("curveFamily")
	}
	if !bls.RogueKeyPreventionAlgorithmIsSupported(rogueKeyAlg) {
		return nil, errs.NewType("rogue key prevention algorithm %d is not supported", rogueKeyAlg)
	}
	scheme, err := bls.NewLongKeyScheme(curveFamily, bls.POP)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create BLS long key scheme")
	}
	blsDst, err := scheme.CipherSuite().GetDst(rogueKeyAlg, bls.LongKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to get BLS destination for rogue key prevention algorithm")
	}
	return &Aggregator[P2, FE2, P1, FE1, E, S]{
		scheme:            scheme,
		targetRogueKeyAlg: rogueKeyAlg,
		targetDst:         blsDst,
		publicMaterial:    publicMaterial,
	}, nil
}

func (A *Aggregator[PK, PKFE, SG, SGFE, E, S]) Aggregate(
	partialSigs network.RoundMessages[*boldyreva02.PartialSignature[SG, SGFE, PK, PKFE, E, S]],
	message []byte,
) (*bls.Signature[SG, SGFE, PK, PKFE, E, S], error) {
	if partialSigs == nil {
		return nil, errs.NewIsNil("partialSigs")
	}
	if len(message) == 0 {
		return nil, errs.NewArgument("message cannot be empty")
	}
	if !A.publicMaterial.AccessStructure().IsAuthorized(partialSigs.Keys()...) {
		return nil, errs.NewArgument("partial signatures are not authorized in the access structure")
	}
	partialSignatureVerifier, err := A.scheme.Verifier(bls.VerifyWithCustomDST[PK](A.targetDst))
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create verifier for partial signature")
	}
	sigShares := feldman.SharesInExponent[SG, S]{}
	popShares := feldman.SharesInExponent[SG, S]{}
	for sender, psig := range partialSigs.Iter() {
		partialPublicKey, exists := A.publicMaterial.PartialPublicKeys().Get(sender)
		if !exists {
			return nil, errs.NewArgument("partial public key for sender %d does not exist in public material", sender)
		}
		var err error
		var internalMessage []byte
		switch A.targetRogueKeyAlg {
		case bls.Basic:
			internalMessage = message
		case bls.MessageAugmentation:
			internalMessage, err = bls.AugmentMessage(message, A.publicMaterial.PublicKey().Value())
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to augment message for sender %d", sender)
			}
		case bls.POP:
			internalMessage = message
			internalPopMessage := A.publicMaterial.PublicKey().Bytes()
			popDst := A.scheme.CipherSuite().GetPopDst(A.scheme.Variant())
			popVerifier, err := A.scheme.Verifier(bls.VerifyWithCustomDST[PK](popDst))
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to create verifier for POP")
			}
			if err := popVerifier.Verify(psig.SigmaPopI, partialPublicKey, internalPopMessage); err != nil {
				return nil, errs.WrapVerification(err, "failed to verify POP signature for sender %d", sender)
			}
		default:
			return nil, errs.NewType("unsupported rogue key prevention algorithm: %d", A.scheme.RogueKeyPreventionAlgorithm())
		}
		if err := partialSignatureVerifier.Verify(psig.SigmaI, partialPublicKey, internalMessage); err != nil {
			return nil, errs.WrapVerification(err, "failed to verify partial signature for sender %d", sender)
		}
		shareInExponent, err := feldman.NewLiftedShare(sender, psig.SigmaI.Value())
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to create additive share for sender %d", sender)
		}
		sigShares = append(sigShares, shareInExponent)
		if A.targetRogueKeyAlg == bls.POP {
			popShareInExponent, err := feldman.NewLiftedShare(sender, psig.SigmaPopI.Value())
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to create additive share for POP signature for sender %d", sender)
			}
			popShares = append(popShares, popShareInExponent)
		}
	}

	reconstructedSignatureValue, err := sigShares.ReconstructAsAdditive()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to reconstruct signature value from shares")
	}
	var pop *bls.ProofOfPossession[SG, SGFE, PK, PKFE, E, S]
	if A.targetRogueKeyAlg == bls.POP {
		reconstructedPopValue, err := popShares.ReconstructAsAdditive()
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to reconstruct POP value from shares")
		}
		pop, err = bls.NewProofOfPossession(reconstructedPopValue)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to create POP from reconstructed value")
		}
	}
	aggregatedSignature, err := bls.NewSignature(reconstructedSignatureValue, pop)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create signature from reconstructed value")
	}
	return aggregatedSignature, nil
}
