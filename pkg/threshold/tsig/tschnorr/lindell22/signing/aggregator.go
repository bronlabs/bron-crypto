package signing

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr/lindell22"
)

type Aggregator[
	VR tschnorr.MPCFriendlyVariant[GE, S, M], GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorr.Message,
] struct {
	pkm          *lindell22.PublicMaterial[GE, S]
	group        algebra.PrimeGroup[GE, S]
	sf           algebra.PrimeField[S]
	variant      VR
	verifier     schnorr.Verifier[VR, GE, S, M]
	psigVerifier schnorr.Verifier[VR, GE, S, M]
}

func (a *Aggregator[VR, GE, S, M]) PublicMaterial() *lindell22.PublicMaterial[GE, S] {
	if a == nil {
		return nil
	}
	return a.pkm
}

func NewAggregator[
	SCH tschnorr.MPCFriendlyScheme[VR, GE, S, M, KG, SG, VF],
	VR tschnorr.MPCFriendlyVariant[GE, S, M],
	GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorr.Message,
	KG schnorr.KeyGenerator[GE, S], SG schnorr.Signer[VR, GE, S, M], VF schnorr.Verifier[VR, GE, S, M],
](
	pk *lindell22.PublicMaterial[GE, S],
	scheme SCH,
) (*Aggregator[VR, GE, S, M], error) {
	if pk == nil {
		return nil, errs.NewIsNil("public material cannot be nil")
	}
	group := pk.PublicKey().Group()
	sf, ok := group.ScalarStructure().(algebra.PrimeField[S])
	if !ok {
		return nil, errs.NewType("group scalar structure is not a prime field")
	}
	verifier, err := scheme.Verifier()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create verifier for scheme %s", scheme.Name())
	}
	psigVerifier, err := scheme.PartialSignatureVerifier(pk.PublicKey())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create partial signature verifier for scheme %s", scheme.Name())
	}
	variant, err := scheme.Variant()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to get variant for scheme %s", scheme.Name())
	}
	return &Aggregator[VR, GE, S, M]{pkm: pk, group: group, sf: sf, variant: variant, verifier: verifier, psigVerifier: psigVerifier}, nil
}

func (a *Aggregator[VR, GE, S, M]) Aggregate(
	partialSignatures network.RoundMessages[*lindell22.PartialSignature[GE, S]],
	message M,
) (*schnorr.Signature[GE, S], error) {
	if a == nil {
		return nil, errs.NewIsNil("aggregator cannot be nil")
	}
	if partialSignatures == nil {
		return nil, errs.NewIsNil("partial signatures cannot be nil")
	}
	quorum := hashset.NewComparable(partialSignatures.Keys()...).Freeze()
	if !a.pkm.AccessStructure().IsAuthorized(quorum.List()...) {
		return nil, errs.NewMembership("invalid authorization: not enough shares are qualified")
	}
	R := iterutils.Reduce(slices.Values(partialSignatures.Values()),
		a.group.OpIdentity(), func(acc GE, x *lindell22.PartialSignature[GE, S]) GE { return acc.Op(x.Sig.R) },
	)
	s := iterutils.Reduce(slices.Values(partialSignatures.Values()),
		a.sf.Zero(), func(acc S, x *lindell22.PartialSignature[GE, S]) S { return acc.Add(x.Sig.S) },
	)
	e, err := a.variant.ComputeChallenge(R, a.pkm.PublicKey().Value(), message)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to compute challenge")
	}
	if sliceutils.Any(partialSignatures.Values(), func(x *lindell22.PartialSignature[GE, S]) bool {
		return x == nil || !x.Sig.E.Equal(e)
	}) {
		return nil, errs.NewType("invalid partial signature")
	}
	aggregatedSignature, err := schnorr.NewSignature(e, R, s)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create aggregated signature")
	}

	if err := a.verifier.Verify(aggregatedSignature, a.pkm.PublicKey(), message); err == nil {
		return aggregatedSignature, nil
	}

	// aggregated signature verification failed, now doing identifiable abort

	quorumAsMinimalQualifiedSet, err := sharing.NewMinimalQualifiedAccessStructure(quorum)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create minimal qualified access structure")
	}
	for sender, psig := range partialSignatures.Iter() {
		if psig == nil {
			return nil, errs.NewIsNil("partial signature cannot be nil")
		}
		senderPartialPublicKey, _ := a.pkm.PartialPublicKeys().Get(sender)
		senderPKShare, err := feldman.NewLiftedShare(sender, senderPartialPublicKey.Value())
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to create lifted share for sender %d", sender)
		}
		senderAdditivePKShare, err := senderPKShare.ToAdditive(quorumAsMinimalQualifiedSet)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to convert lifted share to additive share for sender %d", sender)
		}
		senderAdditivePK, err := schnorr.NewPublicKey(senderAdditivePKShare.Value())
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to create public key for sender %d", sender)
		}
		if err := a.psigVerifier.Verify(&psig.Sig, senderAdditivePK, message); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, sender, "failed to verify partial signature")
		}
	}
	panic("should not reach here: not all partial signatures should have been valid")
}
