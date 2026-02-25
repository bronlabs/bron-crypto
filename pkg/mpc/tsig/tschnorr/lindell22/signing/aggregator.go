package signing

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/feldman"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tschnorr"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tschnorr/lindell22"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
	"github.com/bronlabs/errs-go/errs"
)

// Aggregator combines partial signatures into a complete threshold signature.
type Aggregator[
	VR tschnorr.MPCFriendlyVariant[GE, S, M], GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message,
] struct {
	pkm          *lindell22.PublicMaterial[GE, S]
	group        algebra.PrimeGroup[GE, S]
	sf           algebra.PrimeField[S]
	variant      VR
	verifier     schnorrlike.Verifier[VR, GE, S, M]
	psigVerifier schnorrlike.Verifier[VR, GE, S, M]
}

// PublicMaterial returns the public key material for signature verification.
func (a *Aggregator[VR, GE, S, M]) PublicMaterial() *lindell22.PublicMaterial[GE, S] {
	if a == nil {
		return nil
	}
	return a.pkm
}

// NewAggregator creates a new signature aggregator for the given public material and scheme.
func NewAggregator[
	SCH tschnorr.MPCFriendlyScheme[VR, GE, S, M, KG, SG, VF],
	VR tschnorr.MPCFriendlyVariant[GE, S, M],
	GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message,
	KG schnorrlike.KeyGenerator[GE, S], SG schnorrlike.Signer[VR, GE, S, M], VF schnorrlike.Verifier[VR, GE, S, M],
](
	pk *lindell22.PublicMaterial[GE, S],
	scheme SCH,
) (*Aggregator[VR, GE, S, M], error) {
	if pk == nil {
		return nil, ErrNilArgument.WithMessage("public material cannot be nil")
	}
	group := pk.PublicKey().Group()
	sf, ok := group.ScalarStructure().(algebra.PrimeField[S])
	if !ok {
		return nil, ErrInvalidType.WithMessage("group scalar structure is not a prime field")
	}
	verifier, err := scheme.Verifier()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create verifier for scheme %s", scheme.Name())
	}
	psigVerifier, err := scheme.PartialSignatureVerifier(pk.PublicKey())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create partial signature verifier for scheme %s", scheme.Name())
	}
	return &Aggregator[VR, GE, S, M]{pkm: pk, group: group, sf: sf, variant: scheme.Variant(), verifier: verifier, psigVerifier: psigVerifier}, nil
}

// Aggregate combines partial signatures into a complete signature, verifying validity.
// Returns an identifiable abort error if any partial signature is invalid.
func (a *Aggregator[VR, GE, S, M]) Aggregate(
	partialSignatures network.RoundMessages[*lindell22.PartialSignature[GE, S]],
	message M,
) (*schnorrlike.Signature[GE, S], error) {
	if a == nil {
		return nil, ErrNilArgument.WithMessage("aggregator cannot be nil")
	}
	if partialSignatures == nil {
		return nil, ErrNilArgument.WithMessage("partial signatures cannot be nil")
	}
	quorum := hashset.NewComparable(partialSignatures.Keys()...).Freeze()
	if !a.pkm.AccessStructure().IsQualified(quorum.List()...) {
		return nil, ErrInvalidMembership.WithMessage("invalid authorization: not enough shares are qualified")
	}
	R := iterutils.Reduce(slices.Values(partialSignatures.Values()),
		a.group.OpIdentity(), func(acc GE, x *lindell22.PartialSignature[GE, S]) GE { return acc.Op(x.Sig.R) },
	)
	s := iterutils.Reduce(slices.Values(partialSignatures.Values()),
		a.sf.Zero(), func(acc S, x *lindell22.PartialSignature[GE, S]) S { return acc.Add(x.Sig.S) },
	)
	e, err := a.variant.ComputeChallenge(R, a.pkm.PublicKey().Value(), message)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compute challenge")
	}
	if sliceutils.Any(partialSignatures.Values(), func(x *lindell22.PartialSignature[GE, S]) bool {
		return x == nil || !x.Sig.E.Equal(e)
	}) {

		return nil, ErrInvalidType.WithMessage("invalid partial signature")
	}
	aggregatedSignature, err := schnorrlike.NewSignature(e, R, s)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create aggregated signature")
	}

	if err := a.verifier.Verify(aggregatedSignature, a.pkm.PublicKey(), message); err == nil {
		return aggregatedSignature, nil
	}

	// aggregated signature verification failed, now doing identifiable abort

	identityAborts := []error{}
	quorumAsUnanimitySet, err := accessstructures.NewUnanimityAccessStructure(quorum)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create minimal qualified access structure")
	}
	for sender, psig := range partialSignatures.Iter() {
		if psig == nil {
			return nil, ErrNilArgument.WithMessage("partial signature cannot be nil")
		}
		senderPartialPublicKey, _ := a.pkm.PartialPublicKeys().Get(sender)
		senderPKShare, err := feldman.NewLiftedShare(sender, senderPartialPublicKey.Value())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create lifted share for sender %d", sender)
		}
		senderAdditivePKShare, err := senderPKShare.ToAdditive(quorumAsUnanimitySet)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to convert lifted share to additive share for sender %d", sender)
		}
		senderAdditivePK, err := schnorrlike.NewPublicKey(senderAdditivePKShare.Value())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create public key for sender %d", sender)
		}
		if err := a.psigVerifier.Verify(&psig.Sig, senderAdditivePK, message); err != nil {
			identityAborts = append(identityAborts, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, sender).WithMessage("failed to verify partial signature"))
		}
	}
	if len(identityAborts) != 0 {
		return nil, errs.Join(identityAborts...).WithMessage("verification failed")
	}

	panic("should not reach here: not all partial signatures should have been valid")
}
