package signing

import (
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	mpcschnorr "github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/schnorr/lindell22"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
)

// Aggregator combines partial signatures into a complete signature.
type Aggregator[
	VR mpcschnorr.MPCFriendlyVariant[GE, S, M], GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message,
] struct {
	pkm          *lindell22.PublicMaterial[GE, S]
	group        algebra.PrimeGroup[GE, S]
	sf           algebra.PrimeField[S]
	variant      VR
	verifier     schnorrlike.Verifier[VR, GE, S, M]
	psigVerifier schnorrlike.Verifier[VR, GE, S, M]
	feldmanVSS   *feldman.Scheme[GE, S]
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
	SCH mpcschnorr.MPCFriendlyScheme[VR, GE, S, M, KG, SG, VF],
	VR mpcschnorr.MPCFriendlyVariant[GE, S, M],
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
	kwScheme, err := kw.NewInducedScheme(pk.MSP())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create KW scheme for aggregator")
	}
	feldmanVSS, err := feldman.NewSchemeFromKW(group, kwScheme)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create Feldman VSS scheme for aggregator")
	}
	return &Aggregator[VR, GE, S, M]{pkm: pk, group: group, sf: sf, variant: scheme.Variant(), verifier: verifier, psigVerifier: psigVerifier, feldmanVSS: feldmanVSS}, nil
}

// Aggregate combines partial signatures into a complete signature, verifying validity.
// Returns an identifiable abort error if any partial signature is invalid.
func (a *Aggregator[VR, GE, S, M]) Aggregate(
	partialSignatures ds.Map[sharing.ID, *lindell22.PartialSignature[GE, S]],
	message M,
) (*schnorrlike.Signature[GE, S], error) {
	if a == nil {
		return nil, ErrNilArgument.WithMessage("aggregator cannot be nil")
	}
	quorum := hashset.NewComparable(partialSignatures.Keys()...).Freeze()
	if !a.pkm.MSP().Accepts(quorum.List()...) {
		return nil, ErrInvalidMembership.WithMessage("invalid authorization: not enough shares are qualified")
	}
	for sender, psig := range partialSignatures.Iter() {
		if psig == nil {
			return nil, ErrNilArgument.WithMessage("partial signature from sender %d cannot be nil", sender).WithTag(
				base.IdentifiableAbortPartyIDTag, sender,
			)
		}
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
		return !x.Sig.E.Equal(e)
	}) {

		return nil, ErrInvalidType.WithMessage("partial signatures have inconsistent challenges")
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
	quorumAsUnanimitySet, err := unanimity.NewUnanimityAccessStructure(quorum)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create minimal qualified access structure")
	}
	for sender, psig := range partialSignatures.Iter() {
		if psig == nil {
			return nil, ErrNilArgument.WithMessage("partial signature cannot be nil")
		}
		senderPKShare, ok := a.pkm.PublicKeyShares().Get(sender)
		if !ok {
			return nil, ErrInvalidMembership.WithMessage("invalid authorization: sender %d is not in public material", sender)
		}
		senderAdditivePKShare, err := a.feldmanVSS.ConvertLiftedShareToAdditive(senderPKShare, quorumAsUnanimitySet)
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
