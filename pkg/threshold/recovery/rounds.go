package recovery

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials/interpolation/lagrange"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
)

// Round1 blinds the dealer polynomial and distributes blinded shares.
func (r *Recoverer[G, S]) Round1() (*Round1Broadcast[G, S], network.OutgoingUnicasts[*Round1P2P[G, S]], error) {
	blindOutput, _, err := r.scheme.DealRandom(r.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot deal blind")
	}

	shift, ok := blindOutput.Shares().Get(r.mislayerID)
	if !ok {
		return nil, nil, ErrInvalidArgument.WithMessage("cannot find mislayer share")
	}
	blindShares := make(map[sharing.ID]*feldman.Share[S])
	for id, s := range blindOutput.Shares().Iter() {
		blindShares[id] = s.SubPlain(shift.Value())
		if id == r.SharingID() {
			r.state.blindShare = blindShares[id]
		}
	}
	blindVerification := blindOutput.VerificationMaterial().OpElement(r.group.Generator().ScalarOp(shift.Value()).OpInv())

	r1b := &Round1Broadcast[G, S]{
		BlindVerificationVector: blindVerification,
	}
	r1u := hashmap.NewComparable[sharing.ID, *Round1P2P[G, S]]()
	for id := range r.quorum.Iter() {
		if id == r.mislayerID || id == r.SharingID() {
			continue
		}
		s, ok := blindShares[id]
		if !ok {
			return nil, nil, ErrFailed.WithMessage("missing share")
		}
		r1u.Put(id, &Round1P2P[G, S]{
			BlindShare: s,
		})
	}

	return r1b, r1u.Freeze(), nil
}

// Round2 aggregates blinded shares and publishes the original verification vector.
func (r *Recoverer[G, S]) Round2(r1b network.RoundMessages[*Round1Broadcast[G, S]], r1u network.RoundMessages[*Round1P2P[G, S]]) (*Round2Broadcast[G, S], network.OutgoingUnicasts[*Round2P2P[G, S]], error) {
	// TODO add share verification

	blindedShare := r.state.blindShare.Add(r.shard.Share())
	for id := range r.quorum.Iter() {
		if id == r.mislayerID || id == r.SharingID() {
			continue
		}
		u, ok := r1u.Get(id)
		if !ok {
			return nil, nil, ErrFailed.WithMessage("missing share")
		}
		b, ok := r1b.Get(id)
		if !ok {
			return nil, nil, ErrFailed.WithMessage("missing verification vector")
		}

		verificationVector := b.BlindVerificationVector
		if !verificationVector.Eval(r.field.FromUint64(uint64(r.mislayerID))).IsOpIdentity() {
			return nil, nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid share")
		}

		share := u.BlindShare
		err := r.scheme.Verify(share, verificationVector)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("cannot verify share")
		}

		blindedShare = blindedShare.Add(share)
	}

	r2b := &Round2Broadcast[G, S]{
		VerificationVector: r.shard.VerificationVector(),
	}
	r2u := hashmap.NewComparable[sharing.ID, *Round2P2P[G, S]]()
	r2u.Put(r.mislayerID, &Round2P2P[G, S]{
		BlindedShare: blindedShare,
	})

	return r2b, r2u.Freeze(), nil
}

// Round3 interpolates the blinded shares to reconstruct the missing share.
func (m *Mislayer[G, S]) Round3(r2b network.RoundMessages[*Round2Broadcast[G, S]], r2u network.RoundMessages[*Round2P2P[G, S]]) (share *feldman.Share[S], verification feldman.VerificationVector[G, S], err error) {
	xs := []S{}
	ys := []S{}

	var verificationVector feldman.VerificationVector[G, S]
	for id := range m.quorum.Iter() {
		if id == m.sharingID {
			continue
		}
		b, ok := r2b.Get(id)
		if !ok {
			return nil, nil, ErrFailed.WithMessage("missing message")
		}
		if verificationVector == nil {
			verificationVector = b.VerificationVector
		} else if !verificationVector.Equal(b.VerificationVector) {
			return nil, nil, base.ErrAbort.WithMessage("mislayer verification vector does not match")
		}

		u, ok := r2u.Get(id)
		if !ok {
			return nil, nil, ErrFailed.WithMessage("missing message")
		}
		xs = append(xs, m.field.FromUint64(uint64(id)))
		ys = append(ys, u.BlindedShare.Value())
	}

	shareValue, err := lagrange.InterpolateAt(xs, ys, m.field.FromUint64(uint64(m.sharingID)))
	if err != nil {
		return nil, nil, base.ErrAbort.WithMessage("cannot interpolate")
	}
	share, err = feldman.NewShare(m.sharingID, shareValue, nil)
	if err != nil {
		return nil, nil, ErrFailed.WithMessage("cannot create share")
	}
	err = m.scheme.Verify(share, verificationVector)
	if err != nil {
		return nil, nil, base.ErrAbort.WithMessage("cannot verify share")
	}

	return share, verificationVector, nil
}
