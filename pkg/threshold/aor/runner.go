package aor

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

func RunAgreeOnRandom(router testutils.Router, id sharing.ID, quorum network.Quorum, size int, tape transcripts.Transcript, prng io.Reader) ([]byte, error) {
	coparties := quorum.Clone().Unfreeze()
	coparties.Remove(id)

	party, err := NewParticipant(id, quorum, size, tape, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create participant")
	}

	// r1
	r1Out, err := party.Round1()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot run round 1")
	}
	r2In := hashmap.NewImmutableComparableFromNativeLike(testutils.ExchangeBroadcast(router, r1Out, coparties.List()...))

	// r2
	r2Out, err := party.Round2(r2In)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot run round 2")
	}
	r3In := hashmap.NewImmutableComparableFromNativeLike(testutils.ExchangeBroadcast(router, r2Out, coparties.List()...))

	// r3
	sample, err := party.Round3(r3In)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot run round 3")
	}

	return sample, nil
}
