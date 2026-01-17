package refresh

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
)

// Round1 runs the zero-sharing subprotocol to derive a refresh offset.
func (p *Participant[G, S]) Round1() (broadcast *Round1Broadcast[G, S], unicasts network.OutgoingUnicasts[*Round1P2P[G, S]], err error) {
	bc, uu, err := p.zeroParticipant.Round1()
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("failed to execute zero sharing Round1")
	}
	return bc, uu, nil
}

// Round2 finishes the refresh by adding the zero-share to the existing shard.
func (p *Participant[G, S]) Round2(r2b network.RoundMessages[*Round1Broadcast[G, S]], r2u network.RoundMessages[*Round1P2P[G, S]]) (share *feldman.Share[S], verification feldman.VerificationVector[G, S], err error) {
	share, verification, err = p.zeroParticipant.Round2(r2b, r2u)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("failed to run round 2 of zero participant")
	}

	share = share.Add(p.shard.Share())
	verification = verification.Op(p.shard.VerificationVector())

	return share, verification, nil
}
