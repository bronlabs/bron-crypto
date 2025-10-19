package refresh

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
)

func (p *Participant[G, S]) Round1() (*Round1Broadcast[G, S], network.OutgoingUnicasts[*Round1P2P[G, S]], error) {
	bc, uu, err := p.zeroParticipant.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to execute zero sharing Round1")
	}
	return bc, uu, nil
}

func (p *Participant[G, S]) Round2(r2b network.RoundMessages[*Round1Broadcast[G, S]], r2u network.RoundMessages[*Round1P2P[G, S]]) (*feldman.Share[S], feldman.VerificationVector[G, S], error) {
	share, verification, err := p.zeroParticipant.Round2(r2b, r2u)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to run round 2 of zero participant")
	}

	share = share.Add(p.share)
	verification = verification.Op(p.verificationVector)

	return share, verification, nil
}
