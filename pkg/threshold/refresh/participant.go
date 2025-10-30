package refresh

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/hjky"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	transcriptLabel = "BRON_CRYPTO_REFRESH-"
)

type Participant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	shard           *tsig.BaseShard[G, S]
	zeroParticipant *hjky.Participant[G, S]
}

func NewParticipant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](sid network.SID, shard *tsig.BaseShard[G, S], tape transcripts.Transcript, prng io.Reader) (*Participant[G, S], error) {
	if shard == nil || tape == nil || prng == nil {
		return nil, errs.NewIsNil("argument")
	}

	tape.AppendDomainSeparator(fmt.Sprintf("%s%s", transcriptLabel, hex.EncodeToString(sid[:])))
	group := algebra.StructureMustBeAs[algebra.PrimeGroup[G, S]](shard.VerificationVector().Coefficients()[0].Structure())
	zeroParticipant, err := hjky.NewParticipant(sid, shard.Share().ID(), shard.AccessStructure(), group, tape, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create zero participant")
	}

	p := &Participant[G, S]{
		shard:           shard,
		zeroParticipant: zeroParticipant,
	}

	return p, nil
}

func (p *Participant[G, S]) SharingID() sharing.ID {
	return p.shard.Share().ID()
}
