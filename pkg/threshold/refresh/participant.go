package refresh

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/hjky"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	transcriptLabel = "BRON_CRYPTO_REFRESH-"
)

type Participant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	id                 sharing.ID
	share              *feldman.Share[S]
	verificationVector feldman.VerificationVector[G, S]

	zeroParticipant *hjky.Participant[G, S]
}

func NewParticipant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](sid network.SID, share *feldman.Share[S], verificationVector feldman.VerificationVector[G, S], as sharing.ThresholdAccessStructure, tape transcripts.Transcript, prng io.Reader) (*Participant[G, S], error) {
	if share == nil || verificationVector == nil || tape == nil || prng == nil || as == nil || !as.Shareholders().Contains(share.ID()) {
		return nil, errs.NewIsNil("argument")
	}

	tape.AppendDomainSeparator(fmt.Sprintf("%s%s", transcriptLabel, hex.EncodeToString(sid[:])))
	group := algebra.StructureMustBeAs[algebra.PrimeGroup[G, S]](verificationVector.Coefficients()[0].Structure())
	zeroParticipant, err := hjky.NewParticipant(sid, share.ID(), as, group, tape, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create zero participant")
	}

	p := &Participant[G, S]{
		id:                 share.ID(),
		share:              share,
		verificationVector: verificationVector,
		zeroParticipant:    zeroParticipant,
	}

	return p, nil
}

func (p *Participant[G, S]) SharingID() sharing.ID {
	return p.id
}
