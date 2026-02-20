package hjky

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/feldman"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/errs-go/errs"
)

const (
	transcriptLabel  = "BRON_CRYPTO_HJKY-"
	coefficientLabel = "BRON_CRYPTO_HJKY_COEFFICIENT-"
)

// Participant executes the HJKY zero-sharing protocol.
type Participant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	sessionID       network.SID
	sharingID       sharing.ID
	accessStructure *sharing.ThresholdAccessStructure
	group           algebra.PrimeGroup[G, S]
	field           algebra.PrimeField[S]
	scheme          *feldman.Scheme[G, S]
	round           network.Round
	prng            io.Reader
	tape            transcripts.Transcript
	state           State[G, S]
}

type State[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	verificationVectors map[sharing.ID]feldman.VerificationVector[G, S]
	share               *feldman.Share[S]
}

// NewParticipant creates a zero-sharing participant bound to the given session and access structure.
func NewParticipant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](sid network.SID, id sharing.ID, as *sharing.ThresholdAccessStructure, g algebra.PrimeGroup[G, S], tape transcripts.Transcript, prng io.Reader) (*Participant[G, S], error) {
	if tape == nil || prng == nil || !as.Shareholders().Contains(id) {
		return nil, ErrInvalidArgument.WithMessage("invalid arguments")
	}

	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](g.ScalarStructure())
	scheme, err := feldman.NewScheme(g.Generator(), as)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create feldman scheme")
	}
	tape.AppendDomainSeparator(fmt.Sprintf("%s%s", transcriptLabel, hex.EncodeToString(sid[:])))

	return &Participant[G, S]{
		sessionID:       sid,
		sharingID:       id,
		accessStructure: as,
		group:           g,
		field:           field,
		scheme:          scheme,
		round:           1,
		prng:            prng,
		tape:            tape,
		state: State[G, S]{
			verificationVectors: nil,
			share:               nil,
		},
	}, nil
}

// SharingID returns the identifier for this participant within the access structure.
func (p *Participant[G, S]) SharingID() sharing.ID {
	return p.sharingID
}
