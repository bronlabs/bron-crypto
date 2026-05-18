package aor

import (
	"encoding/binary"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/commitments/hashcom"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	transcriptLabel    = "BRON_CRYPTO_AOR-"
	sizeLabel          = "BRON_CRYPTO_AOR_SIZE-"
	commitmentKeyLabel = "BRON_CRYPTO_AOR_COMMITMENT_KEY-"
	commitmentLabel    = "BRON_CRYPTO_AOR_COMMITMENT-"
)

// Participant runs the Agree-on-Random protocol for a single party.
type Participant struct {
	id            sharing.ID
	size          int
	quorum        network.Quorum
	round         network.Round
	tape          transcripts.Transcript
	commitmentKey *hashcom.CommitmentKey
	prng          io.Reader
	state         State
}

type State struct {
	r            []byte
	rWitness     hashcom.Witness
	rCommitments map[sharing.ID]hashcom.Commitment
}

// NewParticipant initialises an AOR participant with transcript binding and randomness.
func NewParticipant(id sharing.ID, quorum network.Quorum, size int, tape transcripts.Transcript, prng io.Reader) (*Participant, error) {
	if size <= 0 || tape == nil || prng == nil || quorum == nil || !quorum.Contains(id) {
		return nil, ErrInvalidArgument.WithMessage("invalid arguments")
	}

	tape.AppendDomainSeparator(transcriptLabel)
	tape.AppendBytes(sizeLabel, binary.LittleEndian.AppendUint64(nil, uint64(size)))
	key, err := hashcom.ExtractCommitmentKey(tape, commitmentKeyLabel)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not extract commitment key from transcript")
	}

	return &Participant{
		id:            id,
		size:          size,
		quorum:        quorum,
		round:         1,
		tape:          tape,
		commitmentKey: key,
		prng:          prng,
		state:         State{}, //nolint:exhaustruct // initially empty state
	}, nil
}

func (p *Participant) SharingID() sharing.ID {
	return p.id
}
