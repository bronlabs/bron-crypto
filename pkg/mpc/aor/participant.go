package aor

import (
	"encoding/binary"
	"io"

	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/errs-go/errs"
)

const (
	transcriptLabel    = "BRON_CRYPTO_AOR-"
	sizeLabel          = "BRON_CRYPTO_AOR_SIZE-"
	commitmentKeyLabel = "BRON_CRYPTO_AOR_COMMITMENT_KEY-"
	commitmentLabel    = "BRON_CRYPTO_AOR_COMMITMENT-"
)

// Participant runs the Agree-on-Random protocol for a single party.
type Participant struct {
	id               sharing.ID
	size             int
	quorum           network.Quorum
	round            network.Round
	tape             transcripts.Transcript
	commitmentScheme *hash_comm.Scheme
	prng             io.Reader
	state            State
}

type State struct {
	r            []byte
	rWitness     hash_comm.Witness
	rCommitments map[sharing.ID]hash_comm.Commitment
}

// NewParticipant initialises an AOR participant with transcript binding and randomness.
func NewParticipant(id sharing.ID, quorum network.Quorum, size int, tape transcripts.Transcript, prng io.Reader) (*Participant, error) {
	if size <= 0 || tape == nil || prng == nil || quorum == nil || !quorum.Contains(id) {
		return nil, ErrInvalidArgument.WithMessage("invalid arguments")
	}

	tape.AppendDomainSeparator(transcriptLabel)
	tape.AppendBytes(sizeLabel, binary.LittleEndian.AppendUint64(nil, uint64(size)))
	keyBytes, err := tape.ExtractBytes(commitmentKeyLabel, hash_comm.KeySize)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot extract commitment key")
	}
	var key hash_comm.Key
	copy(key[:], keyBytes)
	commitmentScheme, err := hash_comm.NewScheme(key)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create commitment scheme")
	}

	return &Participant{
		id:               id,
		size:             size,
		quorum:           quorum,
		round:            1,
		tape:             tape,
		commitmentScheme: commitmentScheme,
		prng:             prng,
		state:            State{}, //nolint:exhaustruct // initially empty state
	}, nil
}

func (p *Participant) SharingID() sharing.ID {
	return p.id
}
