package canetti

import (
	"encoding/binary"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/mathutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/batch_schnorr"
)

const (
	domainSeparator = "BRON_CRYPTO_DKG_CANETTI-"
	ckLabel         = "BRON_CRYPTO_DKG_CANETTI_CK-"
)

// Participant executes the Canetti-style DKG rounds for one party.
type Participant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	ctx           *session.Context
	commitmentKey hash_comm.Key
	group         algebra.PrimeGroup[G, S]
	sharingScheme *feldman.Scheme[G, S]
	schScheme     *batch_schnorr.Protocol[G, S]
	round         network.Round
	prng          io.Reader
	rhoLen        int
	state         state[G, S]
}

type state[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	dealerFunc         *feldman.DealerFunc[S]
	share              *feldman.Share[S]
	verificationVector *feldman.VerificationVector[G, S]

	rho []byte
	tau *batch_schnorr.State[S]
	msg map[sharing.ID]*CommitmentMessage[G, S]

	u  hash_comm.Witness
	vs map[sharing.ID]hash_comm.Commitment
}

// NewParticipant creates a participant bound to the provided session context,
// access structure, group, and randomness source.
func NewParticipant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](ctx *session.Context, accessStructure accessstructures.Monotone, group algebra.PrimeGroup[G, S], prng io.Reader) (*Participant[G, S], error) {
	if ctx == nil || accessStructure == nil || group == nil || prng == nil {
		return nil, ErrInvalidArgument.WithMessage("argument is nil")
	}
	if !ctx.Quorum().Equal(accessStructure.Shareholders()) {
		return nil, ErrInvalidArgument.WithMessage("invalid quorum")
	}

	ctx.Transcript().AppendDomainSeparator(domainSeparator)
	ckBytes, err := ctx.Transcript().ExtractBytes(ckLabel, hash_comm.KeySize)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create commitment key")
	}
	var commitmentKey hash_comm.Key
	copy(commitmentKey[:], ckBytes)
	sharingScheme, err := feldman.NewScheme(group, accessStructure)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create feldman scheme")
	}
	schScheme, err := batch_schnorr.NewProtocol(int(sharingScheme.MSP().D()), group, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create ZK scheme")
	}
	rhoLenBits := base.ComputationalSecurityBits + mathutils.CeilLog2(int(sharingScheme.MSP().D()))
	rhoLen := mathutils.CeilDiv(rhoLenBits, 8)

	//nolint:exhaustruct // state is lazy initialised
	p := &Participant[G, S]{
		ctx:           ctx,
		commitmentKey: commitmentKey,
		sharingScheme: sharingScheme,
		schScheme:     schScheme,
		group:         group,
		rhoLen:        rhoLen,
		round:         1,
		prng:          prng,
	}
	return p, nil
}

// SharingID returns the sharing identifier of the local participant.
func (p *Participant[G, S]) SharingID() sharing.ID {
	return p.ctx.HolderID()
}

func (p *Participant[G, S]) commit(message base.BytesLike) (hash_comm.Commitment, hash_comm.Witness, error) {
	messageBytes := message.Bytes()
	commitmentScheme, err := hash_comm.NewScheme(p.commitmentKey)
	if err != nil {
		return hash_comm.Commitment{}, hash_comm.Witness{}, errs.Wrap(err).WithMessage("cannot create commitment scheme")
	}
	committer, err := commitmentScheme.Committer()
	if err != nil {
		return hash_comm.Commitment{}, hash_comm.Witness{}, errs.Wrap(err).WithMessage("cannot create committer")
	}
	commitment, witness, err := committer.Commit(messageBytes, p.prng)
	if err != nil {
		return hash_comm.Commitment{}, hash_comm.Witness{}, errs.Wrap(err).WithMessage("cannot commit")
	}

	return commitment, witness, nil
}

func (p *Participant[G, S]) verify(message base.BytesLike, commitment hash_comm.Commitment, witness hash_comm.Witness) error {
	messageBytes := message.Bytes()
	commitmentScheme, err := hash_comm.NewScheme(p.commitmentKey)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create commitment scheme")
	}
	verifier, err := commitmentScheme.Verifier()
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create verifier")
	}
	if err := verifier.Verify(commitment, messageBytes, witness); err != nil {
		return errs.Wrap(err).WithMessage("invalid commitment")
	}

	return nil
}

type aux struct {
	sessionID network.SID
	sharingID sharing.ID
	rho       []byte
}

func newAux(sessionID network.SID, sharingID sharing.ID, rho []byte) *aux {
	return &aux{
		sessionID: sessionID,
		sharingID: sharingID,
		rho:       rho,
	}
}

func (aux *aux) Bytes() []byte {
	var out []byte
	out = append(out, aux.sessionID[:]...)
	out = binary.LittleEndian.AppendUint64(out, uint64(aux.sharingID))
	out = sliceutils.AppendLengthPrefixed(out, aux.rho)
	return out
}
