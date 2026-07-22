package dkg

import (
	"encoding/binary"
	"fmt"
	"io"
	"slices"
	"testing"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/commitments/hashcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/lindell17"
	"github.com/bronlabs/bron-crypto/pkg/network"
	schnorrpok "github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/lp"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/lpdl"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

const (
	// DefaultPaillierKeyLen is the minimum Paillier modulus length used in production.
	DefaultPaillierKeyLen = base.IFCKeyLength

	transcriptLabel      = "BRON_CRYPTO_LINDELL17_DKG-"
	commitmentKeyLabel   = "BRON_CRYPTO_LINDELL17_DKG_COMMITMENT_KEY-"
	commitmentPartyLabel = "BRON_CRYPTO_LINDELL17_DKG_COMMITMENT_PARTY-"
)

// Participant runs the Lindell17 auxiliary-information DKG protocol. It
// proves a Paillier encryption of every component of the local MSP share.
type Participant[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ctx            *session.Context
	round          network.Round
	paillierKeyLen int
	prng           io.Reader
	curve          ecdsa.Curve[P, B, S]
	baseShard      *mpc.BaseShard[P, S]
	quorumBytes    [][]byte
	state          *State[P, B, S]
}

// State holds secret and public DKG state across rounds. Component slices are
// ordered by ascending absolute MSP row identifier.
type State[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	myXPrime          []S
	myXDoublePrime    []S
	myBigQPrime       []P
	myBigQDoublePrime []P
	myBigQOpening     hashcom.Witness
	myPaillierPk      *paillier.PublicKey
	myPaillierSk      *paillier.SecretKey
	myRPrime          []*paillier.Nonce
	myRDoublePrime    []*paillier.Nonce

	commitmentKeys map[sharing.ID]*hashcom.CommitmentKey
	niDlogScheme   compiler.NonInteractiveProtocol[*schnorrpok.Statement[P, S], *schnorrpok.Witness[S]]

	theirBigQCommitment          map[sharing.ID]hashcom.Commitment
	theirBigQPrime               map[sharing.ID][]P
	theirBigQDoublePrime         map[sharing.ID][]P
	theirPaillierPublicKeys      map[sharing.ID]*paillier.PublicKey
	theirPaillierEncryptedShares map[sharing.ID][]*paillier.Ciphertext

	lpProvers                map[sharing.ID]*lp.Prover
	lpVerifiers              map[sharing.ID]*lp.Verifier
	lpdlPrimeProvers         map[sharing.ID][]*lpdl.Prover[P, B, S]
	lpdlPrimeVerifiers       map[sharing.ID][]*lpdl.Verifier[P, B, S]
	lpdlDoublePrimeProvers   map[sharing.ID][]*lpdl.Prover[P, B, S]
	lpdlDoublePrimeVerifiers map[sharing.ID][]*lpdl.Verifier[P, B, S]
}

// NewParticipant constructs a DKG participant. The session quorum must be the
// complete MSP shareholder set: this protocol generates auxiliary information
// for every shareholder, not only for a signing quorum. In production,
// paillierKeyLen must be at least DefaultPaillierKeyLen. The PRNG must be
// cryptographically secure and safe for concurrent use by proof batches. All
// participants in one session must use the same paillierKeyLen and nic.
func NewParticipant[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	ctx *session.Context,
	baseShard *mpc.BaseShard[P, S],
	paillierKeyLen int,
	curve ecdsa.Curve[P, B, S],
	prng io.Reader,
	nic compiler.Name,
) (*Participant[P, B, S], error) {
	if prng == nil {
		return nil, ErrInvalidArgument.WithMessage("prng must not be nil")
	}
	if ctx == nil {
		return nil, ErrInvalidArgument.WithMessage("context must not be nil")
	}
	if baseShard == nil {
		return nil, ErrInvalidArgument.WithMessage("base shard must not be nil")
	}
	if curve == nil {
		return nil, ErrInvalidArgument.WithMessage("curve must not be nil")
	}
	if baseShard.Share().ID() != ctx.HolderID() {
		return nil, ErrInvalidArgument.WithMessage("sharing id must match context id")
	}
	if !baseShard.MSP().Shareholders().Equal(ctx.Quorum()) {
		return nil, ErrInvalidArgument.WithMessage("context quorum must equal the MSP shareholder set")
	}
	if !testing.Testing() && paillierKeyLen < base.IFCKeyLength {
		return nil, ErrInvalidArgument.WithMessage("Paillier key length must be at least %d bits", base.IFCKeyLength)
	}
	if paillierKeyLen < 1 {
		return nil, ErrInvalidArgument.WithMessage("Paillier key length must be positive")
	}
	if !compiler.IsSupported(nic) {
		return nil, ErrInvalidArgument.WithMessage("unsupported NIC: %s", nic)
	}

	sid := ctx.SessionID()
	dst := fmt.Sprintf("%s_%x_%s_%s", transcriptLabel, sid, nic, curve.Name())
	ctx.Transcript().AppendDomainSeparator(dst)

	commitmentKeys := make(map[sharing.ID]*hashcom.CommitmentKey, ctx.Quorum().Size())
	for id := range ctx.AllPartiesOrdered() {
		keyTranscript := ctx.Transcript().Clone()
		keyTranscript.AppendBytes(commitmentPartyLabel, binary.BigEndian.AppendUint64(nil, uint64(id)))
		key, err := hashcom.ExtractCommitmentKey(keyTranscript, commitmentKeyLabel)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not extract commitment key for participant %d", id)
		}
		commitmentKeys[id] = key
	}

	schnorrProtocol, err := schnorrpok.NewProtocol(curve.Generator(), prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create Schnorr protocol")
	}
	niDlogScheme, err := compiler.Compile(nic, schnorrProtocol, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compile discrete-log protocol")
	}
	localComponentCount := len(baseShard.Share().Value())

	return &Participant[P, B, S]{
		ctx:            ctx,
		round:          1,
		paillierKeyLen: paillierKeyLen,
		prng:           prng,
		curve:          curve,
		baseShard:      baseShard,
		quorumBytes:    lindell17.QuorumBytes(ctx.Quorum()),
		state: &State[P, B, S]{ //nolint:exhaustruct // round state is populated lazily
			commitmentKeys:    commitmentKeys,
			niDlogScheme:      niDlogScheme,
			myXPrime:          make([]S, localComponentCount),
			myXDoublePrime:    make([]S, localComponentCount),
			myBigQPrime:       make([]P, localComponentCount),
			myBigQDoublePrime: make([]P, localComponentCount),
			myRPrime:          make([]*paillier.Nonce, localComponentCount),
			myRDoublePrime:    make([]*paillier.Nonce, localComponentCount),

			theirBigQCommitment:          make(map[sharing.ID]hashcom.Commitment, ctx.Quorum().Size()-1),
			theirBigQPrime:               make(map[sharing.ID][]P, ctx.Quorum().Size()-1),
			theirBigQDoublePrime:         make(map[sharing.ID][]P, ctx.Quorum().Size()-1),
			theirPaillierPublicKeys:      make(map[sharing.ID]*paillier.PublicKey, ctx.Quorum().Size()-1),
			theirPaillierEncryptedShares: make(map[sharing.ID][]*paillier.Ciphertext, ctx.Quorum().Size()-1),

			lpProvers:                make(map[sharing.ID]*lp.Prover, ctx.Quorum().Size()-1),
			lpVerifiers:              make(map[sharing.ID]*lp.Verifier, ctx.Quorum().Size()-1),
			lpdlPrimeProvers:         make(map[sharing.ID][]*lpdl.Prover[P, B, S], ctx.Quorum().Size()-1),
			lpdlPrimeVerifiers:       make(map[sharing.ID][]*lpdl.Verifier[P, B, S], ctx.Quorum().Size()-1),
			lpdlDoublePrimeProvers:   make(map[sharing.ID][]*lpdl.Prover[P, B, S], ctx.Quorum().Size()-1),
			lpdlDoublePrimeVerifiers: make(map[sharing.ID][]*lpdl.Verifier[P, B, S], ctx.Quorum().Size()-1),
		},
	}, nil
}

// SharingID returns the participant sharing identifier.
func (p *Participant[P, B, S]) SharingID() sharing.ID {
	return p.ctx.HolderID()
}

func (p *Participant[P, B, S]) qualifiedPeers(id sharing.ID) []sharing.ID {
	peers := make([]sharing.ID, 0, p.ctx.Quorum().Size()-1)
	for candidate := range p.ctx.AllPartiesOrdered() {
		if candidate != id && p.baseShard.MSP().Accepts(id, candidate) {
			peers = append(peers, candidate)
		}
	}
	return peers
}

func (p *Participant[P, B, S]) qualifiedPeersOrdered() func(func(sharing.ID) bool) {
	return slices.Values(p.qualifiedPeers(p.SharingID()))
}

func (p *Participant[P, B, S]) shareRows(id sharing.ID) []int {
	rows, ok := p.baseShard.MSP().HoldersToRows().Get(id)
	if !ok {
		return nil
	}
	return slices.Sorted(rows.Iter())
}
