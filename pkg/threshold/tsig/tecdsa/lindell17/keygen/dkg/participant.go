package dkg

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/network"
	schnorrpok "github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/lp"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/lpdl"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/lindell17"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/errs-go/errs"
)

const (
	transcriptLabel = "BRON_CRYPTO_LINDELL17_DKG-"
)

// Participant runs the Lindell17 DKG protocol.
type Participant[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	round uint
	// Base participant
	prng  io.Reader
	curve ecdsa.Curve[P, B, S]
	sid   network.SID
	tape  transcripts.Transcript

	// Threshold participant
	shard       *tecdsa.Shard[P, B, S]
	nic         compiler.Name
	quorumBytes [][]byte
	state       *State[P, B, S]
}

// State holds internal DKG state across rounds.
type State[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	myXPrime          S
	myXDoublePrime    S
	myBigQPrime       P
	myBigQDoublePrime P
	myBigQOpening     hash_comm.Witness
	myPaillierPk      *paillier.PublicKey
	myPaillierSk      *paillier.PrivateKey
	myRPrime          *paillier.Nonce
	myRDoublePrime    *paillier.Nonce

	paillierScheme    *paillier.Scheme
	commitmentSchemes map[sharing.ID]*hash_comm.Scheme
	niDlogScheme      compiler.NonInteractiveProtocol[*schnorrpok.Statement[P, S], *schnorrpok.Witness[S]]

	theirBigQCommitment          map[sharing.ID]hash_comm.Commitment
	theirBigQPrime               map[sharing.ID]P
	theirBigQDoublePrime         map[sharing.ID]P
	theirPaillierPublicKeys      map[sharing.ID]*paillier.PublicKey
	theirPaillierEncryptedShares map[sharing.ID]*paillier.Ciphertext

	lpProvers                map[sharing.ID]*lp.Prover
	lpVerifiers              map[sharing.ID]*lp.Verifier
	lpdlPrimeProvers         map[sharing.ID]*lpdl.Prover[P, B, S]
	lpdlPrimeVerifiers       map[sharing.ID]*lpdl.Verifier[P, B, S]
	lpdlDoublePrimeProvers   map[sharing.ID]*lpdl.Prover[P, B, S]
	lpdlDoublePrimeVerifiers map[sharing.ID]*lpdl.Verifier[P, B, S]
}

// NewParticipant constructs a DKG participant.
func NewParticipant[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	sid network.SID,
	shard *tecdsa.Shard[P, B, S],
	curve ecdsa.Curve[P, B, S],
	prng io.Reader,
	nic compiler.Name,
	tape transcripts.Transcript,
) (*Participant[P, B, S], error) {
	if prng == nil {
		return nil, ErrInvalidArgument.WithMessage("prng must not be nil")
	}
	if tape == nil {
		return nil, ErrInvalidArgument.WithMessage("tape must not be nil")
	}
	if shard == nil {
		return nil, ErrInvalidArgument.WithMessage("shard must not be nil")
	}
	if !compiler.IsSupported(nic) {
		return nil, ErrInvalidArgument.WithMessage("unsupported NIC: %s", nic)
	}

	dst := fmt.Sprintf("%s_%s_%s_%s", transcriptLabel, sid, nic, curve.Name())
	tape.AppendDomainSeparator(dst)

	commitmentSchemes := make(map[sharing.ID]*hash_comm.Scheme)
	for id := range shard.AccessStructure().Shareholders().Iter() {
		ck, err := hash_comm.NewKeyFromCRSBytes(
			sid, dst, binary.BigEndian.AppendUint64(nil, uint64(id)),
		)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not create commitment key from CRS")
		}
		scheme, err := hash_comm.NewScheme(ck)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not create commitment scheme")
		}
		commitmentSchemes[id] = scheme
	}

	schnorrProtocol, err := schnorrpok.NewProtocol(curve.Generator(), prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create schnorr protocol")
	}
	niDlogScheme, err := compiler.Compile(nic, schnorrProtocol, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compile niDlogProver")
	}

	//nolint:exhaustruct // partially initialised
	return &Participant[P, B, S]{
		round:       1,
		prng:        prng,
		curve:       curve,
		sid:         sid,
		nic:         nic,
		tape:        tape,
		shard:       shard,
		quorumBytes: lindell17.QuorumBytes(shard.AccessStructure().Shareholders()),
		//nolint:exhaustruct // partially initialised
		state: &State[P, B, S]{
			paillierScheme:    paillier.NewScheme(),
			commitmentSchemes: commitmentSchemes,
			niDlogScheme:      niDlogScheme,

			theirBigQCommitment:          make(map[sharing.ID]hash_comm.Commitment),
			theirBigQPrime:               make(map[sharing.ID]P),
			theirBigQDoublePrime:         make(map[sharing.ID]P),
			theirPaillierPublicKeys:      make(map[sharing.ID]*paillier.PublicKey),
			theirPaillierEncryptedShares: make(map[sharing.ID]*paillier.Ciphertext),

			lpProvers:                make(map[sharing.ID]*lp.Prover),
			lpVerifiers:              make(map[sharing.ID]*lp.Verifier),
			lpdlPrimeProvers:         make(map[sharing.ID]*lpdl.Prover[P, B, S]),
			lpdlPrimeVerifiers:       make(map[sharing.ID]*lpdl.Verifier[P, B, S]),
			lpdlDoublePrimeProvers:   make(map[sharing.ID]*lpdl.Prover[P, B, S]),
			lpdlDoublePrimeVerifiers: make(map[sharing.ID]*lpdl.Verifier[P, B, S]),
		},
	}, nil
}

// SharingID returns the participant sharing identifier.
func (p *Participant[P, B, S]) SharingID() sharing.ID {
	return p.shard.Share().ID()
}
