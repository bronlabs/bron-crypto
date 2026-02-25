package signing

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa/lindell17"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/exchange"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/errs-go/errs"
)

const (
	r1CorrelationID = "Lindell17SignRound1"
	r2CorrelationID = "Lindell17SignRound2"
	r3CorrelationID = "Lindell17SignRound3"
	r4CorrelationID = "Lindell17SignRound4"
)

type primaryRunner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	cosigner *PrimaryCosigner[P, B, S]
	message  []byte
}

type secondaryRunner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	cosigner *SecondaryCosigner[P, B, S]
	message  []byte
}

func NewPrimaryRunner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	sessionID network.SID,
	suite *ecdsa.Suite[P, B, S],
	secondarySharingID sharing.ID,
	myShard *lindell17.Shard[P, B, S],
	niCompiler compiler.Name,
	tape transcripts.Transcript,
	prng io.Reader,
	message []byte,
) (network.Runner[*ecdsa.Signature[S]], error) {
	cosigner, err := NewPrimaryCosigner(sessionID, suite, secondarySharingID, myShard, niCompiler, tape, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create primary cosigner")
	}
	return &primaryRunner[P, B, S]{
		cosigner: cosigner,
		message:  message,
	}, nil
}

func NewSecondaryRunner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	sessionID network.SID,
	suite *ecdsa.Suite[P, B, S],
	primarySharingID sharing.ID,
	myShard *lindell17.Shard[P, B, S],
	niCompiler compiler.Name,
	tape transcripts.Transcript,
	prng io.Reader,
	message []byte,
) (network.Runner[*ecdsa.Signature[S]], error) {
	cosigner, err := NewSecondaryCosigner(sessionID, suite, primarySharingID, myShard, niCompiler, tape, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create secondary cosigner")
	}
	return &secondaryRunner[P, B, S]{
		cosigner: cosigner,
		message:  message,
	}, nil
}

func (r *primaryRunner[P, B, S]) Run(rt *network.Router) (*ecdsa.Signature[S], error) {
	r1Out, err := r.cosigner.Round1()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 1")
	}
	r1u := hashmap.NewComparable[sharing.ID, *Round1OutputP2P]()
	r1u.Put(r.cosigner.secondarySharingID, r1Out)
	err = exchange.UnicastSend(rt, r1CorrelationID, r1u.Freeze())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot send round 1")
	}

	r2In, err := exchange.UnicastReceive[*Round2OutputP2P[P, B, S]](rt, r2CorrelationID, hashset.NewComparable(r.cosigner.secondarySharingID).Freeze())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot receive round 2")
	}
	r2FromSecondary, ok := r2In.Get(r.cosigner.secondarySharingID)
	if !ok {
		return nil, ErrMissing.WithMessage("missing round 2 message from secondary")
	}
	r3Out, err := r.cosigner.Round3(r2FromSecondary)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 3")
	}
	r3u := hashmap.NewComparable[sharing.ID, *Round3OutputP2P[P, B, S]]()
	r3u.Put(r.cosigner.secondarySharingID, r3Out)
	err = exchange.UnicastSend(rt, r3CorrelationID, r3u.Freeze())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot send round 3")
	}

	r4In, err := exchange.UnicastReceive[*lindell17.PartialSignature](rt, r4CorrelationID, hashset.NewComparable(r.cosigner.secondarySharingID).Freeze())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot receive round 4")
	}
	r4FromSecondary, ok := r4In.Get(r.cosigner.secondarySharingID)
	if !ok {
		return nil, ErrMissing.WithMessage("missing round 4 message from secondary")
	}
	signature, err := r.cosigner.Round5(r4FromSecondary, r.message)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 5")
	}
	return signature, nil
}

func (r *secondaryRunner[P, B, S]) Run(rt *network.Router) (*ecdsa.Signature[S], error) {
	r1In, err := exchange.UnicastReceive[*Round1OutputP2P](rt, r1CorrelationID, hashset.NewComparable(r.cosigner.primarySharingID).Freeze())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot receive round 1")
	}
	r1FromPrimary, ok := r1In.Get(r.cosigner.primarySharingID)
	if !ok {
		return nil, ErrMissing.WithMessage("missing round 1 message from primary")
	}
	r2Out, err := r.cosigner.Round2(r1FromPrimary)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 2")
	}
	r2u := hashmap.NewComparable[sharing.ID, *Round2OutputP2P[P, B, S]]()
	r2u.Put(r.cosigner.primarySharingID, r2Out)
	err = exchange.UnicastSend(rt, r2CorrelationID, r2u.Freeze())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot send round 2")
	}

	r3In, err := exchange.UnicastReceive[*Round3OutputP2P[P, B, S]](rt, r3CorrelationID, hashset.NewComparable(r.cosigner.primarySharingID).Freeze())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot receive round 3")
	}
	r3FromPrimary, ok := r3In.Get(r.cosigner.primarySharingID)
	if !ok {
		return nil, ErrMissing.WithMessage("missing round 3 message from primary")
	}
	r4Out, err := r.cosigner.Round4(r3FromPrimary, r.message)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 4")
	}
	r4u := hashmap.NewComparable[sharing.ID, *lindell17.PartialSignature]()
	r4u.Put(r.cosigner.primarySharingID, r4Out)
	err = exchange.UnicastSend(rt, r4CorrelationID, r4u.Freeze())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot send round 4")
	}

	//nolint:nilnil // Secondary does not produce a final ECDSA signature.
	return nil, nil
}
