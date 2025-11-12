package signing

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/network"
	schnorrpok "github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/lindell17"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	transcriptLabel = "BRON_CRYPTO_LINDELL17_SIGN-"
)

type Cosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	round uint
	// Base participant
	prng  io.Reader
	sid   network.SID
	tape  transcripts.Transcript
	suite *ecdsa.Suite[P, B, S]

	// Threshold participant
	shard *lindell17.Shard[P, B, S]

	commitmentScheme *hash_comm.Scheme
	niDlogScheme     compiler.NonInteractiveProtocol[*schnorrpok.Statement[P, S], *schnorrpok.Witness[S]]
}

type PrimaryCosignerState[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	k1           S
	bigR1Opening hash_comm.Witness
	bigR         P
	r            S
	bigR1        P
}

type PrimaryCosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Cosigner[P, B, S]

	secondarySharingId sharing.ID
	state              *PrimaryCosignerState[P, B, S]
}

type SecondaryCosignerState[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	bigR1Commitment hash_comm.Commitment
	k2              S
	bigR2           P
}

type SecondaryCosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Cosigner[P, B, S]

	primarySharingId sharing.ID
	state            *SecondaryCosignerState[P, B, S]
}

func (cosigner *Cosigner[P, B, S]) SharingID() sharing.ID {
	return cosigner.shard.Share().ID()
}

func newCosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](sessionId network.SID, suite *ecdsa.Suite[P, B, S], hisSharingID sharing.ID, myShard *lindell17.Shard[P, B, S], niCompiler compiler.Name, tape transcripts.Transcript, prng io.Reader, roundNo uint) (cosigner *Cosigner[P, B, S], err error) {
	err = validateInputs(suite, hisSharingID, myShard, niCompiler, tape, prng)
	if err != nil {
		return nil, errs.WrapArgument(err, "invalid input arguments")
	}

	dst := fmt.Sprintf("%s_%s_%s_%s", transcriptLabel, sessionId, niCompiler, suite.Curve().Name())
	tape.AppendDomainSeparator(dst)

	ck, err := hash_comm.NewKeyFromCRSBytes(sessionId, dst, myShard.PublicKey().Value().ToCompressed())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create commitment key from CRS")
	}
	commitmentScheme, err := hash_comm.NewScheme(ck)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create commitment scheme")
	}
	schnorrProtocol, err := schnorrpok.NewProtocol(suite.Curve().Generator(), prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create schnorr protocol")
	}

	niDlogScheme, err := compiler.Compile(niCompiler, schnorrProtocol, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to compile niDlogProver")
	}

	return &Cosigner[P, B, S]{
		round:            roundNo,
		prng:             prng,
		suite:            suite,
		sid:              sessionId,
		tape:             tape,
		shard:            myShard,
		commitmentScheme: commitmentScheme,
		niDlogScheme:     niDlogScheme,
	}, nil
}

func NewPrimaryCosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](sessionId network.SID, suite *ecdsa.Suite[P, B, S], secondarySharingID sharing.ID, myShard *lindell17.Shard[P, B, S], niCompiler compiler.Name, tape transcripts.Transcript, prng io.Reader) (primaryCosigner *PrimaryCosigner[P, B, S], err error) {
	cosigner, err := newCosigner(sessionId, suite, secondarySharingID, myShard, niCompiler, tape, prng, 1)
	if err != nil {
		return nil, errs.WrapValidation(err, "could not construct primary cosigner")
	}
	primaryCosigner = &PrimaryCosigner[P, B, S]{
		Cosigner:           *cosigner,
		secondarySharingId: secondarySharingID,
		state:              &PrimaryCosignerState[P, B, S]{},
	}
	return primaryCosigner, nil
}

func NewSecondaryCosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](sessionId network.SID, suite *ecdsa.Suite[P, B, S], primarySharingID sharing.ID, myShard *lindell17.Shard[P, B, S], niCompiler compiler.Name, tape transcripts.Transcript, prng io.Reader) (secondaryCosigner *SecondaryCosigner[P, B, S], err error) {
	cosigner, err := newCosigner(sessionId, suite, primarySharingID, myShard, niCompiler, tape, prng, 2)
	if err != nil {
		return nil, errs.WrapValidation(err, "could not construct secondary cosigner")
	}
	secondaryCosigner = &SecondaryCosigner[P, B, S]{
		Cosigner:         *cosigner,
		primarySharingId: primarySharingID,
		state:            &SecondaryCosignerState[P, B, S]{},
	}
	return secondaryCosigner, nil
}

func validateInputs[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](suite *ecdsa.Suite[P, B, S], other sharing.ID, myShard *lindell17.Shard[P, B, S], nic compiler.Name, tape transcripts.Transcript, prng io.Reader) error {
	if suite == nil {
		return errs.NewIsNil("suite is nil")
	}
	if suite.IsDeterministic() {
		return errs.NewArgument("suite cannot be deterministic for MPC signing")
	}
	if myShard == nil {
		return errs.NewArgument("myShard is nil")
	}
	if other == myShard.Share().ID() {
		return errs.NewArgument("other sharing ID %d is equal to my sharing ID", other)
	}
	if !myShard.AccessStructure().Shareholders().Contains(other) {
		return errs.NewArgument("other sharing ID %d not in my shard access structure", other)
	}
	if !compiler.IsSupported(nic) {
		return errs.NewArgument("unsupported NI compiler: %s", nic)
	}
	if tape == nil {
		return errs.NewIsNil("tape is nil")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}
