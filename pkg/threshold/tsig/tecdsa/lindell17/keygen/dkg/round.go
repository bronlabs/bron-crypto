package dkg

import (
	"encoding/binary"
	"slices"

	"golang.org/x/sync/errgroup"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	schnorrpok "github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/lp"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/lpdl"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/lindell17"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	transcriptDLogSLabel = "Lindell2017DKGDLogS-"
	proverLabel          = "Lindell2017DKGProver-"
	bigQTwinLabel        = "Lindell2017DKGBigQTwin-"
)

// Round1 executes the first DKG round.
func (p *Participant[P, B, S]) Round1() (output *Round1Broadcast, err error) {
	// Validation
	if p.round != 1 {
		return nil, ErrRound.WithMessage("Running round %d but participant expected round %d", 1, p.round)
	}

	// 1.i. choose randomly x' and x'' such that x = 3x' + x'' and both x' and x'' are in (q/3, 2q/3) range
	xPrime, xDoublePrime, err := lindell17.DecomposeTwoThirds(p.shard.Share().Value(), p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot split share")
	}

	// 1.ii. calculate Q' and Q''
	bigQPrime := p.curve.ScalarBaseMul(xPrime)
	bigQDoublePrime := p.curve.ScalarBaseMul(xDoublePrime)

	// 1.iii. calculates commitments Qcom to Q' and Q''
	committer, err := p.state.commitmentSchemes[p.shard.Share().ID()].Committer()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create committer")
	}
	bigQCommitment, bigQOpening, err := committer.Commit(
		slices.Concat(bigQPrime.ToCompressed(), bigQDoublePrime.ToCompressed()),
		p.prng,
	)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot commit to (Q', Q'')")
	}

	p.state.myXPrime = xPrime
	p.state.myXDoublePrime = xDoublePrime
	p.state.myBigQPrime = bigQPrime
	p.state.myBigQDoublePrime = bigQDoublePrime
	p.state.myBigQOpening = bigQOpening

	// 1.iv. broadcast commitments
	p.round++
	return &Round1Broadcast{
		BigQCommitment: bigQCommitment,
	}, nil
}

// Round2 executes the second DKG round.
func (p *Participant[P, B, S]) Round2(input network.RoundMessages[*Round1Broadcast]) (output *Round2Broadcast[P, B, S], err error) {
	// Validation
	if p.round != 2 {
		return nil, ErrRound.WithMessage("Running round %d but participant expected round %d", 2, p.round)
	}

	// 2. store commitments
	for id := range p.shard.AccessStructure().Shareholders().Iter() {
		if id == p.shard.Share().ID() {
			continue
		}
		message, exists := input.Get(id)
		if !exists {
			return nil, ErrFailed.WithMessage("no input from participant with sharing id %d", id)
		}
		p.state.theirBigQCommitment[id] = message.BigQCommitment
	}

	// 2.i. calculate proofs of dlog knowledge of Q' and Q'' (Qdl' and Qdl'' respectively)
	dlogTranscript := p.tape.Clone()
	bigQPrimeProof, err := dlogProve(p, p.state.myBigQPrime, p.state.myBigQDoublePrime, p.state.myXPrime, dlogTranscript)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create dlog proof of Q'")
	}
	bigQDoublePrimeProof, err := dlogProve(p, p.state.myBigQDoublePrime, p.state.myBigQPrime, p.state.myXDoublePrime, dlogTranscript)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create dlog proof of Q''")
	}

	// 2.ii. send opening of Qcom revealing Q', Q'' and broadcast proofs of dlog knowledge of these (Qdl', Qdl'' respectively)
	p.round++
	return &Round2Broadcast[P, B, S]{
		BigQOpening:          p.state.myBigQOpening,
		BigQPrime:            p.state.myBigQPrime,
		BigQPrimeProof:       bigQPrimeProof,
		BigQDoublePrime:      p.state.myBigQDoublePrime,
		BigQDoublePrimeProof: bigQDoublePrimeProof,
	}, nil
}

// Round3 executes the third DKG round.
func (p *Participant[P, B, S]) Round3(input network.RoundMessages[*Round2Broadcast[P, B, S]]) (output *Round3Broadcast, err error) {
	// Validation
	if p.round != 3 {
		return nil, ErrRound.WithMessage("Running round %d but participant expected round %d", 3, p.round)
	}
	// 3.i. verify proofs of dlog knowledge of Qdl'_j Qdl''_j
	for id := range p.shard.AccessStructure().Shareholders().Iter() {
		if id == p.SharingID() {
			continue
		}
		message, exists := input.Get(id)
		if !exists {
			return nil, ErrFailed.WithMessage("no input from participant with sharing id %d", id)
		}

		// 3.i. open commitments
		verifier, err := p.state.commitmentSchemes[id].Verifier()
		if err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("cannot create verifier")
		}
		if err := verifier.Verify(
			p.state.theirBigQCommitment[id],
			slices.Concat(message.BigQPrime.ToCompressed(), message.BigQDoublePrime.ToCompressed()),
			message.BigQOpening,
		); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("cannot open (Q', Q'') commitment")
		}

		dlogTranscript := p.tape.Clone()
		if err := dlogVerify(p, id, message.BigQPrimeProof, message.BigQPrime, message.BigQDoublePrime, dlogTranscript); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("cannot verify dlog proof of Q'")
		}
		if err := dlogVerify(p, id, message.BigQDoublePrimeProof, message.BigQDoublePrime, message.BigQPrime, dlogTranscript); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("cannot verify dlog proof of Q''")
		}
		p.state.theirBigQPrime[id] = message.BigQPrime
		p.state.theirBigQDoublePrime[id] = message.BigQDoublePrime

		// 3.ii. verify that y_j == 3Q'_j + Q''_j and abort if not
		theirBigQ := message.BigQPrime.Add(message.BigQPrime).Add(message.BigQPrime).Add(message.BigQDoublePrime)
		partialPublicKey, exists := p.shard.PartialPublicKeys().Get(id)
		if !exists {
			return nil, ErrMissing.WithMessage("could not find participant partial publickey (sharing id=%d)", id)
		}
		if !theirBigQ.Equal(partialPublicKey.Value()) {
			return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid Q' or Q''")
		}
	}

	// 3.iii. generate a Paillier key pair
	keyGenerator, err := p.state.paillierScheme.Keygen()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot generate Paillier key generator")
	}
	p.state.myPaillierSk, p.state.myPaillierPk, err = keyGenerator.Generate(p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot generate Paillier keys")
	}
	// 3.iv. calculate ckey' = Enc(x'; r') and ckey'' = Enc(x''; r'')
	ps := p.state.myPaillierPk.PlaintextSpace()
	xPrimeMessage, err := ps.FromBytes(p.state.myXPrime.Bytes())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create plaintext from x'")
	}
	selfEncrypter, err := p.state.paillierScheme.SelfEncrypter(p.state.myPaillierSk)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create paillier self encrypter")
	}
	cKeyPrime, rPrime, err := selfEncrypter.SelfEncrypt(xPrimeMessage, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot encrypt x'")
	}
	xDoublePrimeMessage, err := ps.FromBytes(p.state.myXDoublePrime.Bytes())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create plaintext from x'")
	}
	cKeyDoublePrime, rDoublePrime, err := selfEncrypter.SelfEncrypt(xDoublePrimeMessage, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot encrypt x''")
	}
	p.state.myRPrime = rPrime
	p.state.myRDoublePrime = rDoublePrime

	// 3.vi. prove pairwise iz ZK that pk was generated correctly (LP)
	//       and that (ckey', ckey'') encrypt dlogs of (Q', Q'') (LPDL)
	// Note: Share single transcript clone across all proofs to preserve state
	paillierProofsTranscript := p.tape.Clone()
	for id := range p.shard.AccessStructure().Shareholders().Iter() {
		if id == p.shard.Share().ID() {
			continue
		}
		p.state.lpProvers[id], err = lp.NewProver(p.sid, base.ComputationalSecurityBits, p.state.myPaillierSk, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create LP prover")
		}
		p.state.lpdlPrimeProvers[id], err = lpdl.NewProver(p.sid, p.curve, p.state.myPaillierSk, p.state.myXPrime, p.state.myRPrime, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create PDL prover")
		}
		p.state.lpdlDoublePrimeProvers[id], err = lpdl.NewProver(p.sid, p.curve, p.state.myPaillierSk, p.state.myXDoublePrime, p.state.myRDoublePrime, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create PDL prover")
		}
	}

	// 3.v. broadcast (pk, ckey', ckey'')
	p.round++
	return &Round3Broadcast{
		CKeyPrime:         cKeyPrime,
		CKeyDoublePrime:   cKeyDoublePrime,
		PaillierPublicKey: p.state.myPaillierPk,
	}, nil
}

// Round4 executes the fourth DKG round.
func (p *Participant[P, B, S]) Round4(input network.RoundMessages[*Round3Broadcast]) (output network.OutgoingUnicasts[*Round4P2P], err error) {
	// Validation
	if p.round != 4 {
		return nil, ErrRound.WithMessage("Running round %d but participant expected round %d", 4, p.round)
	}

	r4o := hashmap.NewComparable[sharing.ID, *Round4P2P]()
	for id := range p.shard.AccessStructure().Shareholders().Iter() {
		if id == p.shard.Share().ID() {
			continue
		}
		message, exists := input.Get(id)
		if !exists {
			return nil, ErrFailed.WithMessage("no input from participant with sharing id %d", id)
		}
		theirPaillierPublicKey := message.PaillierPublicKey
		p.state.theirPaillierPublicKeys[id] = theirPaillierPublicKey
		theirCKeyPrime := message.CKeyPrime
		theirCKeyDoublePrime := message.CKeyDoublePrime

		// 4.i. calculate and store ckey_j = 3 (*) ckey'_j (+) ckey''_j
		p.state.theirPaillierEncryptedShares[id] = theirCKeyPrime.HomAdd(theirCKeyDoublePrime).HomAdd(theirCKeyDoublePrime).HomAdd(theirCKeyDoublePrime)

		// 4.ii. LP and LPDL continue
		// Share single transcript clone across all verifiers to preserve state
		paillierProofsTranscript := p.tape.Clone()
		p.state.lpVerifiers[id], err = lp.NewVerifier(p.sid, base.ComputationalSecurityBits, theirPaillierPublicKey, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create P verifier")
		}
		p.state.lpdlPrimeVerifiers[id], err = lpdl.NewVerifier(p.sid, theirPaillierPublicKey, p.state.theirBigQPrime[id], theirCKeyPrime, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create PDL verifier")
		}
		p.state.lpdlDoublePrimeVerifiers[id], err = lpdl.NewVerifier(p.sid, theirPaillierPublicKey, p.state.theirBigQDoublePrime[id], theirCKeyDoublePrime, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create PDL verifier")
		}

		outgoingMessage := new(Round4P2P)
		outgoingMessage.LpRound1Output, err = p.state.lpVerifiers[id].Round1()
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 1 of LP verifier")
		}
		outgoingMessage.LpdlPrimeRound1Output, err = p.state.lpdlPrimeVerifiers[id].Round1()
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 1 of LPDL verifier")
		}
		outgoingMessage.LpdlDoublePrimeRound1Output, err = p.state.lpdlDoublePrimeVerifiers[id].Round1()
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 1 of LPDLP verifier")
		}
		r4o.Put(id, outgoingMessage)
	}

	p.round++
	return r4o.Freeze(), nil
}

// Round5 executes the fifth DKG round.
func (p *Participant[P, B, S]) Round5(input network.RoundMessages[*Round4P2P]) (output network.OutgoingUnicasts[*Round5P2P], err error) {
	// Validation
	if p.round != 5 {
		return nil, ErrRound.WithMessage("Running round %d but participant expected round %d", 5, p.round)
	}
	// 5. LP and LPDL continue
	r5o := hashmap.NewComparable[sharing.ID, *Round5P2P]()
	for id := range p.shard.AccessStructure().Shareholders().Iter() {
		if id == p.SharingID() {
			continue
		}
		message, exists := input.Get(id)
		if !exists {
			return nil, ErrFailed.WithMessage("no input from participant with sharing id %d", id)
		}

		outgoingMessage := new(Round5P2P)
		errGroup := errgroup.Group{}
		errGroup.Go(func() error {
			var err error
			outgoingMessage.LpRound2Output, err = p.state.lpProvers[id].Round2(message.LpRound1Output)
			if err != nil {
				return errs.Wrap(err).WithMessage("cannot run round 2 of LP prover")
			}
			return nil
		})
		errGroup.Go(func() error {
			var err error
			outgoingMessage.LpdlPrimeRound2Output, err = p.state.lpdlPrimeProvers[id].Round2(message.LpdlPrimeRound1Output)
			if err != nil {
				return errs.Wrap(err).WithMessage("cannot run round 2 of LPDL prover")
			}
			return nil
		})
		errGroup.Go(func() error {
			var err error
			outgoingMessage.LpdlDoublePrimeRound2Output, err = p.state.lpdlDoublePrimeProvers[id].Round2(message.LpdlDoublePrimeRound1Output)
			if err != nil {
				return errs.Wrap(err).WithMessage("cannot run round 2 of LPDL prover")
			}
			return nil
		})
		if err := errGroup.Wait(); err != nil {
			return nil, errs.Wrap(err).WithMessage("round 5")
		}
		r5o.Put(id, outgoingMessage)
	}

	p.round++
	return r5o.Freeze(), nil
}

// Round6 executes the sixth DKG round.
func (p *Participant[P, B, S]) Round6(input network.RoundMessages[*Round5P2P]) (output network.OutgoingUnicasts[*Round6P2P], err error) {
	// Validation
	if p.round != 6 {
		return nil, ErrRound.WithMessage("Running round %d but participant expected round %d", 6, p.round)
	}
	// 6. LP and LPDL continue
	r6o := hashmap.NewComparable[sharing.ID, *Round6P2P]()
	for id := range p.shard.AccessStructure().Shareholders().Iter() {
		if id == p.SharingID() {
			continue
		}
		message, exists := input.Get(id)
		if !exists {
			return nil, ErrFailed.WithMessage("no input from participant with sharing id %d", id)
		}

		outgoingMessage := new(Round6P2P)
		outgoingMessage.LpRound3Output, err = p.state.lpVerifiers[id].Round3(message.LpRound2Output)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 3 of LP verifier")
		}
		outgoingMessage.LpdlPrimeRound3Output, err = p.state.lpdlPrimeVerifiers[id].Round3(message.LpdlPrimeRound2Output)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 3 of LP verifier")
		}
		outgoingMessage.LpdlDoublePrimeRound3Output, err = p.state.lpdlDoublePrimeVerifiers[id].Round3(message.LpdlDoublePrimeRound2Output)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 3 of LP verifier")
		}
		r6o.Put(id, outgoingMessage)
	}

	p.round++
	return r6o.Freeze(), nil
}

// Round7 executes the seventh DKG round.
func (p *Participant[P, B, S]) Round7(input network.RoundMessages[*Round6P2P]) (output network.OutgoingUnicasts[*Round7P2P[P, B, S]], err error) {
	// Validation
	if p.round != 7 {
		return nil, ErrRound.WithMessage("Running round %d but participant expected round %d", 7, p.round)
	}
	// 7. LP and LPDL continue
	r7o := hashmap.NewComparable[sharing.ID, *Round7P2P[P, B, S]]()
	for id := range p.shard.AccessStructure().Shareholders().Iter() {
		if id == p.SharingID() {
			continue
		}
		message, exists := input.Get(id)
		if !exists {
			return nil, ErrFailed.WithMessage("no input from participant with sharing id %d", id)
		}

		outgoingMessage := new(Round7P2P[P, B, S])
		outgoingMessage.LpRound4Output, err = p.state.lpProvers[id].Round4(message.LpRound3Output)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 2 of LP prover")
		}
		outgoingMessage.LpdlPrimeRound4Output, err = p.state.lpdlPrimeProvers[id].Round4(message.LpdlPrimeRound3Output)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 2 of LP prover")
		}
		outgoingMessage.LpdlDoublePrimeRound4Output, err = p.state.lpdlDoublePrimeProvers[id].Round4(message.LpdlDoublePrimeRound3Output)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 2 of LP prover")
		}
		r7o.Put(id, outgoingMessage)
	}

	p.round++
	return r7o.Freeze(), nil
}

// Round8 executes the final DKG round.
func (p *Participant[P, B, S]) Round8(input network.RoundMessages[*Round7P2P[P, B, S]]) (*lindell17.Shard[P, B, S], error) {
	// Validation
	if p.round != 8 {
		return nil, ErrRound.WithMessage("Running round %d but participant expected round %d", 8, p.round)
	}
	for id := range p.shard.AccessStructure().Shareholders().Iter() {
		if id == p.SharingID() {
			continue
		}
		message, exists := input.Get(id)
		if !exists {
			return nil, ErrFailed.WithMessage("no input from participant with sharing id %d", id)
		}

		if err := p.state.lpVerifiers[id].Round5(message.LpRound4Output); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("failed to verify valid Paillier public-key")
		}
		if err := p.state.lpdlPrimeVerifiers[id].Round5(message.LpdlPrimeRound4Output); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("failed to verify encrypted dlog")
		}
		if err := p.state.lpdlDoublePrimeVerifiers[id].Round5(message.LpdlDoublePrimeRound4Output); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("failed to verify encrypted dlog")
		}
	}

	p.round++
	// 8. store encrypted x_j aka ckey_j (ckey_j = Enc(x_j) = Enc(3x'_j + x''_j)) and pk_j alongside share
	auxInfo, err := lindell17.NewAuxiliaryInfo(
		p.state.myPaillierSk,
		hashmap.NewComparableFromNativeLike(p.state.theirPaillierPublicKeys).Freeze(),
		hashmap.NewComparableFromNativeLike(p.state.theirPaillierEncryptedShares).Freeze(),
	)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create auxiliary info")
	}
	shard, err := lindell17.NewShard(p.shard, auxInfo)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create lindell17 shard")
	}
	return shard, nil
}

func dlogProve[
	P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S],
](c *Participant[P, B, S], bigQ, bigQTwin P, x S, tape transcripts.Transcript) (compiler.NIZKPoKProof, error) {
	proverIDBytes := binary.BigEndian.AppendUint64(nil, uint64(c.SharingID()))
	tape.AppendBytes(transcriptDLogSLabel, c.quorumBytes...)
	tape.AppendBytes(proverLabel, proverIDBytes)
	tape.AppendBytes(bigQTwinLabel, bigQTwin.ToCompressed())
	prover, err := c.state.niDlogScheme.NewProver(c.sid, tape)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create dlog prover")
	}
	statement := &schnorrpok.Statement[P, S]{
		X: bigQ,
	}
	witness := &schnorrpok.Witness[S]{
		W: x,
	}
	proof, err := prover.Prove(statement, witness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create dlog proof")
	}
	return proof, nil
}

func dlogVerify[
	P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S],
](c *Participant[P, B, S], proverID sharing.ID, proof compiler.NIZKPoKProof, bigQ, bigQTwin P, tape transcripts.Transcript) error {
	proverIDBytes := binary.BigEndian.AppendUint64(nil, uint64(proverID))
	tape.AppendBytes(transcriptDLogSLabel, c.quorumBytes...)
	tape.AppendBytes(proverLabel, proverIDBytes)
	tape.AppendBytes(bigQTwinLabel, bigQTwin.ToCompressed())
	verifier, err := c.state.niDlogScheme.NewVerifier(c.sid, tape)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create dlog verifier")
	}
	statement := &schnorrpok.Statement[P, S]{
		X: bigQ,
	}
	if err := verifier.Verify(statement, proof); err != nil {
		return errs.Wrap(err).WithMessage("cannot verify dlog proof for participant %d", proverID)
	}
	return nil
}
