package dkg

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	dlog "github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/fischlin"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/lp"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/lpdl"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

type Round1Broadcast struct {
	BigQCommitment commitments.Commitment

	_ types.Incomparable
}

type Round2Broadcast struct {
	BigQWitness          commitments.Witness
	BigQPrime            curves.Point
	BigQPrimeProof       *dlog.Proof
	BigQDoublePrime      curves.Point
	BigQDoublePrimeProof *dlog.Proof

	_ types.Incomparable
}

type Round3Broadcast struct {
	CKeyPrime         *paillier.CipherText
	CKeyDoublePrime   *paillier.CipherText
	PaillierPublicKey *paillier.PublicKey

	_ types.Incomparable
}

type Round4P2P struct {
	LpRound1Output              *lp.Round1Output
	LpdlPrimeRound1Output       *lpdl.Round1Output
	LpdlDoublePrimeRound1Output *lpdl.Round1Output

	_ types.Incomparable
}

type Round5P2P struct {
	LpRound2Output              *lp.Round2Output
	LpdlPrimeRound2Output       *lpdl.Round2Output
	LpdlDoublePrimeRound2Output *lpdl.Round2Output

	_ types.Incomparable
}

type Round6P2P struct {
	LpRound3Output              *lp.Round3Output
	LpdlPrimeRound3Output       *lpdl.Round3Output
	LpdlDoublePrimeRound3Output *lpdl.Round3Output

	_ types.Incomparable
}

type Round7P2P struct {
	LpRound4Output              *lp.Round4Output
	LpdlPrimeRound4Output       *lpdl.Round4Output
	LpdlDoublePrimeRound4Output *lpdl.Round4Output

	_ types.Incomparable
}

func (p *Participant) Round1() (output *Round1Broadcast, err error) {
	if p.round != 1 {
		return nil, errs.NewInvalidRound("%d != 1", p.round)
	}

	// 1.i. choose randomly x' and x'' such that x = 3x' + x'' and both x' and x'' are in (q/3, 2q/3) range
	xPrime, xDoublePrime, err := lindell17.DecomposeInQThirdsDeterministically(p.mySigningKeyShare.Share, p.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot split share")
	}

	// 1.ii. calculate Q' and Q''
	bigQPrime := p.cohortConfig.CipherSuite.Curve.ScalarBaseMult(xPrime)
	bigQDoublePrime := p.cohortConfig.CipherSuite.Curve.ScalarBaseMult(xDoublePrime)

	// 1.iii. calculates commitments Qcom to Q' and Q''
	bigQCommitment, bigQWitness, err := commit(p.prng, bigQPrime, bigQDoublePrime, p.sessionId, p.myAuthKey.PublicKey())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to (Q', Q'')")
	}

	p.state.myXPrime = xPrime
	p.state.myXDoublePrime = xDoublePrime
	p.state.myBigQPrime = bigQPrime
	p.state.myBigQDoublePrime = bigQDoublePrime
	p.state.myBigQWitness = bigQWitness

	// some paranoid checks
	if !bigQPrime.Add(bigQPrime).Add(bigQPrime).Add(bigQDoublePrime).Equal(p.publicKeyShares.SharesMap[p.myAuthKey.Hash()]) {
		return nil, errs.NewFailed("something went really wrong")
	}

	// 1.iv. broadcast commitments
	p.round++
	return &Round1Broadcast{
		BigQCommitment: bigQCommitment,
	}, nil
}

func (p *Participant) Round2(input map[types.IdentityHash]*Round1Broadcast) (output *Round2Broadcast, err error) {
	if p.round != 2 {
		return nil, errs.NewInvalidRound("%d != 2", p.round)
	}

	// 2. store commitments
	p.state.theirBigQCommitment = make(map[types.IdentityHash]commitments.Commitment)
	for _, identity := range p.cohortConfig.Participants.Iter() {
		if types.Equals(identity, p.myAuthKey) {
			continue
		}
		idHash := identity.Hash()
		if input[idHash] == nil {
			return nil, errs.NewFailed("no input from participant with sharing id %d", p.idKeyToSharingId[idHash])
		}
		p.state.theirBigQCommitment[idHash] = input[idHash].BigQCommitment
	}

	// 2.i. calculate proofs of dlog knowledge of Q' and Q'' (Qdl' and Qdl'' respectively)
	dlogTranscript := p.transcript.Clone()
	bigQPrimeProof, err := dlogProve(p.state.myXPrime, p.state.myBigQPrime, p.state.myBigQDoublePrime, p.sessionId, dlogTranscript, p.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog proof of Q'")
	}
	bigQDoublePrimeProof, err := dlogProve(p.state.myXDoublePrime, p.state.myBigQDoublePrime, p.state.myBigQPrime, p.sessionId, dlogTranscript, p.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog proof of Q''")
	}

	// 2.ii. send opening of Qcom revealing Q', Q'' and broadcast proofs of dlog knowledge of these (Qdl', Qdl'' respectively)
	p.round++
	return &Round2Broadcast{
		BigQWitness:          p.state.myBigQWitness,
		BigQPrime:            p.state.myBigQPrime,
		BigQPrimeProof:       bigQPrimeProof,
		BigQDoublePrime:      p.state.myBigQDoublePrime,
		BigQDoublePrimeProof: bigQDoublePrimeProof,
	}, nil
}

func (p *Participant) Round3(input map[types.IdentityHash]*Round2Broadcast) (output *Round3Broadcast, err error) {
	if p.round != 3 {
		return nil, errs.NewInvalidRound("%d != 3", p.round)
	}

	p.state.theirBigQPrime = make(map[types.IdentityHash]curves.Point)
	p.state.theirBigQDoublePrime = make(map[types.IdentityHash]curves.Point)

	// 3.i. verify proofs of dlog knowledge of Qdl'_j Qdl''_j
	for _, identity := range p.cohortConfig.Participants.Iter() {
		if types.Equals(identity, p.myAuthKey) {
			continue
		}
		idHash := identity.Hash()
		if input[idHash] == nil {
			return nil, errs.NewFailed("no input from participant with sharing id %d", p.idKeyToSharingId[idHash])
		}

		// 3.i. open commitments
		if err := openCommitment(p.state.theirBigQCommitment[idHash], input[idHash].BigQWitness, input[idHash].BigQPrime, input[idHash].BigQDoublePrime, p.sessionId, identity.PublicKey()); err != nil {
			return nil, errs.WrapFailed(err, "cannot open (Q', Q'') commitment")
		}

		dlogTranscript := p.transcript.Clone()
		if err := dlogVerify(input[idHash].BigQPrimeProof, input[idHash].BigQPrime, input[idHash].BigQDoublePrime, p.sessionId, dlogTranscript); err != nil {
			return nil, errs.WrapFailed(err, "cannot verify dlog proof of Q'")
		}
		if err := dlogVerify(input[idHash].BigQDoublePrimeProof, input[idHash].BigQDoublePrime, input[idHash].BigQPrime, p.sessionId, dlogTranscript); err != nil {
			return nil, errs.WrapFailed(err, "cannot verify dlog proof of Q''")
		}
		p.state.theirBigQPrime[idHash] = input[idHash].BigQPrime
		p.state.theirBigQDoublePrime[idHash] = input[idHash].BigQDoublePrime

		// 3.ii. verify that y_j == 3Q'_j + Q''_j and abort if not
		theirBigQ := p.state.theirBigQPrime[idHash].Mul(p.cohortConfig.CipherSuite.Curve.Scalar().New(3)).Add(p.state.theirBigQDoublePrime[idHash])
		if !theirBigQ.Equal(p.publicKeyShares.SharesMap[idHash]) {
			return nil, errs.NewIdentifiableAbort(idHash, "invalid Q' or Q''")
		}
	}

	// 3.iii. generate a Paillier key pair
	p.state.myPaillierPk, p.state.myPaillierSk, err = paillier.NewKeys(lp.PaillierBitSize)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate Paillier keys")
	}
	cKeyPrime, rPrime, err := p.state.myPaillierPk.Encrypt(p.state.myXPrime.Nat())

	// 3.iv. calculate ckey' = Enc(x'; r') and ckey'' = Enc(x''; r'')
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt x'")
	}
	cKeyDoublePrime, rDoublePrime, err := p.state.myPaillierPk.Encrypt(p.state.myXDoublePrime.Nat())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt x''")
	}
	p.state.myRPrime = rPrime
	p.state.myRDoublePrime = rDoublePrime

	// 3.vi. prove pairwise iz ZK that pk was generated correctly (LP)
	//       and that (ckey', ckey'') encrypt dlogs of (Q', Q'') (LPDL)
	p.state.lpProvers = make(map[types.IdentityHash]*lp.Prover)
	p.state.lpdlPrimeProvers = make(map[types.IdentityHash]*lpdl.Prover)
	p.state.lpdlDoublePrimeProvers = make(map[types.IdentityHash]*lpdl.Prover)
	for _, identity := range p.cohortConfig.Participants.Iter() {
		if types.Equals(identity, p.myAuthKey) {
			continue
		}
		paillierProofsTranscript := p.transcript.Clone()
		idHash := identity.Hash()
		p.state.lpProvers[idHash], err = lp.NewProver(128, p.state.myPaillierSk, p.sessionId, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create LP prover")
		}
		p.state.lpdlPrimeProvers[idHash], err = lpdl.NewProver(p.sessionId, p.state.myPaillierSk, p.state.myXPrime, p.state.myRPrime, p.sessionId, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create PDL prover")
		}
		p.state.lpdlDoublePrimeProvers[idHash], err = lpdl.NewProver(p.sessionId, p.state.myPaillierSk, p.state.myXDoublePrime, p.state.myRDoublePrime, p.sessionId, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create PDL prover")
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

func (p *Participant) Round4(input map[types.IdentityHash]*Round3Broadcast) (output map[types.IdentityHash]*Round4P2P, err error) {
	if p.round != 4 {
		return nil, errs.NewInvalidRound("%d != 4", p.round)
	}

	p.state.theirPaillierPublicKeys = make(map[types.IdentityHash]*paillier.PublicKey)
	p.state.theirPaillierEncryptedShares = make(map[types.IdentityHash]*paillier.CipherText)

	p.state.lpVerifiers = make(map[types.IdentityHash]*lp.Verifier)
	p.state.lpdlPrimeVerifiers = make(map[types.IdentityHash]*lpdl.Verifier)
	p.state.lpdlDoublePrimeVerifiers = make(map[types.IdentityHash]*lpdl.Verifier)

	round4Outputs := make(map[types.IdentityHash]*Round4P2P)
	for _, identity := range p.cohortConfig.Participants.Iter() {
		if types.Equals(identity, p.myAuthKey) {
			continue
		}
		idHash := identity.Hash()
		if input[idHash] == nil {
			return nil, errs.NewFailed("no input from participant with sharing id %d", p.idKeyToSharingId[idHash])
		}

		p.state.theirPaillierPublicKeys[idHash] = input[idHash].PaillierPublicKey
		theirCKeyPrime := input[idHash].CKeyPrime
		theirCKeyDoublePrime := input[idHash].CKeyDoublePrime

		// 4.i. calculate and store ckey_j = 3 (*) ckey'_j (+) ckey''_j
		cKey1, err := p.state.theirPaillierPublicKeys[idHash].Add(theirCKeyPrime, theirCKeyPrime)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot add ciphertexts")
		}
		cKey2, err := p.state.theirPaillierPublicKeys[idHash].Add(cKey1, theirCKeyPrime)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot add ciphertexts")
		}
		p.state.theirPaillierEncryptedShares[idHash], err = p.state.theirPaillierPublicKeys[idHash].Add(cKey2, theirCKeyDoublePrime)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot add ciphertexts")
		}

		// 4.ii. LP and LPDL continue
		paillierProofsTranscript := p.transcript.Clone()
		p.state.lpVerifiers[idHash], err = lp.NewVerifier(128, p.state.theirPaillierPublicKeys[idHash], p.sessionId, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create P verifier")
		}
		p.state.lpdlPrimeVerifiers[idHash], err = lpdl.NewVerifier(p.sessionId, p.state.theirPaillierPublicKeys[idHash], p.state.theirBigQPrime[idHash], theirCKeyPrime, p.sessionId, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create PDL verifier")
		}
		p.state.lpdlDoublePrimeVerifiers[idHash], err = lpdl.NewVerifier(p.sessionId, p.state.theirPaillierPublicKeys[idHash], p.state.theirBigQDoublePrime[idHash], theirCKeyDoublePrime, p.sessionId, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create PDL verifier")
		}

		round4Outputs[idHash] = new(Round4P2P)
		round4Outputs[idHash].LpRound1Output, err = p.state.lpVerifiers[idHash].Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 1 of LP verifier")
		}
		round4Outputs[idHash].LpdlPrimeRound1Output, err = p.state.lpdlPrimeVerifiers[idHash].Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 1 of LPDL verifier")
		}
		round4Outputs[idHash].LpdlDoublePrimeRound1Output, err = p.state.lpdlDoublePrimeVerifiers[idHash].Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 1 of LPDLP verifier")
		}
	}

	p.round++
	return round4Outputs, nil
}

func (p *Participant) Round5(input map[types.IdentityHash]*Round4P2P) (output map[types.IdentityHash]*Round5P2P, err error) {
	if p.round != 5 {
		return nil, errs.NewInvalidRound("%d != 5", p.round)
	}

	// 5. LP and LPDL continue
	round5Outputs := make(map[types.IdentityHash]*Round5P2P)
	for _, identity := range p.cohortConfig.Participants.Iter() {
		if types.Equals(identity, p.myAuthKey) {
			continue
		}
		idHash := identity.Hash()
		if input[idHash] == nil {
			return nil, errs.NewFailed("no input from participant with sharing id %d", p.idKeyToSharingId[idHash])
		}

		round5Outputs[idHash] = new(Round5P2P)
		round5Outputs[idHash].LpRound2Output, err = p.state.lpProvers[idHash].Round2(input[idHash].LpRound1Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LP prover")
		}
		round5Outputs[idHash].LpdlPrimeRound2Output, err = p.state.lpdlPrimeProvers[idHash].Round2(input[idHash].LpdlPrimeRound1Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LPDL prover")
		}
		round5Outputs[idHash].LpdlDoublePrimeRound2Output, err = p.state.lpdlDoublePrimeProvers[idHash].Round2(input[idHash].LpdlDoublePrimeRound1Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LPDL prover")
		}
	}

	p.round++
	return round5Outputs, nil
}

func (p *Participant) Round6(input map[types.IdentityHash]*Round5P2P) (output map[types.IdentityHash]*Round6P2P, err error) {
	if p.round != 6 {
		return nil, errs.NewInvalidRound("%d != 6", p.round)
	}

	// 6. LP and LPDL continue
	round6Outputs := make(map[types.IdentityHash]*Round6P2P)
	for _, identity := range p.cohortConfig.Participants.Iter() {
		if types.Equals(identity, p.myAuthKey) {
			continue
		}
		idHash := identity.Hash()
		if input[idHash] == nil {
			return nil, errs.NewFailed("no input from participant with sharing id %d", p.idKeyToSharingId[idHash])
		}

		round6Outputs[idHash] = new(Round6P2P)
		round6Outputs[idHash].LpRound3Output, err = p.state.lpVerifiers[idHash].Round3(input[idHash].LpRound2Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 3 of LP verifier")
		}
		round6Outputs[idHash].LpdlPrimeRound3Output, err = p.state.lpdlPrimeVerifiers[idHash].Round3(input[idHash].LpdlPrimeRound2Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 3 of LP verifier")
		}
		round6Outputs[idHash].LpdlDoublePrimeRound3Output, err = p.state.lpdlDoublePrimeVerifiers[idHash].Round3(input[idHash].LpdlDoublePrimeRound2Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 3 of LP verifier")
		}
	}

	p.round++
	return round6Outputs, nil
}

func (p *Participant) Round7(input map[types.IdentityHash]*Round6P2P) (output map[types.IdentityHash]*Round7P2P, err error) {
	if p.round != 7 {
		return nil, errs.NewInvalidRound("%d != 7", p.round)
	}

	// 7. LP and LPDL continue
	round7Outputs := make(map[types.IdentityHash]*Round7P2P)
	for _, identity := range p.cohortConfig.Participants.Iter() {
		if types.Equals(identity, p.myAuthKey) {
			continue
		}
		idHash := identity.Hash()
		if input[idHash] == nil {
			return nil, errs.NewFailed("no input from participant with sharing id %d", p.idKeyToSharingId[idHash])
		}

		round7Outputs[idHash] = new(Round7P2P)
		round7Outputs[idHash].LpRound4Output, err = p.state.lpProvers[idHash].Round4(input[idHash].LpRound3Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LP prover")
		}
		round7Outputs[idHash].LpdlPrimeRound4Output, err = p.state.lpdlPrimeProvers[idHash].Round4(input[idHash].LpdlPrimeRound3Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LP prover")
		}
		round7Outputs[idHash].LpdlDoublePrimeRound4Output, err = p.state.lpdlDoublePrimeProvers[idHash].Round4(input[idHash].LpdlDoublePrimeRound3Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LP prover")
		}
	}

	p.round++
	return round7Outputs, nil
}

func (p *Participant) Round8(input map[types.IdentityHash]*Round7P2P) (shard *lindell17.Shard, err error) {
	if p.round != 8 {
		return nil, errs.NewInvalidRound("%d != 8", p.round)
	}

	for _, identity := range p.cohortConfig.Participants.Iter() {
		if types.Equals(identity, p.myAuthKey) {
			continue
		}
		idHash := identity.Hash()
		if input[idHash] == nil {
			return nil, errs.NewFailed("no input from participant with sharing id %d", p.idKeyToSharingId[idHash])
		}

		err = p.state.lpVerifiers[idHash].Round5(input[idHash].LpRound4Output)
		if err != nil {
			return nil, errs.WrapIdentifiableAbort(err, idHash, "failed to verify valid Paillier public-key")
		}
		err = p.state.lpdlPrimeVerifiers[idHash].Round5(input[idHash].LpdlPrimeRound4Output)
		if err != nil {
			return nil, errs.WrapIdentifiableAbort(err, idHash, "failed to verify encrypted dlog")
		}
		err = p.state.lpdlDoublePrimeVerifiers[idHash].Round5(input[idHash].LpdlDoublePrimeRound4Output)
		if err != nil {
			return nil, errs.WrapIdentifiableAbort(err, idHash, "failed to verify encrypted dlog")
		}
	}

	p.round++
	// 8. store encrypted x_j aka ckey_j (ckey_j = Enc(x_j) = Enc(3x'_j + x''_j)) and pk_j alongside share
	return &lindell17.Shard{
		SigningKeyShare:         p.mySigningKeyShare,
		PaillierSecretKey:       p.state.myPaillierSk,
		PaillierPublicKeys:      p.state.theirPaillierPublicKeys,
		PaillierEncryptedShares: p.state.theirPaillierEncryptedShares,
	}, nil
}

func commit(prng io.Reader, bigQPrime, bigQDoublePrime curves.Point, sid []byte, pid curves.Point) (commitment commitments.Commitment, witness commitments.Witness, err error) {
	return commitments.Commit(
		sid,
		prng,
		bigQPrime.ToAffineCompressed(),
		bigQDoublePrime.ToAffineCompressed(),
		pid.ToAffineCompressed(),
	)
}

func openCommitment(commitment commitments.Commitment, witness commitments.Witness, bigQPrime, bigQDoublePrime curves.Point, sid []byte, pid curves.Point) (err error) {
	return commitments.Open(sid, commitment, witness, bigQPrime.ToAffineCompressed(), bigQDoublePrime.ToAffineCompressed(), pid.ToAffineCompressed())
}

func dlogProve(x curves.Scalar, bigQ, bigQTwin curves.Point, sid []byte, transcript transcripts.Transcript, prng io.Reader) (proof *dlog.Proof, err error) {
	transcript.AppendPoints("bigQTwin", bigQTwin)

	curve := bigQ.Curve()
	generator := curve.Generator()

	prover, err := dlog.NewProver(generator, sid, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog prover")
	}

	proof, statement, err := prover.Prove(x)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot prove dlog")
	}
	if !bigQ.Equal(statement) {
		return nil, errs.NewFailed("invalid statement")
	}

	return proof, nil
}

func dlogVerify(proof *dlog.Proof, bigQ, bigQTwin curves.Point, sid []byte, transcript transcripts.Transcript) (err error) {
	transcript.AppendPoints("bigQTwin", bigQTwin)

	curve := bigQ.Curve()
	generator := curve.Generator()

	return dlog.Verify(generator, bigQ, proof, sid)
}
