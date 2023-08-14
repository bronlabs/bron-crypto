package dkg

import (
	"crypto/sha256"

	"github.com/copperexchange/knox-primitives/pkg/datastructures/types"

	"github.com/copperexchange/knox-primitives/pkg/commitments"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/paillier"
	"github.com/copperexchange/knox-primitives/pkg/proofs/paillier/lp"
	"github.com/copperexchange/knox-primitives/pkg/proofs/paillier/lpdl"
	dlog "github.com/copperexchange/knox-primitives/pkg/proofs/schnorr"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
)

const (
	paillierBitSize = 1024
)

var (
	commitmentHashFunc = sha256.New
)

type Round1Broadcast struct {
	BigQCommitment commitments.Commitment
}

type Round2Broadcast struct {
	BigQWitness          commitments.Witness
	BigQPrime            curves.Point
	BigQPrimeProof       *dlog.Proof
	BigQDoublePrime      curves.Point
	BigQDoublePrimeProof *dlog.Proof
}

type Round3Broadcast struct {
	CKeyPrime         paillier.CipherText
	CKeyDoublePrime   paillier.CipherText
	PaillierPublicKey *paillier.PublicKey
}

type Round4P2P struct {
	LpRound1Output              *lp.Round1Output
	LpdlPrimeRound1Output       *lpdl.Round1Output
	LpdlDoublePrimeRound1Output *lpdl.Round1Output
}

type Round5P2P struct {
	LpRound2Output              *lp.Round2Output
	LpdlPrimeRound2Output       *lpdl.Round2Output
	LpdlDoublePrimeRound2Output *lpdl.Round2Output
}

type Round6P2P struct {
	LpRound3Output              *lp.Round3Output
	LpdlPrimeRound3Output       *lpdl.Round3Output
	LpdlDoublePrimeRound3Output *lpdl.Round3Output
}

type Round7P2P struct {
	LpRound4Output              *lp.Round4Output
	LpdlPrimeRound4Output       *lpdl.Round4Output
	LpdlDoublePrimeRound4Output *lpdl.Round4Output
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
	bigQCommitment, bigQWitness, err := commit(bigQPrime, bigQDoublePrime, p.sessionId, p.myIdentityKey.PublicKey())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to (Q', Q'')")
	}

	p.state.myXPrime = xPrime
	p.state.myXDoublePrime = xDoublePrime
	p.state.myBigQPrime = bigQPrime
	p.state.myBigQDoublePrime = bigQDoublePrime
	p.state.myBigQWitness = bigQWitness

	// some paranoid checks
	if !bigQPrime.Add(bigQPrime).Add(bigQPrime).Add(bigQDoublePrime).Equal(p.publicKeyShares.SharesMap[p.myIdentityKey]) {
		return nil, errs.NewFailed("something went really wrong")
	}

	// 1.iv. broadcast commitments
	p.round++
	return &Round1Broadcast{
		bigQCommitment,
	}, nil
}

func (p *Participant) Round2(input map[integration.IdentityKey]*Round1Broadcast) (output *Round2Broadcast, err error) {
	if p.round != 2 {
		return nil, errs.NewInvalidRound("%d != 2", p.round)
	}

	// 2. store commitments
	p.state.theirBigQCommitment = make(map[integration.IdentityKey]commitments.Commitment)
	for _, identity := range p.cohortConfig.Participants {
		if types.Equals(identity, p.myIdentityKey) {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with sharing id %d", p.idKeyToSharingId[identity])
		}
		p.state.theirBigQCommitment[identity] = input[identity].BigQCommitment
	}

	// 2.i. calculate proofs of dlog knowledge of Q' and Q'' (Qdl' and Qdl'' respectively)
	dlogTranscript := p.transcript.Clone()
	bigQPrimeProof, err := dlogProve(p.state.myXPrime, p.state.myBigQPrime, p.state.myBigQDoublePrime, p.sessionId, dlogTranscript)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog proof of Q'")
	}
	bigQDoublePrimeProof, err := dlogProve(p.state.myXDoublePrime, p.state.myBigQDoublePrime, p.state.myBigQPrime, p.sessionId, dlogTranscript)
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

func (p *Participant) Round3(input map[integration.IdentityKey]*Round2Broadcast) (output *Round3Broadcast, err error) {
	if p.round != 3 {
		return nil, errs.NewInvalidRound("%d != 3", p.round)
	}

	p.state.theirBigQPrime = make(map[integration.IdentityKey]curves.Point)
	p.state.theirBigQDoublePrime = make(map[integration.IdentityKey]curves.Point)

	// 3.i. verify proofs of dlog knowledge of Qdl'_j Qdl''_j
	for _, identity := range p.cohortConfig.Participants {
		if types.Equals(identity, p.myIdentityKey) {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with sharing id %d", p.idKeyToSharingId[identity])
		}

		// 3.i. open commitments
		if err := openCommitment(p.state.theirBigQCommitment[identity], input[identity].BigQWitness, input[identity].BigQPrime, input[identity].BigQDoublePrime, p.sessionId, identity.PublicKey()); err != nil {
			return nil, errs.WrapFailed(err, "cannot open (Q', Q'') commitment")
		}

		dlogTranscript := p.transcript.Clone()
		if err := dlogVerify(input[identity].BigQPrimeProof, input[identity].BigQPrime, input[identity].BigQDoublePrime, p.sessionId, dlogTranscript); err != nil {
			return nil, errs.WrapFailed(err, "cannot verify dlog proof of Q'")
		}
		if err := dlogVerify(input[identity].BigQDoublePrimeProof, input[identity].BigQDoublePrime, input[identity].BigQPrime, p.sessionId, dlogTranscript); err != nil {
			return nil, errs.WrapFailed(err, "cannot verify dlog proof of Q''")
		}
		p.state.theirBigQPrime[identity] = input[identity].BigQPrime
		p.state.theirBigQDoublePrime[identity] = input[identity].BigQDoublePrime

		// 3.ii. verify that y_j == 3Q'_j + Q''_j and abort if not
		theirBigQ := p.state.theirBigQPrime[identity].Mul(p.cohortConfig.CipherSuite.Curve.Scalar().New(3)).Add(p.state.theirBigQDoublePrime[identity])
		if !theirBigQ.Equal(p.publicKeyShares.SharesMap[identity]) {
			return nil, errs.NewIdentifiableAbort("invalid Q' or Q''")
		}
	}

	// 3.iii. generate a Paillier key pair
	p.state.myPaillierPk, p.state.myPaillierSk, err = paillier.NewKeys(paillierBitSize)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate Paillier keys")
	}
	cKeyPrime, rPrime, err := p.state.myPaillierPk.Encrypt(p.state.myXPrime.BigInt())

	// 3.iv. calculate ckey' = Enc(x'; r') and ckey'' = Enc(x''; r'')
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt x'")
	}
	cKeyDoublePrime, rDoublePrime, err := p.state.myPaillierPk.Encrypt(p.state.myXDoublePrime.BigInt())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt x''")
	}
	p.state.myRPrime = rPrime
	p.state.myRDoublePrime = rDoublePrime

	// 3.vi. prove pairwise iz ZK that pk was generated correctly (LP)
	//       and that (ckey', ckey'') encrypt dlogs of (Q', Q'') (LPDL)
	p.state.lpProvers = make(map[integration.IdentityKey]*lp.Prover)
	p.state.lpdlPrimeProvers = make(map[integration.IdentityKey]*lpdl.Prover)
	p.state.lpdlDoublePrimeProvers = make(map[integration.IdentityKey]*lpdl.Prover)
	for _, identity := range p.cohortConfig.Participants {
		if types.Equals(identity, p.myIdentityKey) {
			continue
		}
		paillierProofsTranscript := p.transcript.Clone()
		p.state.lpProvers[identity], err = lp.NewProver(128, p.state.myPaillierSk, p.sessionId, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create LP prover")
		}
		p.state.lpdlPrimeProvers[identity], err = lpdl.NewProver(p.sessionId, p.state.myPaillierSk, p.state.myXPrime, p.state.myRPrime, p.sessionId, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create PDL prover")
		}
		p.state.lpdlDoublePrimeProvers[identity], err = lpdl.NewProver(p.sessionId, p.state.myPaillierSk, p.state.myXDoublePrime, p.state.myRDoublePrime, p.sessionId, paillierProofsTranscript, p.prng)
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

func (p *Participant) Round4(input map[integration.IdentityKey]*Round3Broadcast) (output map[integration.IdentityKey]*Round4P2P, err error) {
	if p.round != 4 {
		return nil, errs.NewInvalidRound("%d != 4", p.round)
	}

	p.state.theirPaillierPublicKeys = make(map[integration.IdentityKey]*paillier.PublicKey)
	p.state.theirPaillierEncryptedShares = make(map[integration.IdentityKey]paillier.CipherText)

	p.state.lpVerifiers = make(map[integration.IdentityKey]*lp.Verifier)
	p.state.lpdlPrimeVerifiers = make(map[integration.IdentityKey]*lpdl.Verifier)
	p.state.lpdlDoublePrimeVerifiers = make(map[integration.IdentityKey]*lpdl.Verifier)

	round4Outputs := make(map[integration.IdentityKey]*Round4P2P)
	for _, identity := range p.cohortConfig.Participants {
		if types.Equals(identity, p.myIdentityKey) {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with sharing id %d", p.idKeyToSharingId[identity])
		}

		p.state.theirPaillierPublicKeys[identity] = input[identity].PaillierPublicKey
		theirCKeyPrime := input[identity].CKeyPrime
		theirCKeyDoublePrime := input[identity].CKeyDoublePrime

		// 4.i. calculate and store ckey_j = 3 (*) ckey'_j (+) ckey''_j
		cKey1, err := p.state.theirPaillierPublicKeys[identity].Add(theirCKeyPrime, theirCKeyPrime)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot add ciphertexts")
		}
		cKey2, err := p.state.theirPaillierPublicKeys[identity].Add(cKey1, theirCKeyPrime)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot add ciphertexts")
		}
		p.state.theirPaillierEncryptedShares[identity], err = p.state.theirPaillierPublicKeys[identity].Add(cKey2, theirCKeyDoublePrime)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot add ciphertexts")
		}

		// 4.ii. LP and LPDL continue
		paillierProofsTranscript := p.transcript.Clone()
		p.state.lpVerifiers[identity], err = lp.NewVerifier(128, p.state.theirPaillierPublicKeys[identity], p.sessionId, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create P verifier")
		}
		p.state.lpdlPrimeVerifiers[identity], err = lpdl.NewVerifier(p.sessionId, p.state.theirPaillierPublicKeys[identity], p.state.theirBigQPrime[identity], theirCKeyPrime, p.sessionId, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create PDL verifier")
		}
		p.state.lpdlDoublePrimeVerifiers[identity], err = lpdl.NewVerifier(p.sessionId, p.state.theirPaillierPublicKeys[identity], p.state.theirBigQDoublePrime[identity], theirCKeyDoublePrime, p.sessionId, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create PDL verifier")
		}

		round4Outputs[identity] = new(Round4P2P)
		round4Outputs[identity].LpRound1Output, err = p.state.lpVerifiers[identity].Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 1 of LP verifier")
		}
		round4Outputs[identity].LpdlPrimeRound1Output, err = p.state.lpdlPrimeVerifiers[identity].Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 1 of LP verifier")
		}
		round4Outputs[identity].LpdlDoublePrimeRound1Output, err = p.state.lpdlDoublePrimeVerifiers[identity].Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 1 of LP verifier")
		}
	}

	p.round++
	return round4Outputs, nil
}

func (p *Participant) Round5(input map[integration.IdentityKey]*Round4P2P) (output map[integration.IdentityKey]*Round5P2P, err error) {
	if p.round != 5 {
		return nil, errs.NewInvalidRound("%d != 5", p.round)
	}

	// 5. LP and LPDL continue
	round5Outputs := make(map[integration.IdentityKey]*Round5P2P)
	for _, identity := range p.cohortConfig.Participants {
		if types.Equals(identity, p.myIdentityKey) {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with sharing id %d", p.idKeyToSharingId[identity])
		}

		round5Outputs[identity] = new(Round5P2P)
		round5Outputs[identity].LpRound2Output, err = p.state.lpProvers[identity].Round2(input[identity].LpRound1Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LP prover")
		}
		round5Outputs[identity].LpdlPrimeRound2Output, err = p.state.lpdlPrimeProvers[identity].Round2(input[identity].LpdlPrimeRound1Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LPDL prover")
		}
		round5Outputs[identity].LpdlDoublePrimeRound2Output, err = p.state.lpdlDoublePrimeProvers[identity].Round2(input[identity].LpdlDoublePrimeRound1Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LPDL prover")
		}
	}

	p.round++
	return round5Outputs, nil
}

func (p *Participant) Round6(input map[integration.IdentityKey]*Round5P2P) (output map[integration.IdentityKey]*Round6P2P, err error) {
	if p.round != 6 {
		return nil, errs.NewInvalidRound("%d != 6", p.round)
	}

	// 6. LP and LPDL continue
	round6Outputs := make(map[integration.IdentityKey]*Round6P2P)
	for _, identity := range p.cohortConfig.Participants {
		if types.Equals(identity, p.myIdentityKey) {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with sharing id %d", p.idKeyToSharingId[identity])
		}

		round6Outputs[identity] = new(Round6P2P)
		round6Outputs[identity].LpRound3Output, err = p.state.lpVerifiers[identity].Round3(input[identity].LpRound2Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 3 of LP verifier")
		}
		round6Outputs[identity].LpdlPrimeRound3Output, err = p.state.lpdlPrimeVerifiers[identity].Round3(input[identity].LpdlPrimeRound2Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 3 of LP verifier")
		}
		round6Outputs[identity].LpdlDoublePrimeRound3Output, err = p.state.lpdlDoublePrimeVerifiers[identity].Round3(input[identity].LpdlDoublePrimeRound2Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 3 of LP verifier")
		}
	}

	p.round++
	return round6Outputs, nil
}

func (p *Participant) Round7(input map[integration.IdentityKey]*Round6P2P) (output map[integration.IdentityKey]*Round7P2P, err error) {
	if p.round != 7 {
		return nil, errs.NewInvalidRound("%d != 7", p.round)
	}

	// 7. LP and LPDL continue
	round7Outputs := make(map[integration.IdentityKey]*Round7P2P)
	for _, identity := range p.cohortConfig.Participants {
		if types.Equals(identity, p.myIdentityKey) {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with sharing id %d", p.idKeyToSharingId[identity])
		}

		round7Outputs[identity] = new(Round7P2P)
		round7Outputs[identity].LpRound4Output, err = p.state.lpProvers[identity].Round4(input[identity].LpRound3Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LP prover")
		}
		round7Outputs[identity].LpdlPrimeRound4Output, err = p.state.lpdlPrimeProvers[identity].Round4(input[identity].LpdlPrimeRound3Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LP prover")
		}
		round7Outputs[identity].LpdlDoublePrimeRound4Output, err = p.state.lpdlDoublePrimeProvers[identity].Round4(input[identity].LpdlDoublePrimeRound3Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LP prover")
		}
	}

	p.round++
	return round7Outputs, nil
}

func (p *Participant) Round8(input map[integration.IdentityKey]*Round7P2P) (shard *lindell17.Shard, err error) {
	if p.round != 8 {
		return nil, errs.NewInvalidRound("%d != 8", p.round)
	}

	for _, identity := range p.cohortConfig.Participants {
		if types.Equals(identity, p.myIdentityKey) {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with sharing id %d", p.idKeyToSharingId[identity])
		}

		err = p.state.lpVerifiers[identity].Round5(input[identity].LpRound4Output)
		if err != nil {
			return nil, errs.WrapIdentifiableAbort(err, "failed to verify valid Paillier public-key")
		}
		err = p.state.lpdlPrimeVerifiers[identity].Round5(input[identity].LpdlPrimeRound4Output)
		if err != nil {
			return nil, errs.WrapIdentifiableAbort(err, "failed to verify encrypted dlog")
		}
		err = p.state.lpdlDoublePrimeVerifiers[identity].Round5(input[identity].LpdlDoublePrimeRound4Output)
		if err != nil {
			return nil, errs.WrapIdentifiableAbort(err, "failed to verify encrypted dlog")
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

func commit(bigQPrime curves.Point, bigQDoublePrime curves.Point, sid []byte, pid curves.Point) (commitment commitments.Commitment, witness commitments.Witness, err error) {
	message := []byte{}
	message = append(message, bigQPrime.ToAffineCompressed()...)
	message = append(message, bigQDoublePrime.ToAffineCompressed()...)
	message = append(message, sid...)
	message = append(message, pid.ToAffineCompressed()...)
	return commitments.Commit(commitmentHashFunc, message)
}

func openCommitment(commitment commitments.Commitment, witness commitments.Witness, bigQPrime curves.Point, bigQDoublePrime curves.Point, sid []byte, pid curves.Point) (err error) {
	message := []byte{}
	message = append(message, bigQPrime.ToAffineCompressed()...)
	message = append(message, bigQDoublePrime.ToAffineCompressed()...)
	message = append(message, sid...)
	message = append(message, pid.ToAffineCompressed()...)
	return commitments.Open(commitmentHashFunc, message, commitment, witness)
}

func dlogProve(x curves.Scalar, bigQ curves.Point, bigQTwin curves.Point, sid []byte, transcript transcripts.Transcript) (proof *dlog.Proof, err error) {
	transcript.AppendPoints("bigQTwin", bigQTwin)

	curve, err := bigQ.Curve()
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "invalid curve %s", curve.Name())
	}
	generator := curve.Generator()

	prover, err := dlog.NewProver(generator, sid, transcript)
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

func dlogVerify(proof *dlog.Proof, bigQ curves.Point, bigQTwin curves.Point, sid []byte, transcript transcripts.Transcript) (err error) {
	transcript.AppendPoints("bigQTwin", bigQTwin)

	curve, err := bigQ.Curve()
	if err != nil {
		return errs.WrapInvalidCurve(err, "invalid curve %s", curve.Name())
	}
	generator := curve.Generator()

	return dlog.Verify(generator, bigQ, proof, sid, transcript)
}
