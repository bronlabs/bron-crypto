package dkg

import (
	"crypto/sha256"
	"github.com/copperexchange/crypto-primitives-go/pkg/commitments"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/paillier"
	"github.com/copperexchange/crypto-primitives-go/pkg/proofs/paillier/lp"
	"github.com/copperexchange/crypto-primitives-go/pkg/proofs/paillier/lpdl"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17"
	dlog "github.com/copperexchange/crypto-primitives-go/pkg/zkp/schnorr"
)

const (
	paillierBitSize = 1024
)

var (
	commitmentHashFunc = sha256.New
)

type Round1Broadcast struct {
	BigQPrimeCommitment       commitments.Commitment
	BigQDoublePrimeCommitment commitments.Commitment
}

type Round2Broadcast struct {
	BigQPrime              curves.Point
	BigQPrimeWitness       commitments.Witness
	BigQPrimeProof         *dlog.Proof
	BigQDoublePrime        curves.Point
	BigQDoublePrimeWitness commitments.Witness
	BigQDoublePrimeProof   *dlog.Proof
}

type Round3Broadcast struct {
	CKeyPrime         paillier.CipherText
	CKeyDoublePrime   paillier.CipherText
	PaillierPublicKey *paillier.PublicKey
}

type Round4P2P struct {
	LpRound1Output              *lp.Round1Output
	LpdlPrimeRound1Output       *lpdl.VerifierRound1Output
	LpdlDoublePrimeRound1Output *lpdl.VerifierRound1Output
}

type Round5P2P struct {
	LpRound2Output              *lp.Round2Output
	LpdlPrimeRound2Output       *lpdl.ProverRound2Output
	LpdlDoublePrimeRound2Output *lpdl.ProverRound2Output
}

type Round6P2P struct {
	LpRound3Output              *lp.Round3Output
	LpdlPrimeRound3Output       *lpdl.VerifierRound3Output
	LpdlDoublePrimeRound3Output *lpdl.VerifierRound3Output
}

type Round7P2P struct {
	LpRound4Output              *lp.Round4Output
	LpdlPrimeRound4Output       *lpdl.ProverRound4Output
	LpdlDoublePrimeRound4Output *lpdl.ProverRound4Output
}

func (p *Participant) Round1() (output *Round1Broadcast, err error) {
	if p.round != 1 {
		return nil, errs.NewInvalidRound("%d != 1", p.round)
	}

	// 1.a + 2.b In the original paper P chooses a random x in [q/3, 2q/3) range and computes Q = x * G.
	// Since this protocol runs on already existing x, we choose x' and x'' in the given range
	// such that x = 3x' + x'', calculate Q', Q'' respectively and proceed with x' and x'' as if they were x.
	xPrime, xDoublePrime, _, err := lindell17.Split(p.mySigningKeyShare.Share, p.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot split share")
	}
	bigQPrime := p.cohortConfig.CipherSuite.Curve.ScalarBaseMult(xPrime)
	bigQDoublePrime := p.cohortConfig.CipherSuite.Curve.ScalarBaseMult(xDoublePrime)

	bigQPrimeCommitmentMessage := append(p.myIdentityKey.PublicKey().ToAffineCompressed()[:], bigQPrime.ToAffineCompressed()...)
	bigQPrimeCommitment, bigQPrimeWitness, err := commitments.Commit(commitmentHashFunc, bigQPrimeCommitmentMessage)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to Q'")
	}

	bigQDoublePrimeCommitmentMessage := append(p.myIdentityKey.PublicKey().ToAffineCompressed()[:], bigQDoublePrime.ToAffineCompressed()...)
	bigQDoublePrimeCommitment, biqQDoublePrimeWitness, err := commitments.Commit(commitmentHashFunc, bigQDoublePrimeCommitmentMessage)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to Q''")
	}

	p.state.myXPrime = xPrime
	p.state.myXDoublePrime = xDoublePrime
	p.state.myBigQPrime = bigQPrime
	p.state.myBigQDoublePrime = bigQDoublePrime
	p.state.myBigQPrimeWitness = bigQPrimeWitness
	p.state.myBigQDoublePrimeWitness = biqQDoublePrimeWitness

	// some paranoid checks
	if xPrime.Add(xPrime).Add(xPrime).Add(xDoublePrime).Cmp(p.mySigningKeyShare.Share) != 0 {
		return nil, errs.NewFailed("something went really wrong")
	}
	if !bigQPrime.Add(bigQPrime).Add(bigQPrime).Add(bigQDoublePrime).Equal(p.publicKeyShares.SharesMap[p.myIdentityKey]) {
		return nil, errs.NewFailed("something went really wrong")
	}

	p.round++
	return &Round1Broadcast{
		BigQPrimeCommitment:       bigQPrimeCommitment,
		BigQDoublePrimeCommitment: bigQDoublePrimeCommitment,
	}, nil
}

func (p *Participant) Round2(input map[integration.IdentityKey]*Round1Broadcast) (output *Round2Broadcast, err error) {
	if p.round != 2 {
		return nil, errs.NewInvalidRound("%d != 2", p.round)
	}

	p.state.theirBigQPrimeCommitment = make(map[integration.IdentityKey]commitments.Commitment)
	p.state.theirBigQDoublePrimeCommitment = make(map[integration.IdentityKey]commitments.Commitment)
	for _, identity := range p.cohortConfig.Participants {
		if identity == p.myIdentityKey {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with shamir id %d", p.idKeyToShamirId[identity])
		}
		p.state.theirBigQPrimeCommitment[identity] = input[identity].BigQPrimeCommitment
		p.state.theirBigQDoublePrimeCommitment[identity] = input[identity].BigQDoublePrimeCommitment
	}

	bigQPrimeProver, err := dlog.NewProver(p.cohortConfig.CipherSuite.Curve.NewGeneratorPoint(), p.sessionId, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create prover for Q'")
	}
	bigQPrimeProof, bigQPrimeStatement, err := bigQPrimeProver.Prove(p.state.myXPrime)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog proof of Q'")
	}
	if !p.state.myBigQPrime.Equal(bigQPrimeStatement) {
		return nil, errs.NewFailed("invalid statement, something went horribly wrong")
	}

	bigQDoublePrimeProver, err := dlog.NewProver(p.cohortConfig.CipherSuite.Curve.NewGeneratorPoint(), p.sessionId, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create prover for Q'")
	}
	bigQDoublePrimeProof, bigQDoublePrimeStatement, err := bigQDoublePrimeProver.Prove(p.state.myXDoublePrime)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog proof of Q''")
	}
	if !p.state.myBigQDoublePrime.Equal(bigQDoublePrimeStatement) {
		return nil, errs.NewFailed("invalid statement, something went horribly wrong")
	}

	p.round++
	return &Round2Broadcast{
		BigQPrime:              p.state.myBigQPrime,
		BigQPrimeWitness:       p.state.myBigQPrimeWitness,
		BigQPrimeProof:         bigQPrimeProof,
		BigQDoublePrime:        p.state.myBigQDoublePrime,
		BigQDoublePrimeWitness: p.state.myBigQDoublePrimeWitness,
		BigQDoublePrimeProof:   bigQDoublePrimeProof,
	}, nil
}

func (p *Participant) Round3(input map[integration.IdentityKey]*Round2Broadcast) (output *Round3Broadcast, err error) {
	if p.round != 3 {
		return nil, errs.NewInvalidRound("%d != 3", p.round)
	}

	// 3.a P receives dlog proof of Q
	p.state.theirBigQPrime = make(map[integration.IdentityKey]curves.Point)
	p.state.theirBigQDoublePrime = make(map[integration.IdentityKey]curves.Point)

	// 3.b P opens the commitment and verifies dlog proofs
	for _, identity := range p.cohortConfig.Participants {
		if identity == p.myIdentityKey {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with shamir id %d", p.idKeyToShamirId[identity])
		}

		bigQPrimeCommitmentMessage := append(identity.PublicKey().ToAffineCompressed()[:], input[identity].BigQPrime.ToAffineCompressed()...)
		err = commitments.Open(commitmentHashFunc, bigQPrimeCommitmentMessage, p.state.theirBigQPrimeCommitment[identity], input[identity].BigQPrimeWitness)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot open Q' commitment")
		}
		err = dlog.Verify(p.cohortConfig.CipherSuite.Curve.NewGeneratorPoint(), input[identity].BigQPrime, input[identity].BigQPrimeProof, p.sessionId, nil)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot verify dlog proof of Q'")
		}
		p.state.theirBigQPrime[identity] = input[identity].BigQPrime

		bigQDoublePrimeCommitmentMessage := append(identity.PublicKey().ToAffineCompressed()[:], input[identity].BigQDoublePrime.ToAffineCompressed()...)
		err = commitments.Open(commitmentHashFunc, bigQDoublePrimeCommitmentMessage, p.state.theirBigQDoublePrimeCommitment[identity], input[identity].BigQDoublePrimeWitness)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot open Q'' commitment")
		}
		err = dlog.Verify(p.cohortConfig.CipherSuite.Curve.NewGeneratorPoint(), input[identity].BigQDoublePrime, input[identity].BigQDoublePrimeProof, p.sessionId, nil)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot verify dlog proof of Q''")
		}
		p.state.theirBigQDoublePrime[identity] = input[identity].BigQDoublePrime
	}

	// 3.c P generates a Paillier key-pair
	p.state.myPaillierPk, p.state.myPaillierSk, err = paillier.NewKeys(paillierBitSize)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate Paillier keys")
	}
	cKeyPrime, rPrime, err := p.state.myPaillierPk.Encrypt(p.state.myXPrime.BigInt())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt x'")
	}
	cKeyDoublePrime, rDoublePrime, err := p.state.myPaillierPk.Encrypt(p.state.myXDoublePrime.BigInt())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt x''")
	}
	p.state.myRPrime = rPrime
	p.state.myRDoublePrime = rDoublePrime

	p.state.lpProvers = make(map[integration.IdentityKey]*lp.Prover)
	p.state.lpdlPrimeProvers = make(map[integration.IdentityKey]*lpdl.Prover)
	p.state.lpdlDoublePrimeProvers = make(map[integration.IdentityKey]*lpdl.Prover)
	for _, identity := range p.cohortConfig.Participants {
		if identity == p.myIdentityKey {
			continue
		}

		// 4. P proves in zero knowledge that public-key was generated correctly (L_P)
		// and the encrypted share encrypts dlog of Q (L_PDL)
		p.state.lpProvers[identity] = lp.NewProver(40, p.state.myPaillierSk, p.prng)
		p.state.lpdlPrimeProvers[identity], err = lpdl.NewProver(p.sessionId, p.state.myPaillierSk, p.state.myXPrime, p.state.myRPrime, p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create PDL prover")
		}
		p.state.lpdlDoublePrimeProvers[identity], err = lpdl.NewProver(p.sessionId, p.state.myPaillierSk, p.state.myXDoublePrime, p.state.myRDoublePrime, p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create PDL prover")
		}
	}

	// 3.d P sends public-key and encryption of x to other parties
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
		if identity == p.myIdentityKey {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with shamir id %d", p.idKeyToShamirId[identity])
		}

		p.state.theirPaillierPublicKeys[identity] = input[identity].PaillierPublicKey
		theirCKeyPrime := input[identity].CKeyPrime
		theirCKeyDoublePrime := input[identity].CKeyDoublePrime

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

		p.state.lpVerifiers[identity] = lp.NewVerifier(40, p.state.theirPaillierPublicKeys[identity], p.prng)
		p.state.lpdlPrimeVerifiers[identity], err = lpdl.NewVerifier(p.sessionId, p.state.theirPaillierPublicKeys[identity], p.state.theirBigQPrime[identity], theirCKeyPrime, p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create PDL verifier")
		}
		p.state.lpdlDoublePrimeVerifiers[identity], err = lpdl.NewVerifier(p.sessionId, p.state.theirPaillierPublicKeys[identity], p.state.theirBigQDoublePrime[identity], theirCKeyDoublePrime, p.prng)
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

	round5Outputs := make(map[integration.IdentityKey]*Round5P2P)
	for _, identity := range p.cohortConfig.Participants {
		if identity == p.myIdentityKey {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with shamir id %d", p.idKeyToShamirId[identity])
		}

		round5Outputs[identity] = new(Round5P2P)
		round5Outputs[identity].LpRound2Output, err = p.state.lpProvers[identity].Round2(input[identity].LpRound1Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LP prover")
		}
		round5Outputs[identity].LpdlPrimeRound2Output, err = p.state.lpdlPrimeProvers[identity].Round2(input[identity].LpdlPrimeRound1Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LP prover")
		}
		round5Outputs[identity].LpdlDoublePrimeRound2Output, err = p.state.lpdlDoublePrimeProvers[identity].Round2(input[identity].LpdlDoublePrimeRound1Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LP prover")
		}
	}

	p.round++
	return round5Outputs, nil
}

func (p *Participant) Round6(input map[integration.IdentityKey]*Round5P2P) (output map[integration.IdentityKey]*Round6P2P, err error) {
	if p.round != 6 {
		return nil, errs.NewInvalidRound("%d != 6", p.round)
	}

	round6Outputs := make(map[integration.IdentityKey]*Round6P2P)
	for _, identity := range p.cohortConfig.Participants {
		if identity == p.myIdentityKey {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with shamir id %d", p.idKeyToShamirId[identity])
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

	round7Outputs := make(map[integration.IdentityKey]*Round7P2P)
	for _, identity := range p.cohortConfig.Participants {
		if identity == p.myIdentityKey {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with shamir id %d", p.idKeyToShamirId[identity])
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
		if identity == p.myIdentityKey {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with shamir id %d", p.idKeyToShamirId[identity])
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
	// 6. P stores encrypted Enc(x) which is Enc(3x' + x'')
	return &lindell17.Shard{
		SigningKeyShare:         p.mySigningKeyShare,
		PaillierSecretKey:       p.state.myPaillierSk,
		PaillierPublicKeys:      p.state.theirPaillierPublicKeys,
		PaillierEncryptedShares: p.state.theirPaillierEncryptedShares,
	}, nil
}
