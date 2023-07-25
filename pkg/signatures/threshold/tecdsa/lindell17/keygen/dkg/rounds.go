package dkg

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"github.com/copperexchange/crypto-primitives-go/pkg/commitments"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/paillier"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17"
	dlog "github.com/copperexchange/crypto-primitives-go/pkg/zkp/schnorr"
	"io"
	"math/big"
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
	BigQWitness    commitments.Witness
	BigQPrimeProof *dlog.Proof
	BigQBisProof   *dlog.Proof
}

type Round3Broadcast struct {
	CKeyPrime         paillier.CipherText
	CKeyBis           paillier.CipherText
	PaillierPublicKey *paillier.PublicKey
}

func (participant *Participant) Round1() (output *Round1Broadcast, err error) {
	xPrime, xBis, _, err := split(participant.mySigningKeyShare.Share, participant.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot split share")
	}

	bigQPrimeSessionId := append([]byte("backupQ'"), participant.sessionId...)
	bigQPrimeProver, err := dlog.NewProver(participant.cohortConfig.CipherSuite.Curve.NewGeneratorPoint(), bigQPrimeSessionId, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create prover for Q'")
	}
	bigQPrimeProof, err := bigQPrimeProver.Prove(xPrime)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog proof of x'")
	}

	bigQBisSessionId := append([]byte("backupQ''"), participant.sessionId...)
	bigQBisProver, err := dlog.NewProver(participant.cohortConfig.CipherSuite.Curve.NewGeneratorPoint(), bigQBisSessionId, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create prover for Q'")
	}
	bigQBisProof, err := bigQBisProver.Prove(xBis)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog proof of x'")
	}

	bigQPrimeProofMessage, err := json.Marshal(bigQPrimeProof)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot serialize dlog proof of Q'")
	}
	bigQBisProofMessage, err := json.Marshal(bigQBisProof)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot serialize dlog proof of Q''")
	}
	bigQMessage := append(bigQPrimeProofMessage[:], bigQBisProofMessage...)
	bigQCommitment, bigQWitness, err := commitments.Commit(commitmentHashFunc, bigQMessage)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to Q' and Q''")
	}
	participant.state.myBigQPrimeProof = bigQPrimeProof
	participant.state.myBigQBisProof = bigQBisProof
	participant.state.myBigQWitness = bigQWitness

	return &Round1Broadcast{
		BigQCommitment: bigQCommitment,
	}, nil
}

func (participant *Participant) Round2(input map[integration.IdentityKey]*Round1Broadcast) (output *Round2Broadcast, err error) {
	participant.state.theirBigQCommitment = make(map[integration.IdentityKey]commitments.Commitment)
	for _, identity := range participant.cohortConfig.Participants {
		if identity == participant.myIdentityKey {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with shamir id %d", participant.idKeyToShamirId[identity])
		}
		participant.state.theirBigQCommitment[identity] = input[identity].BigQCommitment
	}

	return &Round2Broadcast{
		BigQWitness:    participant.state.myBigQWitness,
		BigQPrimeProof: participant.state.myBigQPrimeProof,
		BigQBisProof:   participant.state.myBigQBisProof,
	}, nil
}

func (participant *Participant) Round3(input map[integration.IdentityKey]*Round2Broadcast) (output *Round3Broadcast, err error) {
	for _, identity := range participant.cohortConfig.Participants {
		if identity == participant.myIdentityKey {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with shamir id %d", participant.idKeyToShamirId[identity])
		}

		bigQPrimeProofMessage, err := json.Marshal(input[identity].BigQPrimeProof)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot serialize dlog proof of Q'")
		}
		bigQBisProofMessage, err := json.Marshal(input[identity].BigQBisProof)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot serialize dlog proof of Q''")
		}
		bigQMessage := append(bigQPrimeProofMessage[:], bigQBisProofMessage...)
		if err := commitments.Open(commitmentHashFunc, bigQMessage, participant.state.theirBigQCommitment[identity], input[identity].BigQWitness); err != nil {
			return nil, errs.WrapFailed(err, "cannot open commitment")
		}

		bigQPrimeSessionId := append([]byte("backupQ'"), participant.sessionId...)
		if err := dlog.Verify(participant.cohortConfig.CipherSuite.Curve.NewGeneratorPoint(), input[identity].BigQPrimeProof, bigQPrimeSessionId, nil); err != nil {
			return nil, errs.WrapFailed(err, "cannot verify dlog proof of Q'")
		}
		bigQBisSessionId := append([]byte("backupQ''"), participant.sessionId...)
		if err := dlog.Verify(participant.cohortConfig.CipherSuite.Curve.NewGeneratorPoint(), input[identity].BigQBisProof, bigQBisSessionId, nil); err != nil {
			return nil, errs.WrapFailed(err, "cannot verify dlog proof of Q'")
		}

		theirBigQPrime := input[identity].BigQPrimeProof.Statement
		theirBigQBis := input[identity].BigQBisProof.Statement
		theirBigQ := theirBigQPrime.Add(theirBigQPrime).Add(theirBigQPrime).Sub(theirBigQBis)
		if !theirBigQ.Equal(participant.publicKeyShares.SharesMap[identity]) {
			return nil, errs.NewVerificationFailed("public key share don't match")
		}

		participant.state.theirBigQPrime = theirBigQPrime
		participant.state.theirBigQBis = theirBigQBis
	}

	participant.state.myPaillierPk, participant.state.myPaillierSk, err = paillier.NewKeys(paillierBitSize)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate Paillier keys")
	}

	cKeyPrime, rPrime, err := participant.state.myPaillierPk.Encrypt(participant.state.myXPrime.BigInt())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt x'")
	}
	cKeyBis, rBis, err := participant.state.myPaillierPk.Encrypt(participant.state.myxBis.BigInt())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt x''")
	}
	participant.state.myRPrime = rPrime
	participant.state.myRBis = rBis

	return &Round3Broadcast{
		CKeyPrime:         cKeyPrime,
		CKeyBis:           cKeyBis,
		PaillierPublicKey: participant.state.myPaillierPk,
	}, nil
}

func (participant *Participant) Round4(input map[integration.IdentityKey]*Round3Broadcast) (shard *lindell17.Shard, err error) {
	// TODO: add zk-proof (3 additional rounds)

	paillierPublicKeys := make(map[integration.IdentityKey]*paillier.PublicKey)
	paillierEncryptedShares := make(map[integration.IdentityKey]paillier.CipherText)

	for _, identity := range participant.cohortConfig.Participants {
		if identity == participant.myIdentityKey {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with shamir id %d", participant.idKeyToShamirId[identity])
		}
		theirPaillierPk := input[identity].PaillierPublicKey
		theirCKeyPrime := input[identity].CKeyPrime
		theirCKeyBis := input[identity].CKeyBis
		cKey1, err := theirPaillierPk.Add(theirCKeyPrime, theirCKeyPrime)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot add ciphertexts")
		}
		cKey2, err := theirPaillierPk.Add(cKey1, theirCKeyPrime)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot add ciphertexts")
		}
		theirCKey, err := theirPaillierPk.Add(cKey2, theirCKeyBis)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot add ciphertexts")
		}

		paillierEncryptedShares[identity] = theirCKey
		paillierPublicKeys[identity] = theirPaillierPk
	}

	return &lindell17.Shard{
		SigningKeyShare:         participant.mySigningKeyShare,
		PaillierSecretKey:       participant.state.myPaillierSk,
		PaillierPublicKeys:      paillierPublicKeys,
		PaillierEncryptedShares: paillierEncryptedShares,
	}, nil
}

func split(scalar curves.Scalar, prng io.Reader) (xPrime curves.Scalar, xBis curves.Scalar, i int, err error) {
	curve, err := curves.GetCurveByName(scalar.Point().CurveName())
	if err != nil {
		return nil, nil, 0, errs.WrapInvalidCurve(err, "invalid curve %s", scalar.Point().CurveName())
	}
	order, err := getCurveSubgroupOrder(curve)
	if err != nil {
		return nil, nil, 0, errs.WrapFailed(err, "cannot get curve order")
	}

	i = 0
	l := new(big.Int).Div(order, big.NewInt(3))
	for {
		r, err := crand.Int(prng, l)
		if err != nil {
			return nil, nil, 0, errs.WrapFailed(err, "cannot generate random")
		}
		xPrimeInt := new(big.Int).Add(l, r)
		xPrime, err = curve.NewScalar().SetBigInt(xPrimeInt)
		if err != nil {
			return nil, nil, 0, errs.WrapFailed(err, "cannot set scalar")
		}
		xBis = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)

		if isInSecondThird(xPrime) && isInSecondThird(xBis) {
			break
		}
		// failsafe
		i++
		if i > 974 {
			// probability of this happening is (5/6)^(974) =~ (1/2)^(256)
			return nil, nil, 0, errs.NewFailed("cannot find x' and x''")
		}
	}

	return xPrime, xBis, i, nil
}

func isInSecondThird(scalar curves.Scalar) bool {
	curve, err := curves.GetCurveByName(scalar.Point().CurveName())
	if err != nil {
		return false
	}
	order, err := getCurveSubgroupOrder(curve)
	if err != nil {
		return false
	}
	l := new(big.Int).Div(order, big.NewInt(3))
	return scalar.BigInt().Cmp(l) >= 0 && scalar.BigInt().Cmp(new(big.Int).Add(l, l)) < 0
}

func getCurveSubgroupOrder(curve *curves.Curve) (order *big.Int, err error) {
	elCurve, err := curve.ToEllipticCurve()
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "invalid curve %s", curve.Name)
	}
	return elCurve.Params().N, nil
}
