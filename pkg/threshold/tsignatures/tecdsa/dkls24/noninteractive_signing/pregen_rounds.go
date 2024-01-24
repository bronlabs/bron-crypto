package noninteractive_signing

import (
	"sort"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/mult"
	"golang.org/x/crypto/sha3"
)

type CombiGroupHash [32]byte

// short and hash the sharing ids to get the combi group hash
func NewCombiGroupHash(sharingIds []int) CombiGroupHash {
	sort.Ints(sharingIds)
	var sharingBytes [][]byte
	for _, id := range sharingIds {
		sharingBytes = append(sharingBytes, bitstring.ToBytesLE(id))
	}
	bytes, err := hashing.Hash(sha3.New256, sharingBytes...)
	if err != nil {
		return CombiGroupHash{}
	}
	return CombiGroupHash(bytes)
}

type Round1Broadcast struct {
	R_i map[CombiGroupHash][]curves.Point

	_ types.Incomparable
}

type Round1P2P struct {
	CommitmentToInstanceKey map[CombiGroupHash][]commitments.Commitment
	MultiplicationOutput    map[CombiGroupHash][]*mult.Round1Output

	_ types.Incomparable
}

type Round2P2P struct {
	Multiplication                      map[CombiGroupHash][]*mult.Round2Output
	GammaU_ij                           map[CombiGroupHash][]curves.Point
	GammaV_ij                           map[CombiGroupHash][]curves.Point
	Psi_ij                              map[CombiGroupHash][]curves.Scalar
	WitnessOfTheCommitmentToInstanceKey map[CombiGroupHash][]commitments.Witness

	_ types.Incomparable
}

type Round2Broadcast struct {
	PK_i map[CombiGroupHash][]curves.Point

	_ types.Incomparable
}

func (ic *PregenParticipant) Round1() (r1b *Round1Broadcast, r1u map[types.IdentityHash]*Round1P2P, err error) {
	if ic.round != 1 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 1", ic.round)
	}
	broadcast := &Round1Broadcast{
		R_i: make(map[CombiGroupHash][]curves.Point),
	}
	outputP2P := make(map[types.IdentityHash]*Round1P2P)
	for _, combination := range ic.combinations {
		group := NewCombiGroupHash(combination)
		broadcast.R_i[group] = make([]curves.Point, ic.tau)
		for i := 0; i < ic.tau; i++ {
			// step 1.1
			ic.state[group].phi_i[i], err = ic.CohortConfig.CipherSuite.Curve.ScalarField().Random(ic.prng)

			if err != nil {
				return nil, nil, errs.WrapRandomSampleFailed(err, "could not sample phi_i")
			}
			// step 1.2
			ic.state[group].r_i[i], err = ic.CohortConfig.CipherSuite.Curve.ScalarField().Random(ic.prng)
			if err != nil {
				return nil, nil, errs.WrapRandomSampleFailed(err, "could not sample r_i")
			}
			// step 1.3
			ic.state[group].R_i[i] = ic.CohortConfig.CipherSuite.Curve.ScalarBaseMult(ic.state[group].r_i[i])

			for _, participant := range ic.SessionParticipants[group].Iter() {
				if participant.PublicKey().Equal(ic.MyAuthKey.PublicKey()) {
					continue
				}

				// step 1.3.1
				idHash := participant.Hash()
				commitmentToInstanceKey, witness, err := commitments.Commit(
					ic.UniqueSessionId,
					ic.prng,
					bitstring.ToBytesLE(ic.MySharingId),
					bitstring.ToBytesLE(ic.IdentityKeyToSharingId[idHash]),
					ic.state[group].R_i[i].ToAffineCompressed(),
				)
				if err != nil {
					return nil, nil, errs.WrapFailed(err, "could not commit to instance key")
				}
				ic.state[group].witnessesOfCommitmentToInstanceKey[i][idHash] = witness

				// step 1.3.2
				b, multiplicationOutput, err := ic.subprotocols[group].multiplication[idHash].Bob.Round1()
				if err != nil {
					return nil, nil, errs.WrapFailed(err, "multiplication round 1")
				}

				// step 1.3.3
				ic.state[group].Chi_i[i][idHash] = b

				// step 1.3.4
				if outputP2P[idHash] == nil {
					outputP2P[idHash] = &Round1P2P{
						CommitmentToInstanceKey: make(map[CombiGroupHash][]commitments.Commitment),
						MultiplicationOutput:    make(map[CombiGroupHash][]*mult.Round1Output),
					}
				}
				if outputP2P[idHash].CommitmentToInstanceKey[group] == nil {
					outputP2P[idHash].CommitmentToInstanceKey[group] = make([]commitments.Commitment, ic.tau)
				}
				if outputP2P[idHash].MultiplicationOutput[group] == nil {
					outputP2P[idHash].MultiplicationOutput[group] = make([]*mult.Round1Output, ic.tau)
				}
				outputP2P[idHash].CommitmentToInstanceKey[group][i] = commitmentToInstanceKey
				outputP2P[idHash].MultiplicationOutput[group][i] = multiplicationOutput
			}
			broadcast.R_i[group][i] = ic.state[group].R_i[i]
		}
	}

	ic.round++
	// step 1.4
	return broadcast, outputP2P, nil
}

func (ic *PregenParticipant) Round2(round1outputBroadcast map[types.IdentityHash]*Round1Broadcast, round1outputP2P map[types.IdentityHash]*Round1P2P) (*Round2Broadcast, map[types.IdentityHash]*Round2P2P, error) {
	if ic.round != 2 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 2", ic.round)
	}
	outputP2P := make(map[types.IdentityHash]*Round2P2P)
	broadcast := &Round2Broadcast{
		PK_i: make(map[CombiGroupHash][]curves.Point),
	}
	for _, combination := range ic.combinations {
		group := NewCombiGroupHash(combination)
		broadcast.PK_i[group] = make([]curves.Point, ic.tau)
		for i := 0; i < ic.tau; i++ {
			// step 2.1
			zeta_i, err := ic.subprotocols[group].zeroShareSampling.Sample()
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "mask F_Zero")
			}
			// step 2.2
			myShamirShare := &shamir.Share{
				Id:    ic.MySharingId,
				Value: ic.Shard.SigningKeyShare.Share,
			}
			myAdditiveShare, err := myShamirShare.ToAdditive(ic.sessionSharingIds[group])
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "could not convert my shamir share to additive share")
			}
			// step 2.3
			ic.state[group].sk_i[i] = myAdditiveShare.Add(zeta_i)
			// step 2.4
			ic.state[group].pk_i[i] = ic.CohortConfig.CipherSuite.Curve.ScalarBaseMult(ic.state[group].sk_i[i])
			// step 2.5
			a := [mult.L]curves.Scalar{ic.state[group].r_i[i], ic.state[group].sk_i[i]}

			for _, participant := range ic.SessionParticipants[group].Iter() {
				if participant.PublicKey().Equal(ic.MyAuthKey.PublicKey()) {
					continue
				}
				// step 2.6.1
				idHash := participant.Hash()
				receivedBroadcastMessage := round1outputBroadcast[idHash]
				ic.state[group].receivedR_i[i][idHash] = receivedBroadcastMessage.R_i[group][i]

				// step 2.6.2
				receivedP2PMessage := round1outputP2P[idHash]
				ic.state[group].receivedCommitmentsToInstanceKey[i][idHash] = receivedP2PMessage.CommitmentToInstanceKey[group][i]

				// step 2.6.3
				c_ij, multiplicationOutput, err := ic.subprotocols[group].multiplication[idHash].Alice.Round2(receivedP2PMessage.MultiplicationOutput[group][i], a)
				if err != nil {
					return nil, nil, errs.WrapFailed(err, "F_RVOLE round 2 sample")
				}
				ic.state[group].cU_i[i][idHash] = c_ij[0]
				ic.state[group].cV_i[i][idHash] = c_ij[1]

				// step 2.6.4
				gammaU_ij := ic.CohortConfig.CipherSuite.Curve.ScalarBaseMult(ic.state[group].cU_i[i][idHash])
				// step 2.6.5
				gammaV_ij := ic.CohortConfig.CipherSuite.Curve.ScalarBaseMult(ic.state[group].cV_i[i][idHash])
				// step 2.6.6
				psi_ij := ic.state[group].phi_i[i].Sub(ic.state[group].Chi_i[i][idHash])

				// step 2.6.7
				if outputP2P[idHash] == nil {
					outputP2P[idHash] = &Round2P2P{}
					outputP2P[idHash].Multiplication = make(map[CombiGroupHash][]*mult.Round2Output, ic.tau)
					outputP2P[idHash].GammaU_ij = make(map[CombiGroupHash][]curves.Point, ic.tau)
					outputP2P[idHash].GammaV_ij = make(map[CombiGroupHash][]curves.Point, ic.tau)
					outputP2P[idHash].Psi_ij = make(map[CombiGroupHash][]curves.Scalar, ic.tau)
					outputP2P[idHash].WitnessOfTheCommitmentToInstanceKey = make(map[CombiGroupHash][]commitments.Witness, ic.tau)
				}
				outputP2P[idHash].Multiplication[group][i] = multiplicationOutput
				outputP2P[idHash].GammaU_ij[group][i] = gammaU_ij
				outputP2P[idHash].GammaV_ij[group][i] = gammaV_ij
				outputP2P[idHash].Psi_ij[group][i] = psi_ij
				outputP2P[idHash].WitnessOfTheCommitmentToInstanceKey[group][i] = ic.state[group].witnessesOfCommitmentToInstanceKey[i][idHash]
			}
			broadcast.PK_i[group][i] = ic.state[group].pk_i[i]
		}
	}
	ic.round++
	// step 2.7
	return broadcast, outputP2P, nil
}
