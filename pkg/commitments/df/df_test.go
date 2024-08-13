package df_test

import (
	crand "crypto/rand"
	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
	"github.com/copperexchange/krypton-primitives/pkg/cgo/boring"
	"github.com/copperexchange/krypton-primitives/pkg/commitments/df"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
	"io"
	"testing"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	g, h, n := genParams(t, prng)
	scheme := df.NewScheme(g, h, n)

	message := randomMessage(t, 2048, prng)

	commitment, witness := scheme.Commit(message, prng)
	err := scheme.Verify(message, commitment, witness)
	require.NoError(t, err)
}

func Test_ShouldFailOnInvalidCommitmentOrOpening(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	g, h, n := genParams(t, prng)
	scheme := df.NewScheme(g, h, n)

	message := randomMessage(t, 2048, prng)

	commitmentA, witnessA := scheme.Commit(message, prng)
	commitmentB, witnessB := scheme.Commit(message, prng)

	err := scheme.Verify(message, commitmentA, witnessB)
	require.Error(t, err)

	err = scheme.Verify(message, commitmentB, witnessA)
	require.Error(t, err)
}

func Test_ShouldFailOnNilCommitment(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	g, h, n := genParams(t, prng)
	scheme := df.NewScheme(g, h, n)

	message := randomMessage(t, 2048, prng)

	_, witness := scheme.Commit(message, prng)
	//require.NoError(t, err)

	err := scheme.Verify(message, nil, witness)
	require.Error(t, err)

}

func Test_HappyPathAdd(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	g, h, n := genParams(t, prng)
	scheme := df.NewScheme(g, h, n)

	messageA := randomMessage(t, 2048, prng)
	messageB := randomMessage(t, 2048, prng)
	messageAPlusB := new(saferith.Int).Add(messageA, messageB, -1)

	commitmentA, witnessA := scheme.Commit(messageA, prng)
	commitmentB, witnessB := scheme.Commit(messageB, prng)

	aPlusBCommitment := scheme.CommitmentAdd(commitmentA, commitmentB)
	aPlusBWitness := scheme.WitnessAdd(witnessA, witnessB)

	err := scheme.Verify(messageAPlusB, aPlusBCommitment, aPlusBWitness)
	require.NoError(t, err)

}

func Test_HappyPathSum(t *testing.T) {
	t.Parallel()
	prng := crand.Reader
	const k = 16

	g, h, n := genParams(t, prng)
	scheme := df.NewScheme(g, h, n)

	var messages [k]*df.Message
	for i := range k {
		messages[i] = randomMessage(t, 2048, prng)
	}

	messagesSum := new(saferith.Int).SetUint64(0)
	for _, m := range messages {
		messagesSum.Add(messagesSum, m, -1)
	}

	var commitments [k]*df.Commitment
	var witnesses [k]*df.Witness
	for i := range k {
		commitments[i], witnesses[i] = scheme.Commit(messages[i], prng)
	}

	sumCommitment := scheme.CommitmentSum(commitments[0], commitments[1:]...)
	sumWitness := scheme.WitnessSum(witnesses[0], witnesses[1:]...)
	err := scheme.Verify(messagesSum, sumCommitment, sumWitness)
	require.NoError(t, err)
}

func Test_HappyPathSub(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	g, h, n := genParams(t, prng)
	scheme := df.NewScheme(g, h, n)

	messageA := randomMessage(t, 2048, prng)
	messageB := randomMessage(t, 2048, prng)
	messageAMinusB := new(saferith.Int).Add(messageA, new(saferith.Int).SetInt(messageB).Neg(1), -1)

	commitmentA, witnessA := scheme.Commit(messageA, prng)
	commitmentB, witnessB := scheme.Commit(messageB, prng)

	aMinusBCommitment := scheme.CommitmentSub(commitmentA, commitmentB)
	aMinusBWitness := scheme.WitnessSub(witnessA, witnessB)

	err := scheme.Verify(messageAMinusB, aMinusBCommitment, aMinusBWitness)
	require.NoError(t, err)

}

func Test_HappyPathNeg(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	g, h, n := genParams(t, prng)
	scheme := df.NewScheme(g, h, n)

	message := randomMessage(t, 2048, prng)
	messageNeg := new(saferith.Int).SetInt(message).Neg(1)

	commitment, witness := scheme.Commit(message, prng)
	negCommitment := scheme.CommitmentNeg(commitment)
	negWitness := scheme.WitnessNeg(witness)
	err := scheme.Verify(messageNeg, negCommitment, negWitness)
	require.NoError(t, err)

}

func Test_HappyPathScale(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	g, h, n := genParams(t, prng)
	scheme := df.NewScheme(g, h, n)

	message := randomMessage(t, 2048, prng)
	sc := randomMessage(t, 2048, prng)
	scaledMessage := new(saferith.Int).Mul(message, sc, -1)

	commitment, witness := scheme.Commit(message, prng)
	scaledCommitment := scheme.CommitmentScale(commitment, sc)
	scaledWitness := scheme.WitnessScale(witness, sc)
	err := scheme.Verify(scaledMessage, scaledCommitment, scaledWitness)
	require.NoError(t, err)

}

func Test_OpenOnWrongAdd(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	g, h, n := genParams(t, prng)
	scheme := df.NewScheme(g, h, n)

	messageA := randomMessage(t, 2048, prng)
	messageB := randomMessage(t, 2048, prng)
	messageAPlusB := new(saferith.Int).Add(messageA, messageB, -1)

	commitmentA, witnessA := scheme.Commit(messageA, prng)
	commitmentB, witnessB := scheme.Commit(messageB, prng)
	commitmentBPrime, witnessBPrime := scheme.Commit(messageB, prng)

	commitmentAPlusB := scheme.CommitmentAdd(commitmentA, commitmentB)
	commitmentAPlusBPrime := scheme.CommitmentAdd(commitmentA, commitmentBPrime)
	witnessAPlusB := scheme.WitnessAdd(witnessA, witnessB)
	witnessAPlusBPrime := scheme.WitnessAdd(witnessA, witnessBPrime)

	err := scheme.Verify(messageAPlusB, commitmentAPlusB, witnessAPlusBPrime)
	require.Error(t, err)

	err = scheme.Verify(messageAPlusB, commitmentAPlusBPrime, witnessAPlusB)
	require.Error(t, err)
}

func Test_OpenOnWrongScale(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	g, h, n := genParams(t, prng)
	scheme := df.NewScheme(g, h, n)

	message := randomMessage(t, 2048, prng)
	scale := randomMessage(t, 2048, prng)
	scaledMessage := new(saferith.Int).Mul(message, scale, -1)

	commitmentA, witnessA := scheme.Commit(message, prng)
	commitmentB, witnessB := scheme.Commit(message, prng)

	commitmentAScaled := scheme.CommitmentScale(commitmentA, scale)
	commitmentBScaled := scheme.CommitmentScale(commitmentB, scale)

	openingAScaled := scheme.WitnessScale(witnessA, scale)
	openingBScaled := scheme.WitnessScale(witnessB, scale)

	err := scheme.Verify(scaledMessage, commitmentAScaled, openingBScaled)
	require.Error(t, err)

	err = scheme.Verify(scaledMessage, commitmentBScaled, openingAScaled)
	require.Error(t, err)
}

func genParams(t require.TestingT, prng io.Reader) (*saferith.Nat, *saferith.Nat, *saferith.Modulus) {
	pBytes, err := boring.NewDiffieHellmanGroup().GenerateParameters(512).GetP().Bytes()
	require.NoError(t, err)
	p := new(saferith.Nat).SetBytes(pBytes)
	qBytes, err := boring.NewDiffieHellmanGroup().GenerateParameters(512).GetP().Bytes()
	require.NoError(t, err)
	q := new(saferith.Nat).SetBytes(qBytes)
	pq := new(saferith.Nat).Mul(p, q, 1024)
	n := saferith.ModulusFromNat(pq)

	gBig, err := crand.Int(prng, n.Big())
	require.NoError(t, err)
	g := new(saferith.Nat).SetBig(gBig, 1024)
	g.ModMul(g, g, n)

	hBig, err := crand.Int(prng, n.Big())
	require.NoError(t, err)
	h := new(saferith.Nat).SetBig(hBig, 1024)
	h.ModMul(h, h, n)

	return g, h, n
}

func randomMessage(t require.TestingT, bits uint, prng io.Reader) *saferith.Int {
	mNat, err := saferithUtils.NatRandomBits(prng, bits)
	require.NoError(t, err)
	m := new(saferith.Int).SetNat(mNat)

	var choice [1]byte
	_, err = io.ReadFull(prng, choice[:])
	require.NoError(t, err)
	m.Neg(saferith.Choice(choice[0] % 2))
	return m
}
