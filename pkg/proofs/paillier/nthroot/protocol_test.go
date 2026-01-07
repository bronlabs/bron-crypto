package nthroot_test

import (
	"bytes"
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/nthroot"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"
)

const primeLen = 1024

func Test_HappyPathInteractive(t *testing.T) {
	t.Parallel()
	prng := crand.Reader
	pBig, err := crand.Prime(prng, primeLen)
	require.NoError(t, err)
	pNatCt := numct.NewNatFromBig(pBig, pBig.BitLen())
	qBig, err := crand.Prime(prng, primeLen)
	require.NoError(t, err)
	gNatCt := numct.NewNatFromBig(qBig, qBig.BitLen())

	xNatPlus, err := num.NPlus().FromNatCT(pNatCt)
	require.NoError(t, err)
	yNatPlus, err := num.NPlus().FromNatCT(gNatCt)
	require.NoError(t, err)

	g, err := znstar.NewPaillierGroup(xNatPlus, yNatPlus)
	require.NoError(t, err)

	yBig, err := crand.Int(prng, g.N().Big())
	require.NoError(t, err)
	yNatCt := numct.NewNatFromBig(yBig, yBig.BitLen())
	var xNatCt numct.Nat
	g.Arithmetic().(*modular.OddPrimeSquareFactors).ExpToN(&xNatCt, yNatCt)

	err = doInteractiveProof(&xNatCt, yNatCt, g, prng)
	require.NoError(t, err)
}

func Test_InvalidRootInteractive(t *testing.T) {
	t.Parallel()
	prng := crand.Reader
	pBig, err := crand.Prime(prng, primeLen)
	require.NoError(t, err)
	pNatCt := numct.NewNatFromBig(pBig, primeLen)
	qBig, err := crand.Prime(prng, primeLen)
	require.NoError(t, err)
	qNatCt := numct.NewNatFromBig(qBig, primeLen)

	xNatPlus, err := num.NPlus().FromNatCT(pNatCt)
	require.NoError(t, err)
	yNatPlus, err := num.NPlus().FromNatCT(qNatCt)
	require.NoError(t, err)

	g, err := znstar.NewPaillierGroup(xNatPlus, yNatPlus)
	require.NoError(t, err)

	y1Big, err := crand.Int(prng, g.N().Big())
	require.NoError(t, err)
	y1NatCt := numct.NewNatFromBig(y1Big, primeLen*2)
	var x1NatCt numct.Nat
	g.Arithmetic().(*modular.OddPrimeSquareFactors).ExpToN(&x1NatCt, y1NatCt)

	y2Big, err := crand.Int(prng, g.N().Big())
	require.NoError(t, err)
	y2NatCt := numct.NewNatFromBig(y2Big, primeLen*2)
	var x2NatCt numct.Nat
	g.Arithmetic().(*modular.OddPrimeSquareFactors).ExpToN(&x2NatCt, y2NatCt)

	err = doInteractiveProof(&x1NatCt, y2NatCt, g, prng)
	require.Error(t, err)
	require.ErrorIs(t, err, nthroot.ErrVerificationFailed)

	err = doInteractiveProof(&x2NatCt, y1NatCt, g, prng)
	require.Error(t, err)
	require.ErrorIs(t, err, nthroot.ErrVerificationFailed)
}

func Test_HappyPathNonInteractive(t *testing.T) {
	t.Parallel()
	sessionId, err := network.NewSID([]byte("nthRootSession"))
	require.NoError(t, err)
	appLabel := "NthRoot"
	prng := crand.Reader
	pBig, err := crand.Prime(prng, primeLen)
	require.NoError(t, err)
	pNatCt := numct.NewNatFromBig(pBig, primeLen)
	qBig, err := crand.Prime(prng, primeLen)
	require.NoError(t, err)
	gNatCt := numct.NewNatFromBig(qBig, primeLen)

	xNatPlus, err := num.NPlus().FromNatCT(pNatCt)
	require.NoError(t, err)
	yNatPlus, err := num.NPlus().FromNatCT(gNatCt)
	require.NoError(t, err)

	g, err := znstar.NewPaillierGroup(xNatPlus, yNatPlus)
	require.NoError(t, err)

	protocol, err := nthroot.NewProtocol(g, prng)
	require.NoError(t, err)

	yBig, err := crand.Int(prng, g.N().Big())
	require.NoError(t, err)
	yNatCt := numct.NewNatFromBig(yBig, primeLen*2)
	var xNatCt numct.Nat
	g.Arithmetic().(*modular.OddPrimeSquareFactors).ExpToN(&xNatCt, yNatCt)

	x, err := g.FromNatCT(&xNatCt)
	require.NoError(t, err)
	w, err := g.FromNatCT(yNatCt)
	require.NoError(t, err)
	statement := nthroot.NewStatement(x)
	witness := nthroot.NewWitness(w)

	fsProtocol, err := fiatshamir.NewCompiler(protocol)
	require.NoError(t, err)

	proverTranscript := hagrid.NewTranscript(appLabel)
	prover, err := fsProtocol.NewProver(sessionId, proverTranscript)
	require.NoError(t, err)

	verifierTranscript := hagrid.NewTranscript(appLabel)
	verifier, err := fsProtocol.NewVerifier(sessionId, verifierTranscript)
	require.NoError(t, err)

	theProof, err := prover.Prove(statement, witness)
	require.NoError(t, err)

	err = verifier.Verify(statement, theProof)
	require.NoError(t, err)
}

func Test_InvalidRootNonInteractive(t *testing.T) {
	t.Parallel()
	sessionId, err := network.NewSID([]byte("nthRootSession"))
	require.NoError(t, err)
	appLabel := "NthRoot"
	prng := crand.Reader
	pBig, err := crand.Prime(prng, primeLen)
	require.NoError(t, err)
	pNatCt := numct.NewNatFromBig(pBig, primeLen)
	qBig, err := crand.Prime(prng, primeLen)
	require.NoError(t, err)
	qNatCt := numct.NewNatFromBig(qBig, primeLen)

	xNatPlus, err := num.NPlus().FromNatCT(pNatCt)
	require.NoError(t, err)
	yNatPlus, err := num.NPlus().FromNatCT(qNatCt)
	require.NoError(t, err)

	g, err := znstar.NewPaillierGroup(xNatPlus, yNatPlus)
	require.NoError(t, err)

	protocol, err := nthroot.NewProtocol(g, prng)
	require.NoError(t, err)

	y1Big, err := crand.Int(prng, g.N().Big())
	require.NoError(t, err)
	y1NatCt := numct.NewNatFromBig(y1Big, primeLen*2)
	var x1NatCt numct.Nat
	g.Arithmetic().(*modular.OddPrimeSquareFactors).ExpToN(&x1NatCt, y1NatCt)

	y2Big, err := crand.Int(prng, g.N().Big())
	require.NoError(t, err)
	y2NatCt := numct.NewNatFromBig(y2Big, primeLen*2)
	var x2NatCt numct.Nat
	g.Arithmetic().(*modular.OddPrimeSquareFactors).ExpToN(&x2NatCt, y2NatCt)

	x1, err := g.FromNatCT(&x1NatCt)
	require.NoError(t, err)
	w1, err := g.FromNatCT(y1NatCt)
	require.NoError(t, err)
	x2, err := g.FromNatCT(&x2NatCt)
	require.NoError(t, err)
	y2, err := g.FromNatCT(y2NatCt)
	require.NoError(t, err)

	fsProtocol, err := fiatshamir.NewCompiler(protocol)
	require.NoError(t, err)

	proverTranscript := hagrid.NewTranscript(appLabel)
	prover, err := fsProtocol.NewProver(sessionId, proverTranscript)
	require.NoError(t, err)

	verifierTranscript := hagrid.NewTranscript(appLabel)
	verifier, err := fsProtocol.NewVerifier(sessionId, verifierTranscript)
	require.NoError(t, err)

	statement1 := nthroot.NewStatement(x1)
	witness2 := nthroot.NewWitness(y2)
	proof1, err := prover.Prove(statement1, witness2)
	require.NoError(t, err)
	err = verifier.Verify(statement1, proof1)
	require.Error(t, err)
	require.ErrorIs(t, err, nthroot.ErrVerificationFailed)

	statement1 = nthroot.NewStatement(x1)
	witness1 := nthroot.NewWitness(w1)
	statement2 := nthroot.NewStatement(x2)
	proof2, err := prover.Prove(statement1, witness1)
	require.NoError(t, err)
	err = verifier.Verify(statement2, proof2)
	require.Error(t, err)
	require.ErrorIs(t, err, nthroot.ErrVerificationFailed)

	statement2 = nthroot.NewStatement(x2)
	witness2 = nthroot.NewWitness(y2)
	proof3, err := prover.Prove(statement2, witness2)
	require.NoError(t, err)
	err = verifier.Verify(statement1, proof3)
	require.Error(t, err)
	require.ErrorIs(t, err, nthroot.ErrVerificationFailed)

	statement2 = nthroot.NewStatement(x2)
	witness1 = nthroot.NewWitness(w1)
	proof4, err := prover.Prove(statement2, witness1)
	require.NoError(t, err)
	err = verifier.Verify(statement2, proof4)
	require.Error(t, err)
	require.ErrorIs(t, err, nthroot.ErrVerificationFailed)
}

func Test_Simulator(t *testing.T) {
	t.Parallel()
	prng := crand.Reader
	pBig, err := crand.Prime(prng, primeLen)
	require.NoError(t, err)
	pNatCt := numct.NewNatFromBig(pBig, primeLen)
	qBig, err := crand.Prime(prng, primeLen)
	require.NoError(t, err)
	qNatCt := numct.NewNatFromBig(qBig, primeLen)

	xNatPlus, err := num.NPlus().FromNatCT(pNatCt)
	require.NoError(t, err)
	yNatPlus, err := num.NPlus().FromNatCT(qNatCt)
	require.NoError(t, err)

	g, err := znstar.NewPaillierGroup(xNatPlus, yNatPlus)
	require.NoError(t, err)

	yBig, err := crand.Int(prng, g.N().Big())
	require.NoError(t, err)
	yNatCt := numct.NewNatFromBig(yBig, primeLen*2)
	var xNatCt numct.Nat
	g.Arithmetic().(*modular.OddPrimeSquareFactors).ExpToN(&xNatCt, yNatCt)

	xUnit, err := g.FromNatCT(&xNatCt)
	require.NoError(t, err)

	protocol, err := nthroot.NewProtocol(g, prng)
	require.NoError(t, err)

	e := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, e)
	require.NoError(t, err)

	x := nthroot.NewStatement(xUnit)
	a, z, err := protocol.RunSimulator(x, e)
	require.NoError(t, err)

	err = protocol.Verify(x, a, e, z)
	require.NoError(t, err)
}

func Test_Extractor(t *testing.T) {
	t.Parallel()
	prng := crand.Reader
	pBig, err := crand.Prime(prng, primeLen)
	require.NoError(t, err)
	pNatCt := numct.NewNatFromBig(pBig, primeLen)
	qBig, err := crand.Prime(prng, primeLen)
	require.NoError(t, err)
	qNatCt := numct.NewNatFromBig(qBig, primeLen)

	pNatPlus, err := num.NPlus().FromNatCT(pNatCt)
	require.NoError(t, err)
	qNatPlus, err := num.NPlus().FromNatCT(qNatCt)
	require.NoError(t, err)

	g, err := znstar.NewPaillierGroup(pNatPlus, qNatPlus)
	require.NoError(t, err)

	yBig, err := crand.Int(prng, g.N().Big())
	require.NoError(t, err)
	yNatCt := numct.NewNatFromBig(yBig, primeLen*2)
	var xNatCt numct.Nat
	g.Arithmetic().(*modular.OddPrimeSquareFactors).ExpToN(&xNatCt, yNatCt)

	w, err := g.FromNatCT(yNatCt)
	require.NoError(t, err)
	x, err := g.FromNatCT(&xNatCt)
	require.NoError(t, err)
	witness := nthroot.NewWitness(w)
	statement := nthroot.NewStatement(x)
	protocol, err := nthroot.NewProtocol(g, prng)
	require.NoError(t, err)

	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(t, err)
	challenge1 := make(sigma.ChallengeBytes, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge1)
	require.NoError(t, err)
	response1, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge1)
	require.NoError(t, err)
	challenge2 := make(sigma.ChallengeBytes, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge2)
	require.NoError(t, err)
	response2, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge2)
	require.NoError(t, err)

	ei := []sigma.ChallengeBytes{challenge1, challenge2}
	zi := []*nthroot.Response[*modular.OddPrimeSquareFactors]{response1, response2}
	extractedWitness, err := protocol.Extract(statement, commitment, ei, zi)
	require.NoError(t, err)
	require.True(t, witness.Value().Equal(extractedWitness.Value()))
}

func doInteractiveProof[A znstar.ArithmeticPaillier](xNatCt, yNatCt *numct.Nat, g *znstar.PaillierGroup[A], prng io.Reader) (err error) {
	var sessionId network.SID
	copy(sessionId[:], "nthRootSession")
	appLabel := "NthRoot"
	protocol, err := nthroot.NewProtocol(g, prng)
	if err != nil {
		return err
	}
	xUnit, err := g.FromNatCT(xNatCt)
	if err != nil {
		return err
	}
	yUnit, err := g.FromNatCT(yNatCt)
	if err != nil {
		return err
	}
	proverStatement := nthroot.NewStatement(xUnit)
	proverWitness := nthroot.NewWitness(yUnit)
	proverTranscript := hagrid.NewTranscript(appLabel)
	prover, err := sigma.NewProver(sessionId, proverTranscript, protocol, proverStatement, proverWitness)
	if err != nil {
		return err
	}

	verifierTranscript := hagrid.NewTranscript(appLabel)
	verifier, err := sigma.NewVerifier(sessionId, verifierTranscript, protocol, proverStatement, prng)
	if err != nil {
		return err
	}

	a, err := prover.Round1()
	if err != nil {
		return err
	}
	e, err := verifier.Round2(a)
	if err != nil {
		return err
	}
	z, err := prover.Round3(e)
	if err != nil {
		return err
	}

	err = verifier.Verify(z)
	if err != nil {
		return err
	}

	label := "gimme, gimme"
	proverBytes, err := proverTranscript.ExtractBytes(label, base.CollisionResistanceBytesCeil)
	if err != nil {
		return err
	}
	verifierBytes, err := verifierTranscript.ExtractBytes(label, base.CollisionResistanceBytesCeil)
	if err != nil {
		return err
	}
	if !bytes.Equal(proverBytes, verifierBytes) {
		return nthroot.ErrFailed.WithMessage("transcript record different data")
	}

	return nil
}
