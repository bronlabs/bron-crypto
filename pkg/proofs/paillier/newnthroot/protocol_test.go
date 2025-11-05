package newnthroot_test

import (
	"bytes"
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/network"
	nthroot "github.com/bronlabs/bron-crypto/pkg/proofs/paillier/newnthroot"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"
)

func Test_HappyPathInteractive(t *testing.T) {
	t.Parallel()
	prng := crand.Reader
	pInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	p := numct.NewNatFromBig(pInt, 128)
	qInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	q := numct.NewNatFromBig(qInt, 128)

	xNatPlus, err := num.NPlus().FromNatCT(p)
	require.NoError(t, err)
	yNatPlus, err := num.NPlus().FromNatCT(q)
	require.NoError(t, err)

	g, err := znstar.NewPaillierGroup(xNatPlus, yNatPlus)
	require.NoError(t, err)

	yInt, err := crand.Int(prng, g.N().Big())
	require.NoError(t, err)
	y := numct.NewNatFromBig(yInt, 256)
	var x numct.Nat
	g.Arithmetic().ExpToN(&x, y)

	err = doInteractiveProof(&x, y, g, prng)
	require.NoError(t, err)
}

func Test_InvalidRootInteractive(t *testing.T) {
	t.Parallel()
	prng := crand.Reader
	pInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	p := numct.NewNatFromBig(pInt, 128)
	qInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	q := numct.NewNatFromBig(qInt, 128)

	xNatPlus, err := num.NPlus().FromNatCT(p)
	require.NoError(t, err)
	yNatPlus, err := num.NPlus().FromNatCT(q)
	require.NoError(t, err)

	g, err := znstar.NewPaillierGroup(xNatPlus, yNatPlus)
	require.NoError(t, err)

	y1Int, err := crand.Int(prng, g.N().Big())
	require.NoError(t, err)
	y1 := numct.NewNatFromBig(y1Int, 256)
	var x1 numct.Nat
	g.Arithmetic().ExpToN(&x1, y1)

	y2Int, err := crand.Int(prng, g.N().Big())
	require.NoError(t, err)
	y2 := numct.NewNatFromBig(y2Int, 256)
	var x2 numct.Nat
	g.Arithmetic().ExpToN(&x2, y2)

	err = doInteractiveProof(&x1, y2, g, prng)
	require.Error(t, err)
	require.True(t, errs.IsVerification(err))

	err = doInteractiveProof(&x2, y1, g, prng)
	require.Error(t, err)
	require.True(t, errs.IsVerification(err))
}

func Test_HappyPathNonInteractive(t *testing.T) {
	t.Parallel()
	sessionId, err := network.NewSID([]byte("nthRootSession"))
	require.NoError(t, err)
	appLabel := "NthRoot"
	prng := crand.Reader
	pInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	p := numct.NewNatFromBig(pInt, 128)
	qInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	q := numct.NewNatFromBig(qInt, 128)

	xNatPlus, err := num.NPlus().FromNatCT(p)
	require.NoError(t, err)
	yNatPlus, err := num.NPlus().FromNatCT(q)
	require.NoError(t, err)

	g, err := znstar.NewPaillierGroup(xNatPlus, yNatPlus)
	require.NoError(t, err)

	protocol, err := nthroot.NewProtocol(g, prng)
	require.NoError(t, err)

	yInt, err := crand.Int(prng, g.N().Big())
	require.NoError(t, err)
	y := numct.NewNatFromBig(yInt, 256)
	var x numct.Nat
	g.Arithmetic().ExpToN(&x, y)

	xx, err := g.FromNatCT(&x)
	require.NoError(t, err)
	yy, err := g.FromNatCT(y)
	require.NoError(t, err)
	statement := nthroot.NewStatement(xx)
	witness := nthroot.NewWitness(yy)

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
	pInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	p := numct.NewNatFromBig(pInt, 128)
	qInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	q := numct.NewNatFromBig(qInt, 128)

	xNatPlus, err := num.NPlus().FromNatCT(p)
	require.NoError(t, err)
	yNatPlus, err := num.NPlus().FromNatCT(q)
	require.NoError(t, err)

	g, err := znstar.NewPaillierGroup(xNatPlus, yNatPlus)
	require.NoError(t, err)

	protocol, err := nthroot.NewProtocol(g, prng)
	require.NoError(t, err)

	y1Int, err := crand.Int(prng, g.N().Big())
	require.NoError(t, err)
	y1 := numct.NewNatFromBig(y1Int, 256)
	var x1 numct.Nat
	g.Arithmetic().ExpToN(&x1, y1)

	y2Int, err := crand.Int(prng, g.N().Big())
	require.NoError(t, err)
	y2 := numct.NewNatFromBig(y2Int, 256)
	var x2 numct.Nat
	g.Arithmetic().ExpToN(&x2, y2)

	xx1, err := g.FromNatCT(&x1)
	require.NoError(t, err)
	yy1, err := g.FromNatCT(y1)
	require.NoError(t, err)
	xx2, err := g.FromNatCT(&x2)
	require.NoError(t, err)
	yy2, err := g.FromNatCT(y2)
	require.NoError(t, err)

	fsProtocol, err := fiatshamir.NewCompiler(protocol)
	require.NoError(t, err)

	proverTranscript := hagrid.NewTranscript(appLabel)
	prover, err := fsProtocol.NewProver(sessionId, proverTranscript)
	require.NoError(t, err)

	verifierTranscript := hagrid.NewTranscript(appLabel)
	verifier, err := fsProtocol.NewVerifier(sessionId, verifierTranscript)
	require.NoError(t, err)

	statement1 := nthroot.NewStatement(xx1)
	witness2 := nthroot.NewWitness(yy2)
	proof1, err := prover.Prove(statement1, witness2)
	require.NoError(t, err)
	err = verifier.Verify(statement1, proof1)
	require.Error(t, err)
	require.True(t, errs.IsVerification(err))

	statement1 = nthroot.NewStatement(xx1)
	witness1 := nthroot.NewWitness(yy1)
	statement2 := nthroot.NewStatement(xx2)
	proof2, err := prover.Prove(statement1, witness1)
	require.NoError(t, err)
	err = verifier.Verify(statement2, proof2)
	require.Error(t, err)
	require.True(t, errs.IsVerification(err))

	statement2 = nthroot.NewStatement(xx2)
	witness2 = nthroot.NewWitness(yy2)
	proof3, err := prover.Prove(statement2, witness2)
	require.NoError(t, err)
	err = verifier.Verify(statement1, proof3)
	require.Error(t, err)
	require.True(t, errs.IsVerification(err))

	statement2 = nthroot.NewStatement(xx2)
	witness1 = nthroot.NewWitness(yy1)
	proof4, err := prover.Prove(statement2, witness1)
	require.NoError(t, err)
	err = verifier.Verify(statement2, proof4)
	require.Error(t, err)
	require.True(t, errs.IsVerification(err))
}

func Test_Simulator(t *testing.T) {
	t.Parallel()
	prng := crand.Reader
	pInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	p := numct.NewNatFromBig(pInt, 128)
	qInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	q := numct.NewNatFromBig(qInt, 128)

	xNatPlus, err := num.NPlus().FromNatCT(p)
	require.NoError(t, err)
	yNatPlus, err := num.NPlus().FromNatCT(q)
	require.NoError(t, err)

	g, err := znstar.NewPaillierGroup(xNatPlus, yNatPlus)
	require.NoError(t, err)

	yInt, err := crand.Int(prng, g.N().Big())
	require.NoError(t, err)
	y := numct.NewNatFromBig(yInt, 256)
	var x numct.Nat
	g.Arithmetic().ExpToN(&x, y)

	xx, err := g.FromNatCT(&x)
	require.NoError(t, err)

	protocol, err := nthroot.NewProtocol(g, prng)
	require.NoError(t, err)

	e := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, e)
	require.NoError(t, err)

	statement := nthroot.NewStatement(xx)
	a, z, err := protocol.RunSimulator(statement, e)
	require.NoError(t, err)

	err = protocol.Verify(statement, a, e, z)
	require.NoError(t, err)
}

func Test_Extractor(t *testing.T) {
	t.Parallel()
	prng := crand.Reader
	pInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	p := numct.NewNatFromBig(pInt, 128)
	qInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	q := numct.NewNatFromBig(qInt, 128)

	xNatPlus, err := num.NPlus().FromNatCT(p)
	require.NoError(t, err)
	yNatPlus, err := num.NPlus().FromNatCT(q)
	require.NoError(t, err)

	g, err := znstar.NewPaillierGroup(xNatPlus, yNatPlus)
	require.NoError(t, err)

	yInt, err := crand.Int(prng, g.N().Big())
	require.NoError(t, err)
	y := numct.NewNatFromBig(yInt, 256)
	var x numct.Nat
	g.Arithmetic().ExpToN(&x, y)

	protocol, err := nthroot.NewProtocol(g, prng)
	require.NoError(t, err)
	xx, err := g.FromNatCT(&x)
	require.NoError(t, err)
	yy, err := g.FromNatCT(y)
	require.NoError(t, err)

	witness := nthroot.NewWitness(yy)
	statement := nthroot.NewStatement(xx)
	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(t, err)

	challenge1 := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge1)
	require.NoError(t, err)
	response1, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge1)
	require.NoError(t, err)
	challenge2 := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge2)
	require.NoError(t, err)
	response2, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge2)
	require.NoError(t, err)

	ei := []sigma.ChallengeBytes{challenge1, challenge2}
	zi := []*nthroot.Response{response1, response2}
	extractedWitness, err := protocol.Extract(statement, commitment, ei, zi)
	require.NoError(t, err)
	require.True(t, witness.PreImage.Equal(extractedWitness.PreImage))

}

func doInteractiveProof(x, y *numct.Nat, g znstar.PaillierGroup, prng io.Reader) (err error) {
	sessionId := []byte("nthRootsSession")
	appLabel := "NthRoot"
	protocol, err := nthroot.NewProtocol(g, prng)
	if err != nil {
		return err
	}
	xx, err := g.FromNatCT(x)
	if err != nil {
		return err
	}
	yy, err := g.FromNatCT(y)
	if err != nil {
		return err
	}
	proverStatement := nthroot.NewStatement(xx)
	proverWitness := nthroot.NewWitness(yy)
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
	proverBytes, err := proverTranscript.ExtractBytes(label, 128)
	if err != nil {
		return err
	}
	verifierBytes, err := verifierTranscript.ExtractBytes(label, 128)
	if err != nil {
		return err
	}
	if !bytes.Equal(proverBytes, verifierBytes) {
		return errs.NewFailed("transcript record different data")
	}

	return nil
}
