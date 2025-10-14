package nthroots_test

import (
	"bytes"
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/nthroots"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
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

// func Test_InvalidRootInteractive(t *testing.T) {
// 	t.Parallel()
// 	prng := crand.Reader
// 	pInt, err := crand.Prime(prng, 128)
// 	require.NoError(t, err)
// 	p := new(saferith.Nat).SetBig(pInt, 128)
// 	qInt, err := crand.Prime(prng, 128)
// 	require.NoError(t, err)
// 	q := new(saferith.Nat).SetBig(qInt, 128)
// 	bigN, err := modular.NewFastModulusFromPrimeFactors(p, q)
// 	require.NoError(t, err)
// 	bigNSquared := saferith.ModulusFromNat(new(saferith.Nat).Mul(bigN.Modulus().Nat(), bigN.Modulus().Nat(), -1))

// 	y1Int, err := crand.Int(prng, bigN.Modulus().Big())
// 	require.NoError(t, err)
// 	y1 := new(saferith.Nat).SetBig(y1Int, 256)
// 	x1 := new(saferith.Nat).Exp(y1, bigN.Modulus().Nat(), bigNSquared)

// 	y2Int, err := crand.Int(prng, bigN.Modulus().Big())
// 	require.NoError(t, err)
// 	y2 := new(saferith.Nat).SetBig(y2Int, 256)
// 	x2 := new(saferith.Nat).Exp(y2, bigN.Modulus().Nat(), bigNSquared)

// 	err = doInteractiveProof(x1, y2, bigN, prng)
// 	require.Error(t, err)
// 	require.True(t, errs.IsVerification(err))

// 	err = doInteractiveProof(x2, y1, bigN, prng)
// 	require.Error(t, err)
// 	require.True(t, errs.IsVerification(err))
// }

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

	protocol, err := nthroots.NewSigmaProtocol(g, prng)
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
	statement := nthroots.NewStatement(xx)
	witness := nthroots.NewWitness(yy)

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

// func Test_InvalidRootNonInteractive(t *testing.T) {
// 	t.Parallel()
// 	sessionId := []byte("nthRootSession")
// 	appLabel := "NthRoot"
// 	prng := crand.Reader
// 	pInt, err := crand.Prime(prng, 128)
// 	require.NoError(t, err)
// 	p := new(saferith.Nat).SetBig(pInt, 128)
// 	qInt, err := crand.Prime(prng, 128)
// 	require.NoError(t, err)
// 	q := new(saferith.Nat).SetBig(qInt, 128)
// 	bigN, err := modular.NewFastModulusFromPrimeFactors(p, q)
// 	require.NoError(t, err)
// 	nn := saferith.ModulusFromNat(new(saferith.Nat).Mul(bigN.Modulus().Nat(), bigN.Modulus().Nat(), -1))
// 	protocol, err := nthroots.NewSigmaProtocol(bigN, 1, prng)
// 	require.NoError(t, err)

// 	y1Int, err := crand.Int(prng, bigN.Modulus().Big())
// 	require.NoError(t, err)
// 	y1 := new(saferith.Nat).SetBig(y1Int, 256)
// 	x1 := new(saferith.Nat).Exp(y1, bigN.Modulus().Nat(), nn)

// 	y2Int, err := crand.Int(prng, bigN.Modulus().Nat().Big())
// 	require.NoError(t, err)
// 	y2 := new(saferith.Nat).SetBig(y2Int, 256)
// 	x2 := new(saferith.Nat).Exp(y2, bigN.Modulus().Nat(), nn)

// 	fsProtocol, err := fiatshamir.NewCompiler(protocol)
// 	require.NoError(t, err)

// 	proverTranscript := hagrid.NewTranscript(appLabel, prng)
// 	prover, err := fsProtocol.NewProver(sessionId, proverTranscript)
// 	require.NoError(t, err)

// 	verifierTranscript := hagrid.NewTranscript(appLabel, prng)
// 	verifier, err := fsProtocol.NewVerifier(sessionId, verifierTranscript)
// 	require.NoError(t, err)

// 	proof1, err := prover.Prove([]*saferith.Nat{x1}, []*saferith.Nat{y2})
// 	require.NoError(t, err)
// 	err = verifier.Verify([]*saferith.Nat{x1}, proof1)
// 	require.Error(t, err)
// 	require.True(t, errs.IsVerification(err))

// 	proof2, err := prover.Prove([]*saferith.Nat{x1}, []*saferith.Nat{y1})
// 	require.NoError(t, err)
// 	err = verifier.Verify([]*saferith.Nat{x2}, proof2)
// 	require.Error(t, err)
// 	require.True(t, errs.IsVerification(err))

// 	proof3, err := prover.Prove([]*saferith.Nat{x2}, []*saferith.Nat{y2})
// 	require.NoError(t, err)
// 	err = verifier.Verify([]*saferith.Nat{x1}, proof3)
// 	require.Error(t, err)
// 	require.True(t, errs.IsVerification(err))

// 	proof4, err := prover.Prove([]*saferith.Nat{x2}, []*saferith.Nat{y1})
// 	require.NoError(t, err)
// 	err = verifier.Verify([]*saferith.Nat{x2}, proof4)
// 	require.Error(t, err)
// 	require.True(t, errs.IsVerification(err))
// }

// func Test_Simulator(t *testing.T) {
// 	t.Parallel()
// 	prng := crand.Reader
// 	pInt, err := crand.Prime(prng, 128)
// 	require.NoError(t, err)
// 	p := new(saferith.Nat).SetBig(pInt, 128)
// 	qInt, err := crand.Prime(prng, 128)
// 	require.NoError(t, err)
// 	q := new(saferith.Nat).SetBig(qInt, 128)
// 	bigN, err := modular.NewFastModulusFromPrimeFactors(p, q)
// 	require.NoError(t, err)
// 	bigNSquared := saferith.ModulusFromNat(new(saferith.Nat).Mul(bigN.Modulus().Nat(), bigN.Modulus().Nat(), -1))
// 	yInt, err := crand.Int(prng, bigN.Modulus().Big())
// 	require.NoError(t, err)
// 	y := new(saferith.Nat).SetBig(yInt, 256)
// 	x := new(saferith.Nat).Exp(y, bigN.Modulus().Nat(), bigNSquared)

// 	protocol, err := nthroots.NewSigmaProtocol(bigN, 1, prng)
// 	require.NoError(t, err)

// 	e := make([]byte, protocol.GetChallengeBytesLength())
// 	_, err = io.ReadFull(prng, e)
// 	require.NoError(t, err)

// 	a, z, err := protocol.RunSimulator([]*saferith.Nat{x}, e)
// 	require.NoError(t, err)

// 	err = protocol.Verify([]*saferith.Nat{x}, a, e, z)
// 	require.NoError(t, err)
// }

func doInteractiveProof(x, y *numct.Nat, g znstar.PaillierGroup, prng io.Reader) (err error) {
	sessionId := []byte("nthRootsSession")
	appLabel := "NthRoot"
	protocol, err := nthroots.NewSigmaProtocol(g, prng)
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
	proverStatement := nthroots.NewStatement(xx)
	proverWitness := nthroots.NewWitness(yy)
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
