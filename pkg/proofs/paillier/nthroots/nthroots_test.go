package nthroots_test

import (
	"bytes"
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/modular"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/paillier/nthroots"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts/hagrid"
)

func Test_HappyPathInteractive(t *testing.T) {
	t.Parallel()
	prng := crand.Reader
	pInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	p := new(saferith.Nat).SetBig(pInt, 128)
	qInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	q := new(saferith.Nat).SetBig(qInt, 128)
	bigN, err := modular.NewFastModulusFromPrimeFactors(p, q)
	require.NoError(t, err)
	bigNSquared := saferith.ModulusFromNat(new(saferith.Nat).Mul(bigN.Modulus().Nat(), bigN.Modulus().Nat(), -1))

	yInt, err := crand.Int(prng, bigN.Modulus().Big())
	require.NoError(t, err)
	y := new(saferith.Nat).SetBig(yInt, 256)
	x := new(saferith.Nat).Exp(y, bigN.Modulus().Nat(), bigNSquared)

	err = doInteractiveProof(x, y, bigN, prng)
	require.NoError(t, err)
}

func Test_InvalidRootInteractive(t *testing.T) {
	t.Parallel()
	prng := crand.Reader
	pInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	p := new(saferith.Nat).SetBig(pInt, 128)
	qInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	q := new(saferith.Nat).SetBig(qInt, 128)
	bigN, err := modular.NewFastModulusFromPrimeFactors(p, q)
	require.NoError(t, err)
	bigNSquared := saferith.ModulusFromNat(new(saferith.Nat).Mul(bigN.Modulus().Nat(), bigN.Modulus().Nat(), -1))

	y1Int, err := crand.Int(prng, bigN.Modulus().Big())
	require.NoError(t, err)
	y1 := new(saferith.Nat).SetBig(y1Int, 256)
	x1 := new(saferith.Nat).Exp(y1, bigN.Modulus().Nat(), bigNSquared)

	y2Int, err := crand.Int(prng, bigN.Modulus().Big())
	require.NoError(t, err)
	y2 := new(saferith.Nat).SetBig(y2Int, 256)
	x2 := new(saferith.Nat).Exp(y2, bigN.Modulus().Nat(), bigNSquared)

	err = doInteractiveProof(x1, y2, bigN, prng)
	require.Error(t, err)
	require.True(t, errs.IsVerification(err))

	err = doInteractiveProof(x2, y1, bigN, prng)
	require.Error(t, err)
	require.True(t, errs.IsVerification(err))
}

func Test_HappyPathNonInteractive(t *testing.T) {
	t.Parallel()
	sessionId := []byte("nthRootSession")
	appLabel := "NthRoot"
	prng := crand.Reader
	pInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	p := new(saferith.Nat).SetBig(pInt, 128)
	qInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	q := new(saferith.Nat).SetBig(qInt, 128)
	bigN, err := modular.NewFastModulusFromPrimeFactors(p, q)
	require.NoError(t, err)
	bigNSquared := saferith.ModulusFromNat(new(saferith.Nat).Mul(bigN.Modulus().Nat(), bigN.Modulus().Nat(), -1))
	protocol, err := nthroots.NewSigmaProtocol(bigN, 1, prng)
	require.NoError(t, err)

	yInt, err := crand.Int(prng, bigN.Modulus().Big())
	require.NoError(t, err)
	y := new(saferith.Nat).SetBig(yInt, 256)
	x := new(saferith.Nat).Exp(y, bigN.Modulus().Nat(), bigNSquared)

	fsProtocol, err := fiatshamir.NewCompiler(protocol)
	require.NoError(t, err)

	proverTranscript := hagrid.NewTranscript(appLabel, prng)
	prover, err := fsProtocol.NewProver(sessionId, proverTranscript)
	require.NoError(t, err)

	verifierTranscript := hagrid.NewTranscript(appLabel, prng)
	verifier, err := fsProtocol.NewVerifier(sessionId, verifierTranscript)
	require.NoError(t, err)

	theProof, err := prover.Prove([]*saferith.Nat{x}, []*saferith.Nat{y})
	require.NoError(t, err)

	err = verifier.Verify([]*saferith.Nat{x}, theProof)
	require.NoError(t, err)
}

func Test_InvalidRootNonInteractive(t *testing.T) {
	t.Parallel()
	sessionId := []byte("nthRootSession")
	appLabel := "NthRoot"
	prng := crand.Reader
	pInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	p := new(saferith.Nat).SetBig(pInt, 128)
	qInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	q := new(saferith.Nat).SetBig(qInt, 128)
	bigN, err := modular.NewFastModulusFromPrimeFactors(p, q)
	require.NoError(t, err)
	nn := saferith.ModulusFromNat(new(saferith.Nat).Mul(bigN.Modulus().Nat(), bigN.Modulus().Nat(), -1))
	protocol, err := nthroots.NewSigmaProtocol(bigN, 1, prng)
	require.NoError(t, err)

	y1Int, err := crand.Int(prng, bigN.Modulus().Big())
	require.NoError(t, err)
	y1 := new(saferith.Nat).SetBig(y1Int, 256)
	x1 := new(saferith.Nat).Exp(y1, bigN.Modulus().Nat(), nn)

	y2Int, err := crand.Int(prng, bigN.Modulus().Nat().Big())
	require.NoError(t, err)
	y2 := new(saferith.Nat).SetBig(y2Int, 256)
	x2 := new(saferith.Nat).Exp(y2, bigN.Modulus().Nat(), nn)

	fsProtocol, err := fiatshamir.NewCompiler(protocol)
	require.NoError(t, err)

	proverTranscript := hagrid.NewTranscript(appLabel, prng)
	prover, err := fsProtocol.NewProver(sessionId, proverTranscript)
	require.NoError(t, err)

	verifierTranscript := hagrid.NewTranscript(appLabel, prng)
	verifier, err := fsProtocol.NewVerifier(sessionId, verifierTranscript)
	require.NoError(t, err)

	proof1, err := prover.Prove([]*saferith.Nat{x1}, []*saferith.Nat{y2})
	require.NoError(t, err)
	err = verifier.Verify([]*saferith.Nat{x1}, proof1)
	require.Error(t, err)
	require.True(t, errs.IsVerification(err))

	proof2, err := prover.Prove([]*saferith.Nat{x1}, []*saferith.Nat{y1})
	require.NoError(t, err)
	err = verifier.Verify([]*saferith.Nat{x2}, proof2)
	require.Error(t, err)
	require.True(t, errs.IsVerification(err))

	proof3, err := prover.Prove([]*saferith.Nat{x2}, []*saferith.Nat{y2})
	require.NoError(t, err)
	err = verifier.Verify([]*saferith.Nat{x1}, proof3)
	require.Error(t, err)
	require.True(t, errs.IsVerification(err))

	proof4, err := prover.Prove([]*saferith.Nat{x2}, []*saferith.Nat{y1})
	require.NoError(t, err)
	err = verifier.Verify([]*saferith.Nat{x2}, proof4)
	require.Error(t, err)
	require.True(t, errs.IsVerification(err))
}

func Test_Simulator(t *testing.T) {
	t.Parallel()
	prng := crand.Reader
	pInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	p := new(saferith.Nat).SetBig(pInt, 128)
	qInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	q := new(saferith.Nat).SetBig(qInt, 128)
	bigN, err := modular.NewFastModulusFromPrimeFactors(p, q)
	require.NoError(t, err)
	bigNSquared := saferith.ModulusFromNat(new(saferith.Nat).Mul(bigN.Modulus().Nat(), bigN.Modulus().Nat(), -1))
	yInt, err := crand.Int(prng, bigN.Modulus().Big())
	require.NoError(t, err)
	y := new(saferith.Nat).SetBig(yInt, 256)
	x := new(saferith.Nat).Exp(y, bigN.Modulus().Nat(), bigNSquared)

	protocol, err := nthroots.NewSigmaProtocol(bigN, 1, prng)
	require.NoError(t, err)

	e := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, e)
	require.NoError(t, err)

	a, z, err := protocol.RunSimulator([]*saferith.Nat{x}, e)
	require.NoError(t, err)

	err = protocol.Verify([]*saferith.Nat{x}, a, e, z)
	require.NoError(t, err)
}

func doInteractiveProof(x, y *saferith.Nat, bigN modular.FastModulus, prng io.Reader) (err error) {
	sessionId := []byte("nthRootsSession")
	appLabel := "NthRoot"
	protocol, err := nthroots.NewSigmaProtocol(bigN, 1, prng)
	if err != nil {
		return err
	}
	proverTranscript := hagrid.NewTranscript(appLabel, nil)
	prover, err := sigma.NewProver(sessionId, proverTranscript, protocol, []*saferith.Nat{x}, []*saferith.Nat{y})
	if err != nil {
		return err
	}

	verifierTranscript := hagrid.NewTranscript(appLabel, nil)
	verifier, err := sigma.NewVerifier(sessionId, verifierTranscript, protocol, []*saferith.Nat{x}, prng)
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
