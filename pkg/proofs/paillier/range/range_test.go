package paillierrange_test

import (
	crand "crypto/rand"
	"io"
	"math/big"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base"
	"github.com/bronlabs/krypton-primitives/pkg/indcpa/paillier"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/paillier/range"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma"
	fiatShamir "github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler/fischlin"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
	zkcompiler "github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler/zk"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts/hagrid"
)

const primeLen = 512
const logRange = 256

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	pk, sk, err := paillier.KeyGen(primeLen, prng)
	require.NoError(t, err)

	lBig := new(big.Int).SetBit(big.NewInt(0), logRange, 1)
	l := new(saferith.Nat).SetBig(lBig, lBig.BitLen())
	protocol, err := paillierrange.NewPaillierRange(base.StatisticalSecurity, prng)
	require.NoError(t, err)

	for range 128 {
		xBig, err := crand.Int(prng, lBig)
		require.NoError(t, err)
		x := new(saferith.Int).SetBig(xBig, xBig.BitLen())
		c, r, err := pk.Encrypt(x, prng)
		require.NoError(t, err)

		statement := &paillierrange.Statement{
			Pk: pk,
			C:  c,
			L:  l,
		}
		witness := &paillierrange.Witness{
			Sk: sk,
			X:  x,
			R:  r,
		}

		err = protocol.ValidateStatement(statement, witness)
		require.NoError(t, err)

		a, s, err := protocol.ComputeProverCommitment(statement, witness)
		require.NoError(t, err)

		e := make([]byte, protocol.GetChallengeBytesLength())
		_, err = io.ReadFull(prng, e)
		require.NoError(t, err)

		z, err := protocol.ComputeProverResponse(statement, witness, a, s, e)
		require.NoError(t, err)

		err = protocol.Verify(statement, a, e, z)
		require.NoError(t, err)
	}
}

func Test_CheatingProverBelowRange(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	pk, sk, err := paillier.KeyGen(primeLen, prng)
	require.NoError(t, err)

	lBig := new(big.Int).SetBit(big.NewInt(0), logRange, 1)
	l := new(saferith.Nat).SetBig(lBig, lBig.BitLen())
	protocol, err := paillierrange.NewPaillierRange(base.StatisticalSecurity, prng)
	require.NoError(t, err)

	lowBound := new(big.Int).Neg(lBig)

	for range 128 {
		shift, err := crand.Int(prng, lBig)
		require.NoError(t, err)
		xBig := new(big.Int).Sub(lowBound, shift)
		x := new(saferith.Int).SetBig(xBig, xBig.BitLen())
		c, r, err := pk.Encrypt(x, prng)
		require.NoError(t, err)

		statement := &paillierrange.Statement{
			Pk: pk,
			C:  c,
			L:  l,
		}
		witness := &paillierrange.Witness{
			Sk: sk,
			X:  x,
			R:  r,
		}

		// this must fail as witness is out of bound
		err = protocol.ValidateStatement(statement, witness)
		require.Error(t, err)

		a, s, err := protocol.ComputeProverCommitment(statement, witness)
		require.NoError(t, err)

		e := make([]byte, protocol.GetChallengeBytesLength())
		_, err = io.ReadFull(prng, e)
		require.NoError(t, err)

		z, err := protocol.ComputeProverResponse(statement, witness, a, s, e)
		require.NoError(t, err)

		// make sure cheating prover is caught
		err = protocol.Verify(statement, a, e, z)
		require.Error(t, err)
	}
}

func Test_CheatingProverAboveRange(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	pk, sk, err := paillier.KeyGen(primeLen, prng)
	require.NoError(t, err)

	lBig := new(big.Int).SetBit(big.NewInt(0), logRange, 1)
	l := new(saferith.Nat).SetBig(lBig, lBig.BitLen())
	protocol, err := paillierrange.NewPaillierRange(base.StatisticalSecurity, prng)
	require.NoError(t, err)

	highBound := new(big.Int).Add(lBig, lBig)

	for range 128 {
		shift, err := crand.Int(prng, lBig)
		require.NoError(t, err)
		xBig := new(big.Int).Add(highBound, shift)
		x := new(saferith.Int).SetBig(xBig, xBig.BitLen())
		c, r, err := pk.Encrypt(x, prng)
		require.NoError(t, err)

		statement := &paillierrange.Statement{
			Pk: pk,
			C:  c,
			L:  l,
		}
		witness := &paillierrange.Witness{
			Sk: sk,
			X:  x,
			R:  r,
		}

		// this must fail as witness is out of bound
		err = protocol.ValidateStatement(statement, witness)
		require.Error(t, err)

		a, s, err := protocol.ComputeProverCommitment(statement, witness)
		require.NoError(t, err)

		e := make([]byte, protocol.GetChallengeBytesLength())
		_, err = io.ReadFull(prng, e)
		require.NoError(t, err)

		z, err := protocol.ComputeProverResponse(statement, witness, a, s, e)
		require.NoError(t, err)

		// make sure cheating prover is caught
		err = protocol.Verify(statement, a, e, z)
		require.Error(t, err)
	}
}

func Test_Simulator(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	pk, sk, err := paillier.KeyGen(primeLen, prng)
	require.NoError(t, err)

	lBig := new(big.Int).SetBit(big.NewInt(0), logRange, 1)
	l := new(saferith.Nat).SetBig(lBig, lBig.BitLen())
	protocol, err := paillierrange.NewPaillierRange(base.StatisticalSecurity, prng)
	require.NoError(t, err)

	for range 128 {
		xBig, err := crand.Int(prng, lBig)
		require.NoError(t, err)
		x := new(saferith.Int).SetBig(xBig, xBig.BitLen())
		c, r, err := pk.Encrypt(x, prng)
		require.NoError(t, err)

		statement := &paillierrange.Statement{
			Pk: pk,
			C:  c,
			L:  l,
		}
		witness := &paillierrange.Witness{
			Sk: sk,
			X:  x,
			R:  r,
		}

		err = protocol.ValidateStatement(statement, witness)
		require.NoError(t, err)

		e := make([]byte, protocol.GetChallengeBytesLength())
		_, err = io.ReadFull(prng, e)
		require.NoError(t, err)
		a, z, err := protocol.RunSimulator(statement, e)
		require.NoError(t, err)

		err = protocol.Verify(statement, a, e, z)
		require.NoError(t, err)
	}
}

func Test_Interactive(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	pk, sk, err := paillier.KeyGen(primeLen, prng)
	require.NoError(t, err)

	lBig := new(big.Int).SetBit(big.NewInt(0), logRange, 1)
	l := new(saferith.Nat).SetBig(lBig, lBig.BitLen())
	protocol, err := paillierrange.NewPaillierRange(base.StatisticalSecurity, prng)
	require.NoError(t, err)

	for range 128 {
		xBig, err := crand.Int(prng, lBig)
		require.NoError(t, err)
		x := new(saferith.Int).SetBig(xBig, xBig.BitLen())
		c, r, err := pk.Encrypt(x, prng)
		require.NoError(t, err)

		statement := &paillierrange.Statement{
			Pk: pk,
			C:  c,
			L:  l,
		}
		witness := &paillierrange.Witness{
			Sk: sk,
			X:  x,
			R:  r,
		}

		sessionId := []byte("test sessionId")
		proverTranscript := hagrid.NewTranscript("test", prng)
		verifierTranscript := hagrid.NewTranscript("test", prng)

		prover, err := sigma.NewProver(sessionId, proverTranscript, protocol, statement, witness)
		require.NoError(t, err)
		verifier, err := sigma.NewVerifier(sessionId, verifierTranscript, protocol, statement, prng)
		require.NoError(t, err)

		r1Out, err := prover.Round1()
		require.NoError(t, err)
		r2Out, err := verifier.Round2(r1Out)
		require.NoError(t, err)
		r3Out, err := prover.Round3(r2Out)
		require.NoError(t, err)
		err = verifier.Verify(r3Out)
		require.NoError(t, err)

		proverBytes, err := proverTranscript.ExtractBytes("sigma", 32)
		require.NoError(t, err)
		verifierBytes, err := verifierTranscript.ExtractBytes("sigma", 32)
		require.NoError(t, err)
		require.Equal(t, proverBytes, verifierBytes)
	}
}

func Test_InteractiveZk(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	pk, sk, err := paillier.KeyGen(primeLen, prng)
	require.NoError(t, err)

	lBig := new(big.Int).SetBit(big.NewInt(0), logRange, 1)
	l := new(saferith.Nat).SetBig(lBig, lBig.BitLen())
	protocol, err := paillierrange.NewPaillierRange(base.StatisticalSecurity, prng)
	require.NoError(t, err)

	for range 128 {
		xBig, err := crand.Int(prng, lBig)
		require.NoError(t, err)
		x := new(saferith.Int).SetBig(xBig, xBig.BitLen())
		c, r, err := pk.Encrypt(x, prng)
		require.NoError(t, err)

		statement := &paillierrange.Statement{
			Pk: pk,
			C:  c,
			L:  l,
		}
		witness := &paillierrange.Witness{
			Sk: sk,
			X:  x,
			R:  r,
		}

		sessionId := []byte("test sessionId")
		proverTranscript := hagrid.NewTranscript("test", prng)
		verifierTranscript := hagrid.NewTranscript("test", prng)

		prover, err := zkcompiler.NewProver(sessionId, proverTranscript, protocol, statement, witness)
		require.NoError(t, err)
		verifier, err := zkcompiler.NewVerifier(sessionId, verifierTranscript, protocol, statement, prng)
		require.NoError(t, err)

		r1Out, err := verifier.Round1()
		require.NoError(t, err)
		r2Out, err := prover.Round2(r1Out)
		require.NoError(t, err)
		r3Out, err := verifier.Round3(r2Out)
		require.NoError(t, err)
		r4Out, err := prover.Round4(r3Out)
		require.NoError(t, err)
		err = verifier.Verify(r4Out)
		require.NoError(t, err)

		proverBytes, err := proverTranscript.ExtractBytes("sigma", 32)
		require.NoError(t, err)
		verifierBytes, err := verifierTranscript.ExtractBytes("sigma", 32)
		require.NoError(t, err)
		require.Equal(t, proverBytes, verifierBytes)
	}
}

func Test_NonInteractiveFiatShamir(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	pk, sk, err := paillier.KeyGen(primeLen, prng)
	require.NoError(t, err)

	lBig := new(big.Int).SetBit(big.NewInt(0), logRange, 1)
	l := new(saferith.Nat).SetBig(lBig, lBig.BitLen())
	protocol, err := paillierrange.NewPaillierRange(128, prng)
	require.NoError(t, err)

	xBig, err := crand.Int(prng, lBig)
	require.NoError(t, err)
	x := new(saferith.Int).SetBig(xBig, xBig.BitLen())
	c, r, err := pk.Encrypt(x, prng)
	require.NoError(t, err)

	statement := &paillierrange.Statement{
		Pk: pk,
		C:  c,
		L:  l,
	}
	witness := &paillierrange.Witness{
		Sk: sk,
		X:  x,
		R:  r,
	}

	compiler, err := fiatShamir.NewCompiler(protocol)
	require.NoError(t, err)

	sessionId := []byte("test sessionId")
	proverTranscript := hagrid.NewTranscript("test", prng)
	verifierTranscript := hagrid.NewTranscript("test", prng)

	niProver, err := compiler.NewProver(sessionId, proverTranscript)
	require.NoError(t, err)

	niVerifier, err := compiler.NewVerifier(sessionId, verifierTranscript)
	require.NoError(t, err)

	proof, err := niProver.Prove(statement, witness)
	require.NoError(t, err)

	err = niVerifier.Verify(statement, proof)
	require.NoError(t, err)

	proverBytes, err := proverTranscript.ExtractBytes("sigma", 32)
	require.NoError(t, err)
	verifierBytes, err := verifierTranscript.ExtractBytes("sigma", 32)
	require.NoError(t, err)
	require.Equal(t, proverBytes, verifierBytes)
}

func Test_NonInteractiveFischlin(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	pk, sk, err := paillier.KeyGen(primeLen, prng)
	require.NoError(t, err)

	lBig := new(big.Int).SetBit(big.NewInt(0), logRange, 1)
	l := new(saferith.Nat).SetBig(lBig, lBig.BitLen())
	protocol, err := paillierrange.NewPaillierRange(128, prng)
	require.NoError(t, err)

	xBig, err := crand.Int(prng, lBig)
	require.NoError(t, err)
	x := new(saferith.Int).SetBig(xBig, xBig.BitLen())
	c, r, err := pk.Encrypt(x, prng)
	require.NoError(t, err)

	statement := &paillierrange.Statement{
		Pk: pk,
		C:  c,
		L:  l,
	}
	witness := &paillierrange.Witness{
		Sk: sk,
		X:  x,
		R:  r,
	}

	compiler, err := fischlin.NewCompiler(protocol, 16, prng)
	require.NoError(t, err)

	sessionId := []byte("test sessionId")
	proverTranscript := hagrid.NewTranscript("test", prng)
	verifierTranscript := hagrid.NewTranscript("test", prng)

	niProver, err := compiler.NewProver(sessionId, proverTranscript)
	require.NoError(t, err)

	niVerifier, err := compiler.NewVerifier(sessionId, verifierTranscript)
	require.NoError(t, err)

	proof, err := niProver.Prove(statement, witness)
	require.NoError(t, err)

	err = niVerifier.Verify(statement, proof)
	require.NoError(t, err)

	proverBytes, err := proverTranscript.ExtractBytes("sigma", 32)
	require.NoError(t, err)
	verifierBytes, err := verifierTranscript.ExtractBytes("sigma", 32)
	require.NoError(t, err)
	require.Equal(t, proverBytes, verifierBytes)
}

func Test_NonInteractiveRandomisedFischlin(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	pk, sk, err := paillier.KeyGen(primeLen, prng)
	require.NoError(t, err)

	lBig := new(big.Int).SetBit(big.NewInt(0), logRange, 1)
	l := new(saferith.Nat).SetBig(lBig, lBig.BitLen())
	protocol, err := paillierrange.NewPaillierRange(base.ComputationalSecurity, prng)
	require.NoError(t, err)

	xBig, err := crand.Int(prng, lBig)
	require.NoError(t, err)
	x := new(saferith.Int).SetBig(xBig, xBig.BitLen())
	c, r, err := pk.Encrypt(x, prng)
	require.NoError(t, err)

	statement := &paillierrange.Statement{
		Pk: pk,
		C:  c,
		L:  l,
	}
	witness := &paillierrange.Witness{
		Sk: sk,
		X:  x,
		R:  r,
	}

	compiler, err := randfischlin.NewCompiler(protocol, prng)
	require.NoError(t, err)

	sessionId := []byte("test sessionId")
	proverTranscript := hagrid.NewTranscript("test", prng)
	verifierTranscript := hagrid.NewTranscript("test", prng)

	niProver, err := compiler.NewProver(sessionId, proverTranscript)
	require.NoError(t, err)

	niVerifier, err := compiler.NewVerifier(sessionId, verifierTranscript)
	require.NoError(t, err)

	proof, err := niProver.Prove(statement, witness)
	require.NoError(t, err)

	err = niVerifier.Verify(statement, proof)
	require.NoError(t, err)

	proverBytes, err := proverTranscript.ExtractBytes("sigma", 32)
	require.NoError(t, err)
	verifierBytes, err := verifierTranscript.ExtractBytes("sigma", 32)
	require.NoError(t, err)
	require.Equal(t, proverBytes, verifierBytes)
}
