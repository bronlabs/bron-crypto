//go:debug rsa1024min=0
package paillierrange_test

import (
	crand "crypto/rand"
	"io"
	"math/big"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/network"
	paillierrange "github.com/bronlabs/bron-crypto/pkg/proofs/paillier/range"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/zk"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

const logRange = 256
const keyLen = 512

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	scheme := paillier.NewScheme()
	keyGenerator, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, pk, err := keyGenerator.Generate(prng)
	require.NoError(t, err)

	lBig := new(big.Int).SetBit(big.NewInt(0), logRange, 1)
	l := numct.NewNatFromSaferith((new(saferith.Nat).SetBig(lBig, lBig.BitLen())))
	protocol, err := paillierrange.NewPaillierRange(base.StatisticalSecurityBits, prng)
	require.NoError(t, err)

	enc, err := scheme.Encrypter()
	require.NoError(t, err)

	ps := sk.PublicKey().PlaintextSpace()
	xBig, err := crand.Int(prng, lBig)
	require.NoError(t, err)
	x, err := ps.FromNat(numct.NewNatFromSaferith((new(saferith.Nat).SetBig(xBig, xBig.BitLen()))))
	require.NoError(t, err)
	c, r, err := enc.Encrypt(x, pk, prng)
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

func Test_CheatingProverBelowRange(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	scheme := paillier.NewScheme()
	keyGenerator, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, pk, err := keyGenerator.Generate(prng)
	require.NoError(t, err)

	lBig := new(big.Int).SetBit(big.NewInt(0), logRange, 1)
	l := numct.NewNatFromSaferith((new(saferith.Nat).SetBig(lBig, lBig.BitLen())))
	protocol, err := paillierrange.NewPaillierRange(base.StatisticalSecurityBits, prng)
	require.NoError(t, err)

	lowBound := new(big.Int).Neg(lBig)

	enc, err := scheme.Encrypter()
	require.NoError(t, err)

	shift, err := crand.Int(prng, lBig)
	require.NoError(t, err)
	xBig := new(big.Int).Sub(lowBound, shift)
	x, err := sk.PublicKey().PlaintextSpace().FromInt(numct.NewIntFromSaferith(new(saferith.Int).SetBig(xBig, xBig.BitLen())))
	require.NoError(t, err)
	c, r, err := enc.Encrypt(x, pk, prng)
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

	// this must fail as the witness is out of bound
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

func Test_CheatingProverAboveRange(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	scheme := paillier.NewScheme()
	keyGenerator, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, pk, err := keyGenerator.Generate(prng)
	require.NoError(t, err)

	lBig := new(big.Int).SetBit(big.NewInt(0), logRange, 1)
	l := numct.NewNatFromSaferith((new(saferith.Nat).SetBig(lBig, lBig.BitLen())))
	protocol, err := paillierrange.NewPaillierRange(base.StatisticalSecurityBits, prng)
	require.NoError(t, err)

	highBound := new(big.Int).Add(lBig, lBig)

	enc, err := scheme.Encrypter()
	require.NoError(t, err)

	shift, err := crand.Int(prng, lBig)
	require.NoError(t, err)
	xBig := new(big.Int).Add(highBound, shift)
	x, err := sk.PublicKey().PlaintextSpace().FromInt(numct.NewIntFromSaferith(new(saferith.Int).SetBig(xBig, xBig.BitLen())))
	require.NoError(t, err)
	c, r, err := enc.Encrypt(x, pk, prng)
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

func Test_Simulator(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	scheme := paillier.NewScheme()
	keyGenerator, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, pk, err := keyGenerator.Generate(prng)
	require.NoError(t, err)

	lBig := new(big.Int).SetBit(big.NewInt(0), logRange, 1)
	l := numct.NewNatFromSaferith((new(saferith.Nat).SetBig(lBig, lBig.BitLen())))
	protocol, err := paillierrange.NewPaillierRange(base.StatisticalSecurityBits, prng)
	require.NoError(t, err)

	enc, err := scheme.Encrypter()
	require.NoError(t, err)

	xBig, err := crand.Int(prng, lBig)
	require.NoError(t, err)
	x, err := sk.PublicKey().PlaintextSpace().FromInt(numct.NewIntFromSaferith(new(saferith.Int).SetBig(xBig, xBig.BitLen())))
	require.NoError(t, err)
	c, r, err := enc.Encrypt(x, pk, prng)
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

func Test_Interactive(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	scheme := paillier.NewScheme()
	keyGenerator, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, pk, err := keyGenerator.Generate(prng)
	require.NoError(t, err)

	lBig := new(big.Int).SetBit(big.NewInt(0), logRange, 1)
	l := numct.NewNatFromSaferith((new(saferith.Nat).SetBig(lBig, lBig.BitLen())))
	protocol, err := paillierrange.NewPaillierRange(base.StatisticalSecurityBits, prng)
	require.NoError(t, err)

	enc, err := scheme.Encrypter()
	require.NoError(t, err)

	xBig, err := crand.Int(prng, lBig)
	require.NoError(t, err)
	x, err := sk.PublicKey().PlaintextSpace().FromInt(numct.NewIntFromSaferith(new(saferith.Int).SetBig(xBig, xBig.BitLen())))
	require.NoError(t, err)
	c, r, err := enc.Encrypt(x, pk, prng)
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

	var sessionID network.SID
	copy(sessionID[:], "test sessionID")
	proverTranscript := hagrid.NewTranscript("test")
	verifierTranscript := hagrid.NewTranscript("test")

	prover, err := sigma.NewProver(sessionID, proverTranscript, protocol, statement, witness)
	require.NoError(t, err)
	verifier, err := sigma.NewVerifier(sessionID, verifierTranscript, protocol, statement, prng)
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

func Test_InteractiveZk(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	scheme := paillier.NewScheme()
	keyGenerator, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, pk, err := keyGenerator.Generate(prng)
	require.NoError(t, err)

	lBig := new(big.Int).SetBit(big.NewInt(0), logRange, 1)
	l := numct.NewNatFromSaferith((new(saferith.Nat).SetBig(lBig, lBig.BitLen())))
	protocol, err := paillierrange.NewPaillierRange(base.StatisticalSecurityBits, prng)
	require.NoError(t, err)

	enc, err := scheme.Encrypter()
	require.NoError(t, err)

	xBig, err := crand.Int(prng, lBig)
	require.NoError(t, err)
	x, err := sk.PublicKey().PlaintextSpace().FromInt(numct.NewIntFromSaferith(new(saferith.Int).SetBig(xBig, xBig.BitLen())))
	require.NoError(t, err)
	c, r, err := enc.Encrypt(x, pk, prng)
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

	sessionID, err := network.NewSID([]byte("test sessionID"))
	require.NoError(t, err)
	proverTranscript := hagrid.NewTranscript("test")
	verifierTranscript := hagrid.NewTranscript("test")

	prover, err := zk.NewProver(sessionID, proverTranscript, protocol, statement, witness)
	require.NoError(t, err)
	verifier, err := zk.NewVerifier(sessionID, verifierTranscript, protocol, statement, prng)
	require.NoError(t, err)

	r1Out, err := verifier.Round1()
	require.NoError(t, err)
	r2Out, err := prover.Round2(r1Out)
	require.NoError(t, err)
	r3Out1, r3Out2, err := verifier.Round3(r2Out)
	require.NoError(t, err)
	r4Out, err := prover.Round4(r3Out1, r3Out2)
	require.NoError(t, err)
	err = verifier.Verify(r4Out)
	require.NoError(t, err)

	proverBytes, err := proverTranscript.ExtractBytes("sigma", 32)
	require.NoError(t, err)
	verifierBytes, err := verifierTranscript.ExtractBytes("sigma", 32)
	require.NoError(t, err)
	require.Equal(t, proverBytes, verifierBytes)
}

func Test_NonInteractiveFiatShamir(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	scheme := paillier.NewScheme()
	keyGenerator, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, pk, err := keyGenerator.Generate(prng)
	require.NoError(t, err)

	lBig := new(big.Int).SetBit(big.NewInt(0), logRange, 1)
	l := numct.NewNatFromSaferith((new(saferith.Nat).SetBig(lBig, lBig.BitLen())))
	protocol, err := paillierrange.NewPaillierRange(base.ComputationalSecurityBits, prng)
	require.NoError(t, err)

	enc, err := scheme.Encrypter()
	require.NoError(t, err)

	xBig, err := crand.Int(prng, lBig)
	require.NoError(t, err)
	x, err := sk.PublicKey().PlaintextSpace().FromInt(numct.NewIntFromSaferith(new(saferith.Int).SetBig(xBig, xBig.BitLen())))
	require.NoError(t, err)
	c, r, err := enc.Encrypt(x, pk, prng)
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

	compiler, err := fiatshamir.NewCompiler(protocol)
	require.NoError(t, err)

	sessionID, err := network.NewSID([]byte("test sessionID"))
	require.NoError(t, err)
	proverTranscript := hagrid.NewTranscript("test")
	verifierTranscript := hagrid.NewTranscript("test")

	niProver, err := compiler.NewProver(sessionID, proverTranscript)
	require.NoError(t, err)

	niVerifier, err := compiler.NewVerifier(sessionID, verifierTranscript)
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
