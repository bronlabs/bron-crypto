package enc_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/enc"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
)

const testKeyLen = 1024

func TestFiatShamirHappyPath(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	sk, err := paillier.SampleSecretKey(testKeyLen, prng)
	require.NoError(t, err)
	ringPedersenKey, err := intcom.SampleCommitmentKey(testKeyLen, prng)
	require.NoError(t, err)

	const rangeBits = 256
	const slackBits = 2 * rangeBits
	protocol, err := enc.NewProtocol(sk.Public(), ringPedersenKey, rangeBits, slackBits, prng)
	require.NoError(t, err)

	kInt, err := randomSignedBits(rangeBits, prng)
	require.NoError(t, err)
	k, err := paillier.NewPlaintextSymmetric(kInt, sk.PlaintextGroup().Modulus())
	require.NoError(t, err)
	bigK, rho, err := encryption.Encrypt(k, sk.Public(), prng)
	require.NoError(t, err)

	statement, err := enc.NewStatement(bigK)
	require.NoError(t, err)
	witness, err := enc.NewWitness(k, rho)
	require.NoError(t, err)
	require.NoError(t, protocol.ValidateStatement(statement, witness))

	compiler, err := fiatshamir.NewCompiler(protocol)
	require.NoError(t, err)

	const proverID = 1
	const verifierID = 2
	quorum := hashset.NewComparable[sharing.ID](proverID, verifierID).Freeze()
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)

	prover, err := compiler.NewProver(ctxs[proverID])
	require.NoError(t, err)
	verifier, err := compiler.NewVerifier(ctxs[verifierID])
	require.NoError(t, err)

	proof, err := prover.Prove(statement, witness)
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(statement, proof))

	proverBytes, err := ctxs[proverID].Transcript().ExtractBytes("sigma", 32)
	require.NoError(t, err)
	verifierBytes, err := ctxs[verifierID].Transcript().ExtractBytes("sigma", 32)
	require.NoError(t, err)
	require.Equal(t, proverBytes, verifierBytes)
}

func TestConstructorsRejectNilInputs(t *testing.T) {
	t.Parallel()

	statement, err := enc.NewStatement(nil)
	require.Error(t, err)
	require.Nil(t, statement)

	witness, err := enc.NewWitness(nil, nil)
	require.Error(t, err)
	require.Nil(t, witness)

	commitment, err := enc.NewCommitment(nil, nil, nil)
	require.Error(t, err)
	require.Nil(t, commitment)

	state, err := enc.NewState(nil, nil, nil, nil)
	require.Error(t, err)
	require.Nil(t, state)

	response, err := enc.NewResponse(nil, nil, nil)
	require.Error(t, err)
	require.Nil(t, response)
}

func TestCBORRoundTrip(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	sk, err := paillier.SampleSecretKey(testKeyLen, prng)
	require.NoError(t, err)
	ringPedersenKey, err := intcom.SampleCommitmentKey(testKeyLen, prng)
	require.NoError(t, err)

	const rangeBits = 256
	const slackBits = 2 * rangeBits
	protocol, err := enc.NewProtocol(sk.Public(), ringPedersenKey, rangeBits, slackBits, prng)
	require.NoError(t, err)

	kInt, err := randomSignedBits(rangeBits, prng)
	require.NoError(t, err)
	k, err := paillier.NewPlaintextSymmetric(kInt, sk.PlaintextGroup().Modulus())
	require.NoError(t, err)
	bigK, rho, err := encryption.Encrypt(k, sk.Public(), prng)
	require.NoError(t, err)

	statement, err := enc.NewStatement(bigK)
	require.NoError(t, err)
	witness, err := enc.NewWitness(k, rho)
	require.NoError(t, err)

	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(t, err)
	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge)
	require.NoError(t, err)
	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(t, err)

	statementData, err := serde.MarshalCBOR(statement)
	require.NoError(t, err)
	decodedStatement, err := serde.UnmarshalCBOR[*enc.Statement](statementData)
	require.NoError(t, err)
	require.Equal(t, statement.Bytes(), decodedStatement.Bytes())

	commitmentData, err := serde.MarshalCBOR(commitment)
	require.NoError(t, err)
	decodedCommitment, err := serde.UnmarshalCBOR[*enc.Commitment](commitmentData)
	require.NoError(t, err)
	require.Equal(t, commitment.Bytes(), decodedCommitment.Bytes())

	responseData, err := serde.MarshalCBOR(response)
	require.NoError(t, err)
	decodedResponse, err := serde.UnmarshalCBOR[*enc.Response](responseData)
	require.NoError(t, err)
	require.Equal(t, response.Bytes(), decodedResponse.Bytes())
	require.NoError(t, protocol.Verify(decodedStatement, decodedCommitment, challenge, decodedResponse))
}

func TestSimulator(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	sk, err := paillier.SampleSecretKey(testKeyLen, prng)
	require.NoError(t, err)
	ringPedersenKey, err := intcom.SampleCommitmentKey(testKeyLen, prng)
	require.NoError(t, err)

	const rangeBits = base.ComputationalSecurityBits
	const slackBits = 2 * rangeBits
	protocol, err := enc.NewProtocol(sk.Public(), ringPedersenKey, rangeBits, slackBits, prng)
	require.NoError(t, err)

	kInt, err := randomSignedBits(rangeBits, prng)
	require.NoError(t, err)
	k, err := paillier.NewPlaintextSymmetric(kInt, sk.PlaintextGroup().Modulus())
	require.NoError(t, err)
	bigK, _, err := encryption.Encrypt(k, sk.Public(), prng)
	require.NoError(t, err)
	statement, err := enc.NewStatement(bigK)
	require.NoError(t, err)

	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge)
	require.NoError(t, err)

	commitment, response, err := protocol.RunSimulator(statement, challenge)
	require.NoError(t, err)
	require.NotNil(t, commitment)
	require.NotNil(t, response)
	require.NoError(t, protocol.Verify(statement, commitment, challenge, response))
}

func randomSignedBits(bits int, prng io.Reader) (*num.Int, error) {
	outBytes := make([]byte, bits/8)
	if _, err := io.ReadFull(prng, outBytes); err != nil {
		return nil, err
	}
	return num.Z().FromTwosComplementBytesBE(outBytes)
}
