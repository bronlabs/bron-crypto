package sigma_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

type testStatement []byte
type testWitness []byte
type testCommitment []byte
type testResponse []byte
type testState struct{}

func (t testStatement) Bytes() []byte  { return []byte(t) }
func (t testWitness) Bytes() []byte    { return []byte(t) }
func (t testCommitment) Bytes() []byte { return []byte(t) }
func (t testResponse) Bytes() []byte   { return []byte(t) }

type testProtocol struct{}

func (testProtocol) Name() sigma.Name { return "test" }
func (testProtocol) ComputeProverCommitment(testStatement, testWitness) (testCommitment, testState, error) {
	return testCommitment("commitment"), testState{}, nil
}
func (testProtocol) ComputeProverResponse(testStatement, testWitness, testCommitment, testState, sigma.ChallengeBytes) (testResponse, error) {
	return testResponse("response"), nil
}
func (testProtocol) Verify(testStatement, testCommitment, sigma.ChallengeBytes, testResponse) error {
	return nil
}
func (testProtocol) RunSimulator(testStatement, sigma.ChallengeBytes) (testCommitment, testResponse, error) {
	return testCommitment("commitment"), testResponse("response"), nil
}
func (testProtocol) SpecialSoundness() uint       { return 2 }
func (testProtocol) SoundnessError() uint         { return base.StatisticalSecurityBits }
func (testProtocol) GetChallengeBytesLength() int { return 1 }
func (testProtocol) ValidateStatement(testStatement, testWitness) error {
	return nil
}

func TestNewVerifierRejectsNilPRNG(t *testing.T) {
	t.Parallel()

	quorum := hashset.NewComparable[sharing.ID](1, 2).Freeze()
	ctx := session_testutils.MakeRandomContexts(t, quorum, pcg.NewRandomised())[1]

	_, err := sigma.NewVerifier(ctx, testProtocol{}, testStatement("statement"), nil)
	require.Error(t, err)
}

func TestFailedCallsDoNotMutateTranscript(t *testing.T) {
	t.Parallel()

	t.Run("prover round3 before round1", func(t *testing.T) {
		t.Parallel()

		quorum := hashset.NewComparable[sharing.ID](1, 2).Freeze()
		ctx := session_testutils.MakeRandomContexts(t, quorum, pcg.New(1, 2))[1]
		controlCtx := session_testutils.MakeRandomContexts(t, quorum, pcg.New(1, 2))[1]
		prover, err := sigma.NewProver(ctx, testProtocol{}, testStatement("statement"), testWitness("witness"))
		require.NoError(t, err)
		_, err = sigma.NewProver(controlCtx, testProtocol{}, testStatement("statement"), testWitness("witness"))
		require.NoError(t, err)

		_, err = prover.Round3([]byte{1})
		require.Error(t, err)

		after, err := ctx.Transcript().ExtractBytes("transcript-check", 32)
		require.NoError(t, err)
		expected, err := controlCtx.Transcript().ExtractBytes("transcript-check", 32)
		require.NoError(t, err)
		require.Equal(t, expected, after)
	})

	t.Run("verifier round2 wrong round", func(t *testing.T) {
		t.Parallel()

		quorum := hashset.NewComparable[sharing.ID](1, 2).Freeze()
		ctx := session_testutils.MakeRandomContexts(t, quorum, pcg.New(3, 4))[2]
		controlCtx := session_testutils.MakeRandomContexts(t, quorum, pcg.New(3, 4))[2]
		verifier, err := sigma.NewVerifier(ctx, testProtocol{}, testStatement("statement"), io.Reader(pcg.New(7, 8)))
		require.NoError(t, err)
		controlVerifier, err := sigma.NewVerifier(controlCtx, testProtocol{}, testStatement("statement"), io.Reader(pcg.New(7, 8)))
		require.NoError(t, err)

		_, err = verifier.Round2(testCommitment("commitment"))
		require.NoError(t, err)
		_, err = controlVerifier.Round2(testCommitment("commitment"))
		require.NoError(t, err)

		_, err = verifier.Round2(testCommitment("commitment-again"))
		require.Error(t, err)

		after, err := ctx.Transcript().ExtractBytes("transcript-check-2", 32)
		require.NoError(t, err)
		expected, err := controlCtx.Transcript().ExtractBytes("transcript-check-2", 32)
		require.NoError(t, err)
		require.Equal(t, expected, after)
	})

	t.Run("verifier verify wrong round", func(t *testing.T) {
		t.Parallel()

		quorum := hashset.NewComparable[sharing.ID](3, 4).Freeze()
		ctx := session_testutils.MakeRandomContexts(t, quorum, pcg.New(5, 6))[3]
		controlCtx := session_testutils.MakeRandomContexts(t, quorum, pcg.New(5, 6))[3]
		verifier, err := sigma.NewVerifier(ctx, testProtocol{}, testStatement("statement"), pcg.NewRandomised())
		require.NoError(t, err)
		_, err = sigma.NewVerifier(controlCtx, testProtocol{}, testStatement("statement"), pcg.NewRandomised())
		require.NoError(t, err)

		err = verifier.Verify(testResponse("response"))
		require.Error(t, err)

		after, err := ctx.Transcript().ExtractBytes("transcript-check-3", 32)
		require.NoError(t, err)
		expected, err := controlCtx.Transcript().ExtractBytes("transcript-check-3", 32)
		require.NoError(t, err)
		require.Equal(t, expected, after)
	})
}
