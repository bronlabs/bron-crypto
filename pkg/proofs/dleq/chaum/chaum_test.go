package chaum_test

import (
	crand "crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dleq/chaum"
)

func doChaum(curve curves.Curve, sid []byte, prng io.Reader) error {
	prover, err := chaum.NewProver(sid[:], nil, prng)
	if err != nil {
		return errs.WrapFailed(err, "failed to create prover")
	}
	x, err := curve.ScalarField().Random(crand.Reader)
	if err != nil {
		return errs.WrapRandomSampleFailed(err, "failed to generate random scalar")
	}
	H1, err := curve.Random(crand.Reader)
	if err != nil {
		return errs.WrapRandomSampleFailed(err, "failed to generate random scalar")
	}
	H2, err := curve.Random(crand.Reader)
	if err != nil {
		return errs.WrapRandomSampleFailed(err, "failed to generate random scalar")
	}

	proof, statement, err := prover.Prove(x, H1, H2)
	if err != nil {
		return err
	}

	err = chaum.Verify(statement, proof, sid[:], nil)
	if err != nil {
		return err
	}
	return nil
}

func TestZKPOverMultipleCurves(t *testing.T) {
	t.Parallel()
	uniqueSessionId := sha3.Sum256([]byte("random seed"))
	curveInstances := []curves.Curve{
		k256.NewCurve(),
		p256.NewCurve(),
		edwards25519.NewCurve(),
	}
	for _, curve := range curveInstances {
		boundedCurve := curve
		t.Run(fmt.Sprintf("running the test for curve %s", boundedCurve.Name()), func(t *testing.T) {
			t.Parallel()
			err := doChaum(boundedCurve, uniqueSessionId[:], crand.Reader)
			require.NoError(t, err)
		})
	}
}

func TestNotVerifyZKPOverMultipleCurves(t *testing.T) {
	t.Parallel()

	uniqueSessionId := sha3.Sum256([]byte("random seed"))
	curveInstances := []curves.Curve{
		k256.NewCurve(),
		p256.NewCurve(),
		edwards25519.NewCurve(),
	}
	for _, curve := range curveInstances {
		boundedCurve := curve
		t.Run(fmt.Sprintf("running the test for curve %s", boundedCurve.Name()), func(t *testing.T) {
			t.Parallel()
			prover, err := chaum.NewProver(uniqueSessionId[:], nil, crand.Reader)
			require.NoError(t, err)
			require.NotNil(t, prover)

			secret, err := boundedCurve.ScalarField().Random(crand.Reader)
			require.NoError(t, err)
			H1, err := boundedCurve.Random(crand.Reader)
			require.NoError(t, err)
			H2, err := boundedCurve.Random(crand.Reader)
			require.NoError(t, err)
			proof, correctStatement, err := prover.Prove(secret, H1, H2)
			require.NoError(t, err)

			H3, err := boundedCurve.Random(crand.Reader)
			require.NoError(t, err)
			require.False(t, H1.Equal(H3), "buy a lotter ticket")
			require.False(t, H2.Equal(H3), "buy a lotter ticket")

			P3 := H3.Mul(secret)

			t.Run("bad H1", func(t *testing.T) {
				t.Parallel()
				statement := &chaum.Statement{
					H1: H3,
					H2: H2,
					P1: correctStatement.P1,
					P2: correctStatement.P2,
				}
				err = chaum.Verify(statement, proof, uniqueSessionId[:], nil)
				require.True(t, errs.IsVerificationFailed(err))
			})
			t.Run("bad H2", func(t *testing.T) {
				t.Parallel()
				statement := &chaum.Statement{
					H1: H1,
					H2: H3,
					P1: correctStatement.P1,
					P2: correctStatement.P2,
				}
				err = chaum.Verify(statement, proof, uniqueSessionId[:], nil)
				require.True(t, errs.IsVerificationFailed(err))
			})
			t.Run("can't replace p1 in the proof", func(t *testing.T) {
				t.Parallel()
				statement := &chaum.Statement{
					H1: H3,
					H2: H2,
					P1: P3,
					P2: correctStatement.P2,
				}
				err = chaum.Verify(statement, proof, uniqueSessionId[:], nil)
				require.True(t, errs.IsVerificationFailed(err))
			})
			t.Run("can't replace p2 in the proof", func(t *testing.T) {
				t.Parallel()
				statement := &chaum.Statement{
					H1: H1,
					H2: H3,
					P1: correctStatement.P1,
					P2: P3,
				}
				err = chaum.Verify(statement, proof, uniqueSessionId[:], nil)
				require.True(t, errs.IsVerificationFailed(err))
			})
		})
	}
}
