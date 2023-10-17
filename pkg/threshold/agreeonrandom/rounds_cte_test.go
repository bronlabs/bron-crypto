package agreeonrandom_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/internal"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
)

func Test_MeasureConstantTime(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	curve := k256.New()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha3.New256,
	}
	allIdentities, _ := integration_testutils.MakeTestIdentities(cipherSuite, 3)

	internal.RunMeasurement(500, "agreeonrandom", func(i int) {
		allIdentities, _ = integration_testutils.MakeTestIdentities(cipherSuite, 3)
	}, func() {
		testutils.RunAgreeOnRandom(curve, allIdentities, crand.Reader)
	})
}
