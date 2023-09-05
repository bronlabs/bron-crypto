package agreeonrandom_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/internal"
	"github.com/copperexchange/knox-primitives/pkg/agreeonrandom/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	test_utils_integration "github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
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
	allIdentities, _ := test_utils_integration.MakeIdentities(cipherSuite, 3)

	internal.RunMeasurement(500, "agreeonrandom", func(i int) {
		allIdentities, _ = test_utils_integration.MakeIdentities(cipherSuite, 3)
	}, func() {
		test_utils.ProduceSharedRandomValue(curve, allIdentities, crand.Reader)
	})
}
