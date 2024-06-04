package agreeonrandom_test

import (
	"testing"

	fu "github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
	aortu "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/test/testutils"
	"github.com/stretchr/testify/require"
)

func aorSetupGeneratorFactory(f *testing.F) fu.ObjectGenerator[*aortu.AgreeOnRandomPublicParameters] {
	f.Helper()

	prng := fu.NewPrng()
	objectGenerator, err := fu.NewObjectGenerator(&aortu.AgreeOnRandomPPAdapter{}, prng)
	require.NoError(f, err)

	return objectGenerator
}

func Fuzz_Property_AgreeOnRandom(f *testing.F) {
	setup := aorSetupGeneratorFactory(f)
	fu.RunProtocolPropertyTest(f, setup,
		aortu.Run_HappyPath_AgreeOnRandom,
		aortu.Run_UnhappyPath_AgreeonRandom_MockRound1,
	)
}
