package dkg_test

import (
	"github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	safePrimeMocker := test_utils.NewSafePrimeMocker()
	safePrimeMocker.Mock()

	code := m.Run()
	os.Exit(code)
}
