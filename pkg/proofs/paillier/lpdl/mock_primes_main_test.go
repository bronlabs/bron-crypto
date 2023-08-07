package lpdl_test

import (
	"os"
	"testing"

	"github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
)

func TestMain(m *testing.M) {
	safePrimeMocker := test_utils.NewSafePrimeMocker()
	safePrimeMocker.Mock()

	code := m.Run()
	os.Exit(code)
}
