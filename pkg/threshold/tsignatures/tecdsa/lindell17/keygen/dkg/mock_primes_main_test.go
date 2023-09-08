package dkg_test

import (
	"github.com/copperexchange/krypton/pkg/base/types/integration/testutils"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	safePrimeMocker := testutils.NewSafePrimeMocker()
	safePrimeMocker.Mock()

	code := m.Run()
	os.Exit(code)
}
