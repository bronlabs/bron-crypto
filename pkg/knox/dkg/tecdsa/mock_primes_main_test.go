package tecdsa_test

import (
	"os"
	"testing"

	"github.com/copperexchange/krypton/pkg/base/types/integration/testutils"
)

func TestMain(m *testing.M) {
	safePrimeMocker := testutils.NewSafePrimeMocker()
	safePrimeMocker.Mock()

	code := m.Run()
	os.Exit(code)
}
