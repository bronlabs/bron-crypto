package nocopy_test

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/utils/nocopy"
)

var _ sync.Locker = (*nocopy.NoCopy)(nil)
