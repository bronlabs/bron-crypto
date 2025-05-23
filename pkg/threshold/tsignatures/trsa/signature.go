package trsa

import (
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/rep23"
)

type PartialSignature struct {
	S1Share *rep23.IntExpShare
	S2Share *rep23.IntExpShare
}
