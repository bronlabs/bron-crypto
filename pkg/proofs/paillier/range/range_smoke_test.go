package paillierrange_test

import (
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	paillierrange "github.com/bronlabs/bron-crypto/pkg/proofs/paillier/range"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

func _[EK paillier.EncryptionKey[EK]]() {
	var (
		_ sigma.Witness                                                                                                                              = (*paillierrange.Witness)(nil)
		_ sigma.Statement                                                                                                                            = (*paillierrange.Statement)(nil)
		_ sigma.Commitment                                                                                                                           = (*paillierrange.Commitment)(nil)
		_ sigma.State                                                                                                                                = (*paillierrange.State)(nil)
		_ sigma.Response                                                                                                                             = (*paillierrange.Response)(nil)
		_ sigma.Protocol[*paillierrange.Statement, *paillierrange.Witness, *paillierrange.Commitment, *paillierrange.State, *paillierrange.Response] = (*paillierrange.Protocol[EK])(nil)
	)
}
