package enc_test

import (
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/enc"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

func _[EK paillier.EncryptionKey[EK]]() {
	var (
		_ sigma.Statement                                                                          = (*enc.Statement)(nil)
		_ sigma.Witness                                                                            = (*enc.Witness)(nil)
		_ sigma.Commitment                                                                         = (*enc.Commitment)(nil)
		_ sigma.State                                                                              = (*enc.State)(nil)
		_ sigma.Response                                                                           = (*enc.Response)(nil)
		_ sigma.Protocol[*enc.Statement, *enc.Witness, *enc.Commitment, *enc.State, *enc.Response] = (*enc.Protocol[EK])(nil)
	)
}
