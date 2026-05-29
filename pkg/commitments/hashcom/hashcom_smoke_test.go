package hashcom_test

import (
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/hashcom"
)

var (
	_ commitments.Message                        = hashcom.Message{}
	_ commitments.Witness                        = hashcom.Witness{}
	_ commitments.Commitment[hashcom.Commitment] = hashcom.Commitment{}

	_ commitments.CommitmentKey[*hashcom.CommitmentKey, hashcom.Message, hashcom.Witness, hashcom.Commitment] = (*hashcom.CommitmentKey)(nil)
)
