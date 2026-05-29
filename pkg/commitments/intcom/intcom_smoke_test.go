package intcom_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
)

var (
	_ commitments.GroupHomomorphicCommitmentKey[
		*intcom.CommitmentKey,
		*intcom.Message, *num.Integers, *num.Int,
		*intcom.Witness, *num.Integers, *num.Int,
		*intcom.Commitment, *znstar.RSAGroupUnknownOrder, *znstar.RSAGroupElementUnknownOrder,
		*num.Int,
	] = (*intcom.CommitmentKey)(nil)

	_ commitments.GroupHomomorphicTrapdoorKey[
		*intcom.CommitmentKey,
		*intcom.TrapdoorKey,
		*intcom.Message, *num.Integers, *num.Int,
		*intcom.Witness, *num.Integers, *num.Int,
		*intcom.Commitment, *znstar.RSAGroupUnknownOrder, *znstar.RSAGroupElementUnknownOrder,
		*num.Int,
	] = (*intcom.TrapdoorKey)(nil)
)
