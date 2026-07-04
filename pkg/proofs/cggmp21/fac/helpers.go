package fac

import (
	"crypto/sha256"
	"encoding/hex"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
)

func commitmentKeyDigest(commitmentKey *intcom.CommitmentKey) string {
	out := []byte{}
	out = sliceutils.AppendLengthPrefixed(out, commitmentKey.Group().Modulus().Bytes())
	out = sliceutils.AppendLengthPrefixed(out, commitmentKey.S().Bytes())
	out = sliceutils.AppendLengthPrefixed(out, commitmentKey.T().Bytes())
	sum := sha256.Sum256(out)
	return hex.EncodeToString(sum[:])
}

func intSampleRangeSymmetricBits(bitLen int, prngReader io.Reader) (*num.Int, error) {
	if bitLen <= 0 || bitLen%8 != 0 {
		return nil, ErrInvalidArgument.WithMessage("bitLen must be a positive multiple of 8")
	}
	if prngReader == nil {
		return nil, ErrInvalidArgument.WithMessage("prng must not be nil")
	}

	buf := make([]byte, bitLen/8+1)
	if _, err := io.ReadFull(prngReader, buf); err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample integer bytes")
	}
	buf[0] = byte(int8(buf[0]) >> 7)

	out, err := num.Z().FromTwosComplementBytesBE(buf)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not parse sampled integer")
	}
	return out, nil
}

func intInSignedBitRange(x *num.Int, bitLen int) bool {
	if x == nil || bitLen < 0 {
		return false
	}
	return x.Abs().TrueLen() <= bitLen
}

func paillierKeyFactors(secretKey *paillier.SecretKey) (p, q *num.Int, err error) {
	if secretKey == nil || secretKey.Group() == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("secret key and group must not be nil")
	}

	p, err = num.Z().FromNatCT(secretKey.Group().Arithmetic().P.Factor.Nat())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not convert p")
	}
	q, err = num.Z().FromNatCT(secretKey.Group().Arithmetic().Q.Factor.Nat())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not convert q")
	}
	return p, q, nil
}
