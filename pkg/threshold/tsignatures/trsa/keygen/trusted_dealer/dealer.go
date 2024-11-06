package trusted_dealer

import (
	nativeRsa "crypto/rsa"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa"
	"io"
	"math/big"
)

func Deal(primeBitLen uint, threshold, total uint, prng io.Reader) (shards map[types.SharingID]*trsa.Shard, publicKey *nativeRsa.PublicKey, err error) {
	rsaKey, err := nativeRsa.GenerateKey(prng, int(primeBitLen)*2)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create RSA key")
	}
	p := rsaKey.Primes[0]
	q := rsaKey.Primes[1]
	d := rsaKey.D
	e := rsaKey.E
	n := rsaKey.N

	primeDealer, err := replicated.NewIntDealer(threshold, total, replicated.BitLen(primeBitLen))
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create dealer")
	}
	pShares, err := primeDealer.Share(p, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot share p")
	}
	qShares, err := primeDealer.Share(q, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot share q")
	}

	nDealer, err := replicated.NewIntDealer(threshold, total, replicated.BitLen(primeBitLen*2))
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create dealer")
	}
	dShares, err := nDealer.Share(d, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot share d")
	}

	pk := &nativeRsa.PublicKey{
		N: new(big.Int).Set(n),
		E: e,
	}

	shards = make(map[types.SharingID]*trsa.Shard, total)
	for i := types.SharingID(1); i <= types.SharingID(total); i++ {
		shards[i] = &trsa.Shard{
			PublicKey: nativeRsa.PublicKey{
				N: new(big.Int).Set(n),
				E: e,
			},
			PShare: pShares[i],
			QShare: qShares[i],
			DShare: dShares[i],
		}
	}

	return shards, pk, nil
}
