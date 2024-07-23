package noninteractive_test

import (
	"crypto"
	crand "crypto/rand"
	nativeRsa "crypto/rsa"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/rsa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/damgard/keygen/trusted_dealer"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/damgard/signing"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/damgard/signing/noninteractive"
)

func Test_HappyPath(t *testing.T) {
	const th = 2
	const n = 3
	prng := crand.Reader
	message := []byte("Hello World")

	identities, err := testutils.MakeDeterministicTestIdentities(n)
	require.NoError(t, err)

	signingSuite, err := testutils.MakeSigningSuite(k256.NewCurve(), sha256.New) // dummy curve
	require.NoError(t, err)

	protocol, err := testutils.MakeThresholdSignatureProtocol(signingSuite, identities, th, identities)
	require.NoError(t, err)

	padding := rsa.NewPKCS1v15Padding()

	rsaKey := keyGen(t)
	shards, err := trusted_dealer.Deal(protocol, rsaKey, prng)
	require.NoError(t, err)

	partSignatures := hashmap.NewHashableHashMap[types.IdentityKey, *signing.RsaPartialSignature]()

	c0Shard, ok := shards.Get(identities[2])
	require.True(t, ok)
	c0Signer, err := noninteractive.NewCosigner(protocol, padding, identities[2], c0Shard)
	require.NoError(t, err)
	c0PartSig, err := c0Signer.ProducePartialSignature(message)
	require.NoError(t, err)
	partSignatures.Put(identities[2], c0PartSig)

	c1Shard, ok := shards.Get(identities[1])
	require.True(t, ok)
	c1Signer, err := noninteractive.NewCosigner(protocol, padding, identities[1], c1Shard)
	require.NoError(t, err)
	c1PartSig, err := c1Signer.ProducePartialSignature(message)
	require.NoError(t, err)
	partSignatures.Put(identities[1], c1PartSig)

	signature, err := signing.Aggregate(&rsaKey.PublicKey, padding, protocol, message, partSignatures)
	require.NoError(t, err)
	require.NotNil(t, signature)

	hasher := signingSuite.Hash()()
	hasher.Write(message)
	digest := hasher.Sum(nil)
	signatureBytes := signature.Bytes()
	nativePk := &nativeRsa.PublicKey{
		N: rsaKey.N.Big(),
		E: int(rsaKey.E),
	}

	// verify with native RSA
	err = nativeRsa.VerifyPKCS1v15(nativePk, crypto.SHA256, digest, signatureBytes)
	require.NoError(t, err)
}

func keyGen(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	var rsaKey *rsa.PrivateKey
	six := new(big.Int).SetUint64(6)
	for {
		nativeRsaKey, err := nativeRsa.GenerateKey(crand.Reader, 2048)
		require.NoError(t, err)

		pHalf := new(big.Int).Rsh(nativeRsaKey.Primes[0], 1)
		qHalf := new(big.Int).Rsh(nativeRsaKey.Primes[1], 1)
		pCheck := new(big.Int).GCD(nil, nil, pHalf, six)
		qCheck := new(big.Int).GCD(nil, nil, qHalf, six)
		if pCheck.IsUint64() && pCheck.Uint64() == 1 && qCheck.IsUint64() && qCheck.Uint64() == 1 {
			rsaKey = &rsa.PrivateKey{
				PublicKey: rsa.PublicKey{
					N: saferith.ModulusFromNat(new(saferith.Nat).SetBig(nativeRsaKey.N, nativeRsaKey.N.BitLen())),
					E: uint64(nativeRsaKey.E),
				},
				D: new(saferith.Nat).SetBig(nativeRsaKey.D, nativeRsaKey.N.BitLen()),
			}
			break
		}
	}

	return rsaKey
}
