package decrypting

import (
	"crypto"
	"crypto/subtle"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/numutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/rep23"
	trsa_decryptions "github.com/bronlabs/bron-crypto/pkg/threshold/tdecryptions/trsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/trsa"
)

func AggregatePKCS1v15Decryption(publicShard *trsa.PublicShard, partialDecryptions ...*trsa_decryptions.PartialDecryption) ([]byte, error) {
	dealer1 := rep23.NewIntExpScheme(publicShard.N1)
	p1Shares := sliceutils.Map(partialDecryptions, func(s *trsa_decryptions.PartialDecryption) *rep23.IntExpShare { return s.P1Share })
	s1, err := dealer1.Open(p1Shares...)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot open s1 shares")
	}

	dealer2 := rep23.NewIntExpScheme(publicShard.N2)
	p2Shares := sliceutils.Map(partialDecryptions, func(s *trsa_decryptions.PartialDecryption) *rep23.IntExpShare { return s.P2Share })
	s2, err := dealer2.Open(p2Shares...)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot open s1 shares")
	}

	emNat := numutils.Crt(s1, s2, publicShard.N1, publicShard.N2.Nat())
	em := make([]byte, publicShard.PublicKey().Size())
	emNat.FillBytes(em)

	firstByteIsZero := subtle.ConstantTimeByteEq(em[0], 0)
	secondByteIsTwo := subtle.ConstantTimeByteEq(em[1], 2)

	// The remainder of the plaintext must be a string of non-zero random
	// octets, followed by a 0, followed by the message.
	//   lookingForIndex: 1 iff we are still looking for the zero.
	//   index: the offset of the first zero byte.
	lookingForIndex := 1

	index := 0
	for i := 2; i < len(em); i++ {
		equals0 := subtle.ConstantTimeByteEq(em[i], 0)
		index = subtle.ConstantTimeSelect(lookingForIndex&equals0, i, index)
		lookingForIndex = subtle.ConstantTimeSelect(equals0, 0, lookingForIndex)
	}

	// The PS padding must be at least 8 bytes long, and it starts two
	// bytes into em.
	validPS := subtle.ConstantTimeLessOrEq(2+8, index)

	valid := firstByteIsZero & secondByteIsTwo & (^lookingForIndex & 1) & validPS
	index = subtle.ConstantTimeSelect(valid, index+1, 0)

	if valid == 0 {
		return nil, errs.NewVerification("invalid decryption")
	}
	return em[index:], nil
}

func AggregateOAEPDecryption(publicShard *trsa.PublicShard, cryptoHash crypto.Hash, label []byte, partialDecryptions ...*trsa_decryptions.PartialDecryption) ([]byte, error) {
	dealer1 := rep23.NewIntExpScheme(publicShard.N1)
	p1Shares := sliceutils.Map(partialDecryptions, func(s *trsa_decryptions.PartialDecryption) *rep23.IntExpShare { return s.P1Share })
	s1, err := dealer1.Open(p1Shares...)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot open s1 shares")
	}

	dealer2 := rep23.NewIntExpScheme(publicShard.N2)
	p2Shares := sliceutils.Map(partialDecryptions, func(s *trsa_decryptions.PartialDecryption) *rep23.IntExpShare { return s.P2Share })
	s2, err := dealer2.Open(p2Shares...)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot open s1 shares")
	}

	emNat := numutils.Crt(s1, s2, publicShard.N1, publicShard.N2.Nat())
	em := make([]byte, publicShard.PublicKey().Size())
	emNat.FillBytes(em)

	hash := cryptoHash.New()
	hash.Reset()
	hash.Write(label)
	lHash := hash.Sum(nil)

	firstByteIsZero := subtle.ConstantTimeByteEq(em[0], 0)

	seed := em[1 : hash.Size()+1]
	db := em[hash.Size()+1:]

	mgfHash := cryptoHash.New()
	trsa.Mgf1XOR(seed, mgfHash, db)
	trsa.Mgf1XOR(db, mgfHash, seed)

	lHash2 := db[0:hash.Size()]

	// We have to validate the plaintext in constant time in order to avoid
	// attacks like: J. Manger. A Chosen Ciphertext Attack on RSA Optimal
	// Asymmetric Encryption Padding (OAEP) as Standardised in PKCS #1
	// v2.0. In J. Kilian, editor, Advances in Cryptology.
	lHash2Good := subtle.ConstantTimeCompare(lHash, lHash2)

	// The remainder of the plaintext must be zero or more 0x00, followed
	// by 0x01, followed by the message.
	//   lookingForIndex: 1 iff we are still looking for the 0x01
	//   index: the offset of the first 0x01 byte
	//   invalid: 1 iff we saw a non-zero byte before the 0x01.
	var lookingForIndex, index, invalid int
	lookingForIndex = 1
	rest := db[hash.Size():]

	for i := 0; i < len(rest); i++ {
		equals0 := subtle.ConstantTimeByteEq(rest[i], 0)
		equals1 := subtle.ConstantTimeByteEq(rest[i], 1)
		index = subtle.ConstantTimeSelect(lookingForIndex&equals1, i, index)
		lookingForIndex = subtle.ConstantTimeSelect(equals1, 0, lookingForIndex)
		invalid = subtle.ConstantTimeSelect(lookingForIndex&^equals0, 1, invalid)
	}

	if firstByteIsZero&lHash2Good&^invalid&^lookingForIndex != 1 {
		return nil, errs.NewVerification("invalid decryption")
	}

	return rest[index+1:], nil
}
