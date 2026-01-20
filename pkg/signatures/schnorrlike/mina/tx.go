package mina

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

// Helper functions to create payment and delegation messages
// Reference: https://github.com/o1-labs/o1js/blob/188cf3faf6442e1e1ca8e4b3212a459b917c4ed4/src/mina-signer/src/sign-legacy.ts#L96
func NewPaymentMessage(source, receiver *PublicKey, amount, fee uint64, nonce, validUntil uint32, memo string) (*ROInput, error) {
	msg := new(ROInput).Init()

	// ===== COMMON SECTION =====
	// Reference: commonToInputLegacy in sign-legacy.ts
	// Order: fee, legacyTokenID, feePayer, nonce, validUntil, memo

	// 1. Fee (64 bits, LSB-first)
	msg.AddBits(uint64ToBits(fee)...)

	// 2. Legacy token ID (64 bits: [true, false*63])
	msg.AddBits(legacyTokenID()...)

	// 3. Fee payer public key (x as field, isOdd as 1 bit)
	// In payments, the fee payer is the source
	if err := addPublicKeyToInput(msg, source); err != nil {
		return nil, errs2.Wrap(err)
	}

	// 4. Nonce (32 bits, LSB-first)
	msg.AddBits(uint32ToBits(nonce)...)

	// 5. Valid until (32 bits, LSB-first)
	msg.AddBits(uint32ToBits(validUntil)...)

	// 6. Memo (272 bits = 34 bytes * 8)
	msg.AddBits(memoToBits(memo)...)

	// ===== BODY SECTION =====
	// Reference: bodyToInputLegacy in sign-legacy.ts
	// Order: tag, source, receiver, legacyTokenID, amount, tokenLocked

	// 1. Tag (3 bits: Payment=0 -> [false, false, false])
	msg.AddBits(tagToBits(0)...)

	// 2. Source public key
	if err := addPublicKeyToInput(msg, source); err != nil {
		return nil, errs2.Wrap(err)
	}

	// 3. Receiver public key
	if err := addPublicKeyToInput(msg, receiver); err != nil {
		return nil, errs2.Wrap(err)
	}

	// 4. Legacy token ID again
	msg.AddBits(legacyTokenID()...)

	// 5. Amount (64 bits, LSB-first)
	msg.AddBits(uint64ToBits(amount)...)

	// 6. Token locked flag (1 bit: false)
	msg.AddBits(false)

	return msg, nil
}

func NewDelegationMessage(source, newDelegate *PublicKey, fee uint64, nonce, validUntil uint32, memo string) (*ROInput, error) {
	msg := new(ROInput).Init()

	// ===== COMMON SECTION =====
	// Reference: commonToInputLegacy in sign-legacy.ts
	// Order: fee, legacyTokenID, feePayer, nonce, validUntil, memo

	// 1. Fee (64 bits, LSB-first)
	msg.AddBits(uint64ToBits(fee)...)

	// 2. Legacy token ID (64 bits: [true, false*63])
	msg.AddBits(legacyTokenID()...)

	// 3. Fee payer public key (x as field, isOdd as 1 bit)
	if err := addPublicKeyToInput(msg, source); err != nil {
		return nil, errs2.Wrap(err)
	}

	// 4. Nonce (32 bits, LSB-first)
	msg.AddBits(uint32ToBits(nonce)...)

	// 5. Valid until (32 bits, LSB-first)
	msg.AddBits(uint32ToBits(validUntil)...)

	// 6. Memo (272 bits = 34 bytes * 8)
	msg.AddBits(memoToBits(memo)...)

	// ===== BODY SECTION =====
	// Reference: bodyToInputLegacy in sign-legacy.ts
	// Order: tag, source, receiver (delegate), legacyTokenID, amount, tokenLocked

	// 1. Tag (3 bits: StakeDelegation=1 -> [false, false, true])
	msg.AddBits(tagToBits(1)...)

	// 2. Source public key
	if err := addPublicKeyToInput(msg, source); err != nil {
		return nil, errs2.Wrap(err)
	}
	// 3. Receiver public key (the delegate)
	if err := addPublicKeyToInput(msg, newDelegate); err != nil {
		return nil, errs2.Wrap(err)
	}

	// 4. Legacy token ID again
	msg.AddBits(legacyTokenID()...)

	// 5. Amount (64 bits, LSB-first) - 0 for delegation
	msg.AddBits(uint64ToBits(0)...)

	// 6. Token locked flag (1 bit: false)
	msg.AddBits(false)

	return msg, nil
}

// legacyTokenID is [true, false, false, ..., false] (64 bits total).
// Reference: https://github.com/o1-labs/o1js/blob/main/src/mina-signer/src/sign-legacy.ts
func legacyTokenID() []bool {
	bits := make([]bool, 64)
	bits[0] = true
	return bits
}

// uint64ToBits converts a uint64 to 64 bits in LSB-first order per byte.
// Reference: https://github.com/o1-labs/o1js/blob/main/src/bindings/lib/binable.ts
func uint64ToBits(v uint64) []bool {
	bits := make([]bool, 64)
	for i := range 64 {
		bits[i] = (v>>i)&1 == 1
	}
	return bits
}

// uint32ToBits converts a uint32 to 32 bits in LSB-first order.
func uint32ToBits(v uint32) []bool {
	bits := make([]bool, 32)
	for i := range 32 {
		bits[i] = (v>>i)&1 == 1
	}
	return bits
}

// memoToBits converts a memo string to 272 bits (34 bytes * 8).
// The memo is encoded as: [1 byte type tag (0x01)] + [1 byte length] + [up to 32 bytes UTF-8].
// Reference: https://github.com/o1-labs/o1js/blob/main/src/mina-signer/src/memo.ts
func memoToBits(memo string) []bool {
	const memoSize = 34
	bytes := make([]byte, memoSize)
	memoBytes := []byte(memo)

	if len(memoBytes) > 32 {
		memoBytes = memoBytes[:32]
	}

	// Byte 0: memo type tag (0x01 = user memo)
	bytes[0] = 0x01
	// Byte 1: length of the actual memo content
	bytes[1] = byte(len(memoBytes))
	// Bytes 2+: memo content (up to 32 bytes)
	copy(bytes[2:], memoBytes)

	// Convert to bits (LSB-first per byte)
	bits := make([]bool, memoSize*8)
	for i, b := range bytes {
		for j := range 8 {
			bits[i*8+j] = (b>>j)&1 == 1
		}
	}
	return bits
}

// tagToBits converts a transaction tag (0=Payment, 1=Delegation) to 3 bits.
// Reference: https://github.com/o1-labs/o1js/blob/main/src/mina-signer/src/sign-legacy.ts
func tagToBits(tag int) []bool {
	return []bool{
		tag&4 != 0,
		tag&2 != 0,
		tag&1 != 0,
	}
}

// addPublicKeyToInput adds a public key to ROInput in legacy format:
// x coordinate as field element, isOdd as 1 bit.
// Reference: https://github.com/o1-labs/o1js/blob/main/src/mina-signer/src/curve-bigint.ts
func addPublicKeyToInput(msg *ROInput, pk *PublicKey) error {
	if pk == nil {
		return errs2.New("public key is nil")
	}
	x, err := pk.V.AffineX()
	if err != nil {
		return errs2.Wrap(err)
	}
	y, err := pk.V.AffineY()
	if err != nil {
		return errs2.Wrap(err)
	}
	msg.AddFields(x)
	msg.AddBits(y.IsOdd())
	return nil
}
