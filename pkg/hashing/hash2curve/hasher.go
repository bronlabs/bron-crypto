package hash2curve

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type Hasher interface {
	// HashFresh iteratively writes all the inputs to a fresh hash function and returns the result.
	HashFresh(messages ...[]byte) ([]byte, error)
	// Name returns a human-readable hash name for the underlying hash function.
	Name() string
	// Type returns an enum indicating the type of the underlying hash function.
	Type() types.HasherType
	// ExpandMessageName returns a human-readable name of the message expansion function (XMD or XOF) for the underlying hash function.
	ExpandMessageName() string
	// Curve returns the curve assigned to this hasher.
	Curve() curves.Curve
	// Write implements io.Writer, and writes the input to an instance of the underlying hash function.
	io.Writer
	// Read implements io.Reader, and returns the digest (hash of the written inputs).
	io.Reader
	// Reset resets the underlying hash function.
	Reset()
	// Size returns the digest size of the underlying hash function.
	Size() int
}

// FixedLengthHasher encapsulates the fixed-length hash functions of sha256, sha512, sha3 and blake2b.
type FixedLengthHasher struct {
	hashFactory func() hash.Hash
	curve       curves.Curve
	hash.Hash
	*types.HasherType
}

func NewFixedLengthHasher(hasherType types.HasherType, curve curves.Curve) (Hasher, error) {
	var hashFactory func() hash.Hash
	switch hasherType {
	case types.SHA256:
		hashFactory = sha256.New
	case types.SHA512:
		hashFactory = sha512.New
	case types.BLAKE2B_256:
		hashFactory = newBlake2b_256 // blake2b.New256(nil)
	case types.BLAKE2B_512:
		hashFactory = newBlake2b_512 // blake2b.New512(nil)
	case types.SHA3_256:
		hashFactory = sha3.New256
	case types.SHA3_384:
		hashFactory = sha3.New384
	case types.SHA3_512:
		hashFactory = sha3.New512
	case types.SHAKE128, types.SHAKE256, types.BLAKE2S:
		return nil, errs.NewInvalidArgument("variable length hashers must be created with NewVariableLengthHasher")
	default:
		return nil, errs.NewInvalidArgument("unsupported fixed hash type")
	}
	return &FixedLengthHasher{hashFactory, curve, hashFactory(), &hasherType}, nil
}

func (flh *FixedLengthHasher) Type() types.HasherType {
	return *flh.HasherType
}

func (flh *FixedLengthHasher) Curve() curves.Curve {
	return flh.curve
}

func (flh *FixedLengthHasher) Read(p []byte) (n int, err error) {
	if len(p) < flh.Size() {
		return 0, errs.NewFailed("insufficient buffer size")
	}
	n = copy(p, flh.Hash.Sum(nil))
	return n, nil
}

func (flh *FixedLengthHasher) HashFresh(messages ...[]byte) ([]byte, error) {
	H := flh.hashFactory()
	for _, x := range messages {
		if _, err := H.Write(x); err != nil {
			return nil, errs.WrapFailed(err, "could not write to H")
		}
	}
	digest := H.Sum(nil)
	return digest, nil
}

// ExtendableHash homogeneizes the variable-length hash function interfaces of blake2b.XOF and sha3.ShakeHash.
type ExtendableHash interface {
	io.Writer // Write(p []byte) (n int, err error)
	io.Reader // Read(p []byte) (n int, err error)
	Reset()
	// TODO: find a way to expose Clone() ExtendableHash
}

type VariableLengthHasher struct {
	hashFactory func() ExtendableHash
	curve       curves.Curve
	ExtendableHash
	*types.HasherType
	outputSize int
}

func NewVariableLengthHasher(hasherType types.HasherType, curve curves.Curve, outputSize int) (Hasher, error) {
	var hashFactory func() ExtendableHash
	switch hasherType {
	case types.SHAKE128:
		hashFactory = newShake128
	case types.SHAKE256:
		hashFactory = newShake256
	case types.BLAKE2S:
		hashFactory = newBlake2x
	case types.SHA256, types.SHA512, types.BLAKE2B_256, types.BLAKE2B_512, types.SHA3_256, types.SHA3_384, types.SHA3_512:
		return nil, errs.NewInvalidArgument("fixed length hashers must be created with NewFixedLengthHasher")
	default:
		return nil, errs.NewInvalidArgument("unsupported hash type")
	}
	return &VariableLengthHasher{hashFactory, curve, hashFactory(), &hasherType, outputSize}, nil
}

func (vlh *VariableLengthHasher) Type() types.HasherType {
	return *vlh.HasherType
}

func (vlh *VariableLengthHasher) Curve() curves.Curve {
	return vlh.curve
}

func (vlh *VariableLengthHasher) Size() int {
	return vlh.outputSize
}

func (vlh *VariableLengthHasher) HashFresh(messages ...[]byte) ([]byte, error) {
	H := vlh.hashFactory()
	for _, x := range messages {
		if _, err := H.Write(x); err != nil {
			return nil, errs.WrapFailed(err, "could not write to H")
		}
	}
	digest := make([]byte, vlh.outputSize)
	_, err := H.Read(digest)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not read from H")
	}
	return digest, nil
}

/*.------------------------------ AUXILIARY ---------------------------------.*/

var newBlake2b_256 = func() hash.Hash {
	hashFunction, err := blake2b.New256(nil)
	if err != nil {
		panic(errs.WrapFailed(err, "could not create blake2b-256 hash function"))
	}
	return hashFunction
}

var newBlake2b_512 = func() hash.Hash {
	hashFunction, err := blake2b.New512(nil)
	if err != nil {
		panic(errs.WrapFailed(err, "could not create blake2b-512 hash function"))
	}
	return hashFunction
}

var newShake128 = func() ExtendableHash {
	return sha3.NewShake128()
}

var newShake256 = func() ExtendableHash {
	return sha3.NewShake256()
}

var newBlake2x = func() ExtendableHash {
	hashFunction, err := blake2b.NewXOF(blake2b.OutputLengthUnknown, nil)
	if err != nil {
		panic(errs.WrapFailed(err, "could not create blake2x hash function"))
	}
	return hashFunction
}
