package keyedblock

type KeyedBlock interface {
	Clone(key []byte) KeyedBlock
	Encrypt(dst, src []byte)
	Decrypt(dst, src []byte)
	SetKey(key []byte)
}
