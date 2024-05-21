package impl

const (
	// The BN parameter for Pluto is -0x4000000000001000008780000000.
	paramBNHi         = uint64(0x0004000000000000)
	paramBNLo         = uint64(0x1000008780000000)
	FieldLimbs        = 7
	FieldBytes        = FieldLimbs * 8
	FieldBits         = 446
	WideFieldBytes    = FieldBytes * 2
	FieldBytesFp2     = FieldBytes * 2
	WideFieldBytesFp2 = WideFieldBytes * 2
)
