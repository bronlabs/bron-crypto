package protocols

type Protocol string

const (
	BLS       = "BLS"
	DKLS24    = "DKLs24"
	FROST     = "FROST"
	LINDELL17 = "Lindell17"
	LINDELL22 = "Lindell22"
)

var Supported = map[Protocol]bool{FROST: true, DKLS24: true, LINDELL17: true, LINDELL22: true, BLS: true}
