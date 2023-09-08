package protocols

type Protocol string

const (
	BLS       = "BLS"
	DKLS23    = "DKLs23"
	FROST     = "FROST"
	LINDELL17 = "Lindell17"
	LINDELL22 = "Lindell22"
)

var Supported = map[Protocol]bool{FROST: true, DKLS23: true, LINDELL17: true, LINDELL22: true, BLS: true}
