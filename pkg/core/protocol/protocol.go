package protocol

type Protocol string

const (
	FROST  = "FROST"
	DKLS23 = "DKLs23"
)

var Supported = map[Protocol]bool{FROST: true, DKLS23: true}
