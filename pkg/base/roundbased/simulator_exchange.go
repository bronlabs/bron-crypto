package roundbased

type SimulatorExchange[P any] struct {
	from    string
	payload P
}
