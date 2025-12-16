package network

// Runner executes a networked protocol using a Router and returns its output.
type Runner[O any] interface {
	Run(rt *Router) (O, error)
}
