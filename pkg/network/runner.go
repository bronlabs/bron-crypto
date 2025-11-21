package network

type Runner[O any] interface {
	Run(rt *Router) (O, error)
}
