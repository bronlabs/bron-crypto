package errs2

import (
	"strings"
	"sync"
)

type tagStringRegistry struct {
	tag0 map[string]string
	tag1 map[string]string
	tag2 map[string]string

	mu sync.RWMutex
}

func (r *tagStringRegistry) isRegistered(tagString string, requiredParams int) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.get(tagString, requiredParams)
	return exists
}

func (r *tagStringRegistry) get(tagString string, requiredParams int) (defaultMessage string, exists bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	switch requiredParams {
	case -1, 0:
		defaultMessage, exists = r.tag0[tagString]
	case 1:
		defaultMessage, exists = r.tag1[tagString]
	case 2:
		defaultMessage, exists = r.tag2[tagString]
	default:
		panic("invalid required params")
	}
	return defaultMessage, exists
}

func (r *tagStringRegistry) register(tagString, defaultMessage string, requiredParams uint) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// if !regexp.MustCompile(`^[a-zA-Z0-9 ]*$`).MatchString(tagString) {
	//	panic("can only register alphanumeric tags with possibly spaces and _s")
	//}

	switch requiredParams {
	case 0:
		r.tag0[tagString] = defaultMessage
	case 1:
		r.tag1[tagString] = defaultMessage
	case 2:
		r.tag2[tagString] = defaultMessage
	default:
		panic("invalid required params")
	}
}

func newTagRegistery() tagStringRegistry {
	return tagStringRegistry{
		tag0: map[string]string{},
		tag1: map[string]string{},
		tag2: map[string]string{},

		mu: sync.RWMutex{},
	}
}

var reg = newTagRegistery()

func registerTag(tag Tag0, defaultMessage string) {
	if reg.isRegistered(tag.String(), 1) || reg.isRegistered(tag.String(), 2) {
		panic("tag already registered")
	}
	reg.register(tag.String(), defaultMessage, 0)
}

func registerTag1[T any](tag1 Tag1[T], defaultMessage string) {
	if reg.isRegistered(tag1.String(), 0) || reg.isRegistered(tag1.String(), 2) {
		panic("tag already registered")
	}
	reg.register(tag1.String(), defaultMessage, 1)
}

func registerTag2[T, U any](tag2 Tag2[T, U], defaultMessage string) {
	if reg.isRegistered(tag2.String(), 0) || reg.isRegistered(tag2.String(), 1) {
		panic("tag already registered")
	}
	reg.register(tag2.String(), defaultMessage, 2)
}

func parseMessages(tagMessage string, messages []string) string {
	message := strings.Join(messages, " ")
	if len(messages) == 0 {
		message, _ = reg.get(tagMessage, -1)
	}
	return message
}
