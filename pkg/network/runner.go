package network

import (
	"context"
	"time"

	"github.com/bronlabs/errs-go/errs"
)

// NotificationType identifies a protocol runner notification kind.
type NotificationType string

// Notification is an event emitted by a protocol runner.
type Notification interface {
	Type() NotificationType
	Timestamp() time.Time
}

// NotificationCallback receives protocol runner notifications.
type NotificationCallback func(n Notification)

// Runner executes a networked protocol using a Router and returns its output.
type Runner[O any] interface {
	Run(ctx context.Context, rt *Router, notificationCallback NotificationCallback) (O, error)
}

// NewSafeRunner wraps a runner and converts panics from Run into errors.
func NewSafeRunner[O any](r Runner[O]) (Runner[O], error) {
	if r == nil {
		return nil, errs.New("runner is nil")
	}
	return &safeRunner[O]{
		r: r,
	}, nil
}

type safeRunner[O any] struct {
	r Runner[O]
}

func (r *safeRunner[O]) Run(ctx context.Context, rt *Router, notificationCallback NotificationCallback) (out O, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			switch v := recovered.(type) {
			case error:
				err = errs.Wrap(v).WithMessage("runner panicked")
			default:
				err = errs.New("runner panicked: %v", v)
			}
		}
	}()

	//nolint:wrapcheck // intentionally not wrapping the error
	return r.r.Run(ctx, rt, notificationCallback)
}
