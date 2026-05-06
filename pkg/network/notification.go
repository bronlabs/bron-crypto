package network

import (
	"time"
)

var _ Notification = (*RoundCompletedNotification)(nil)

const (
	// RoundCompletedNotificationType identifies notifications emitted after a protocol round succeeds.
	RoundCompletedNotificationType NotificationType = "ROUND_COMPLETED"
)

// NotifyRoundCompleted emits a round-completed notification when callback is non-nil.
func NotifyRoundCompleted(callback NotificationCallback, protocolName string, round int) {
	if callback != nil {
		callback(&RoundCompletedNotification{
			protocolName: protocolName,
			round:        round,
			timestamp:    time.Now(),
		})
	}
}

// RoundCompletedNotification reports that a protocol runner completed a local round.
type RoundCompletedNotification struct {
	protocolName string
	round        int
	timestamp    time.Time
}

// Type returns the notification type.
func (*RoundCompletedNotification) Type() NotificationType {
	return RoundCompletedNotificationType
}

// Timestamp returns the notification creation time.
func (n *RoundCompletedNotification) Timestamp() time.Time {
	return n.timestamp
}

// Round returns the completed protocol round.
func (n *RoundCompletedNotification) Round() int {
	return n.round
}

// ProtocolName returns the protocol name that emitted the notification.
func (n *RoundCompletedNotification) ProtocolName() string {
	return n.protocolName
}
