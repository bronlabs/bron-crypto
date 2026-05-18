package ntu

import (
	"context"
	"maps"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

// TestExecuteRunners concurrently executes the given runners with mock deliveries and collects their outputs and notifications.
func TestExecuteRunners[O any](tb testing.TB, runners map[sharing.ID]network.Runner[O]) (resultsMap map[sharing.ID]O, notificationsMap map[sharing.ID][]network.Notification) {
	tb.Helper()

	resultsMap = make(map[sharing.ID]O)
	notificationsMap = make(map[sharing.ID][]network.Notification)
	var resultsMutex sync.Mutex
	testCoordinator := NewMockCoordinator(slices.Collect(maps.Keys(runners))...)

	var errGroup errgroup.Group
	for id, runner := range runners {
		errGroup.Go(func() error {
			rt := network.NewRouter(testCoordinator.DeliveryFor(id))

			var notifications []network.Notification
			notificationCallback := func(n network.Notification) {
				notifications = append(notifications, n)
			}
			result, err := runner.Run(context.Background(), rt, notificationCallback)
			if err != nil {
				return err
			}

			resultsMutex.Lock()
			defer resultsMutex.Unlock()
			resultsMap[id] = result
			notificationsMap[id] = notifications
			return nil
		})
	}

	err := errGroup.Wait()
	require.NoError(tb, err)
	return resultsMap, notificationsMap
}

// TestExecuteRunnersWithQuorum concurrently executes the given runners with mock deliveries and collects their outputs and notifications.
func TestExecuteRunnersWithQuorum[O any](tb testing.TB, quorum network.Quorum, runners map[sharing.ID]network.Runner[O]) (resultsMap map[sharing.ID]O, notificationsMap map[sharing.ID][]network.Notification) {
	tb.Helper()

	resultsMap = make(map[sharing.ID]O)
	notificationsMap = make(map[sharing.ID][]network.Notification)
	var resultsMutex sync.Mutex
	testCoordinator := NewMockCoordinator(quorum.List()...)

	var errGroup errgroup.Group
	for id, runner := range runners {
		errGroup.Go(func() error {
			rt := network.NewRouter(testCoordinator.DeliveryFor(id))

			var notifications []network.Notification
			notificationCallback := func(n network.Notification) {
				notifications = append(notifications, n)
			}
			result, err := runner.Run(context.Background(), rt, notificationCallback)
			if err != nil {
				return err
			}

			resultsMutex.Lock()
			defer resultsMutex.Unlock()
			resultsMap[id] = result
			notificationsMap[id] = notifications
			return nil
		})
	}

	err := errGroup.Wait()
	require.NoError(tb, err)
	return resultsMap, notificationsMap
}

// RequireRoundCompletedNotifications checks that each party emitted the expected round-completed notifications.
func RequireRoundCompletedNotifications(tb testing.TB, notifications map[sharing.ID][]network.Notification, quorum network.Quorum, protocolName string, rounds int) {
	tb.Helper()

	for id := range quorum.Iter() {
		partyNotifications := notifications[id]
		require.Len(tb, partyNotifications, rounds)
		for i, n := range partyNotifications {
			roundCompleted, ok := n.(*network.RoundCompletedNotification)
			require.True(tb, ok)
			require.Equal(tb, network.RoundCompletedNotificationType, roundCompleted.Type())
			require.Equal(tb, protocolName, roundCompleted.ProtocolName())
			require.Equal(tb, i+1, roundCompleted.Round())
			require.False(tb, roundCompleted.Timestamp().IsZero())
		}
	}
}
