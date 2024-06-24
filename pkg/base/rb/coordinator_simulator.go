package rb

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"sync"
)

var (
	_ Coordinator = (*simulatorCoordinator)(nil)

	simulatorSessions     = make(map[string]*simulatorSession)
	simulatorSessionsLock = sync.Mutex{}
)

type simulatorCoordinatorMessage struct {
	from    types.IdentityKey
	message []byte
}

type simulatorSession struct {
	buffer map[string][]*simulatorCoordinatorMessage
	mutex  sync.Mutex
	cond   *sync.Cond
}

type simulatorCoordinator struct {
	me           types.AuthKey
	participants []types.IdentityKey
	session      *simulatorSession
}

func (c *simulatorCoordinator) Send(to types.IdentityKey, message []byte) error {
	dst := to.String()

	c.session.cond.L.Lock()
	defer c.session.cond.L.Unlock()
	if _, ok := c.session.buffer[dst]; !ok {
		c.session.buffer[dst] = []*simulatorCoordinatorMessage{}
	}

	c.session.buffer[dst] = append(c.session.buffer[dst], &simulatorCoordinatorMessage{
		from:    c.me,
		message: message,
	})
	c.session.cond.Broadcast()

	return nil
}

func (c *simulatorCoordinator) Receive() (from types.IdentityKey, message []byte, err error) {
	c.session.cond.L.Lock()
	defer c.session.cond.L.Unlock()
	for len(c.session.buffer[c.me.String()]) == 0 {
		c.session.cond.Wait()
	}

	// extract message
	m := c.session.buffer[c.me.String()][0]
	c.session.buffer[c.me.String()] = c.session.buffer[c.me.String()][1:]
	return m.from, m.message, nil
}

func (c *simulatorCoordinator) GetAuthKey() types.AuthKey {
	return c.me
}

func (c *simulatorCoordinator) GetParticipants() []types.IdentityKey {
	return c.participants
}

func DialCoordinatorSimulator(sessionId string, me types.AuthKey, participants []types.IdentityKey) (Coordinator, error) {
	session := getOrCreateSession(sessionId)
	coordinator := &simulatorCoordinator{
		me:           me,
		participants: participants,
		session:      session,
	}

	return coordinator, nil
}

func getOrCreateSession(sessionId string) *simulatorSession {
	simulatorSessionsLock.Lock()
	defer simulatorSessionsLock.Unlock()
	if session, ok := simulatorSessions[sessionId]; ok {
		return session
	} else {
		session = &simulatorSession{
			buffer: make(map[string][]*simulatorCoordinatorMessage),
			mutex:  sync.Mutex{},
		}
		session.cond = sync.NewCond(&session.mutex)
		simulatorSessions[sessionId] = session
		return session
	}
}
