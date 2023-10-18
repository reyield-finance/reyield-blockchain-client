package clientmanager

import (
	"sync"

	"github.com/reyield-finance/reyield-blockchain-client/client"
	"github.com/reyield-finance/reyield-blockchain-client/errors"
)

func NewClientManager() *ClientManager {
	return &ClientManager{
		Clients:        make(map[string][]*client.Client),
		FailedRequests: make([]client.TxRequest, 0),
		mu:             sync.Mutex{},
		clientCounter:  map[string]int{},
	}
}

type ClientManager struct {
	Clients        map[string][]*client.Client
	FailedRequests []client.TxRequest

	mu            sync.Mutex
	clientCounter map[string]int
}

func (cm *ClientManager) AddClient(name string, c *client.Client) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if c == nil {
		return errors.ErrClientIsNil
	}

	if cm.Clients[name] == nil {
		cm.Clients[name] = []*client.Client{}
		cm.clientCounter[name] = 0
	}

	cm.Clients[name] = append(cm.Clients[name], c)

	return nil
}

func (cm *ClientManager) GetClient(name string) *client.Client {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if (cm.Clients[name] == nil) || (len(cm.Clients[name]) == 0) {
		return nil
	}

	index := (cm.clientCounter[name]) % len(cm.Clients[name])
	c := cm.Clients[name][index]
	cm.clientCounter[name] = index + 1

	return c
}

func (cm *ClientManager) RemoveClient(name string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	clients, found := cm.Clients[name]
	if !found {
		return
	}

	for _, c := range clients {
		c.Close()
	}

	delete(cm.Clients, name)
}

func (cm *ClientManager) Close() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	for name, clients := range cm.Clients {
		for _, c := range clients {
			c.Close()
		}

		delete(cm.Clients, name)
	}
}
