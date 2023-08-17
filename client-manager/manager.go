package clientmanager

import (
	"github.com/reyield-blockchain-client/client"
	"github.com/reyield-blockchain-client/errors"
)

func NewClientManager() *ClientManager {
	return &ClientManager{
		Clients: make(map[string]*client.Client),
	}
}

type ClientManager struct {
	Clients map[string]*client.Client
}

func (cm *ClientManager) AddClient(name string, client *client.Client) error {
	if client == nil {
		return errors.ErrClientIsNil
	}
	cm.Clients[name] = client

	return nil
}

func (cm *ClientManager) GetClient(name string) *client.Client {
	return cm.Clients[name]
}

func (cm *ClientManager) RemoveClient(name string) {
	if cm.Clients[name] == nil {
		return
	}
	cm.Clients[name].Close()
	delete(cm.Clients, name)
}
