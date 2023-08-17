package clientmanager_test

import (
	"context"
	"math/big"
	"testing"

	"github.com/reyield-blockchain-client/client"
	cmgr "github.com/reyield-blockchain-client/client-manager"
	"github.com/stretchr/testify/assert"
)

func TestClientManager(t *testing.T) {
	mgr := cmgr.NewClientManager()
	assert.NotNil(t, mgr)

	err := mgr.AddClient("nil", nil)
	assert.NotNil(t, err)

	gc, err := client.NewClient(client.Config{
		Name:      "eth-mainnet",
		URL:       "https://eth-mainnet.g.alchemy.com/v2/Awv8GOY7AVq9KfdpxQ6Uo7aaRAf6Lq39",
		NetworkID: 1,
		Currency:  "ETH",
		IsTestnet: false,
	})
	assert.Nil(t, err)
	err = mgr.AddClient("gc", gc)
	assert.Nil(t, err)

	oc, err := client.NewClient(client.Config{
		Name:      "optimism-testnet",
		URL:       "https://opt-goerli.g.alchemy.com/v2/jV0Mv2QaFbSUrS11K8ZsLSkjAy6xoTPj",
		NetworkID: 420,
		Currency:  "ETH",
		IsTestnet: true,
	})
	assert.Nil(t, err)
	err = mgr.AddClient("oc", oc)
	assert.Nil(t, err)

	block, err := mgr.GetClient("gc").BlockByNumber(context.Background(), big.NewInt(10000000))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, block, "should not be nil")
	assert.Equal(t, block.Number().Int64(), int64(10000000), "should be equal")

	block, err = mgr.GetClient("oc").BlockByNumber(context.Background(), big.NewInt(10000000))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, block, "should not be nil")
	assert.Equal(t, block.Number().Int64(), int64(10000000), "should be equal")

	mgr.RemoveClient("gc")
	gc = mgr.GetClient("gc")
	assert.Nil(t, gc, "should be nil")

	// check idempotency
	mgr.RemoveClient("gc")
	gc = mgr.GetClient("gc")
	assert.Nil(t, gc, "should be nil")

	oc = mgr.GetClient("oc")
	assert.NotNil(t, oc, "should not be nil")
}
