package clientmanager_test

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/reyield-finance/reyield-blockchain-client/client"
	cmgr "github.com/reyield-finance/reyield-blockchain-client/client-manager"
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
		Currency:  "ETH",
		NetworkID: 1,
		IsTestnet: false,
	})
	assert.Nil(t, err)
	err = mgr.AddClient("gc", gc)
	assert.Nil(t, err)

	oc, err := client.NewClient(client.Config{
		Name:      "optimism-testnet",
		URL:       "https://opt-goerli.g.alchemy.com/v2/jV0Mv2QaFbSUrS11K8ZsLSkjAy6xoTPj",
		Currency:  "ETH",
		NetworkID: 420,
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

func TestClientManagerSend(t *testing.T) {
	mgr := cmgr.NewClientManager()
	assert.NotNil(t, mgr)

	err := mgr.AddClient("nil", nil)
	assert.NotNil(t, err)

	oc, err := client.NewClient(client.Config{
		Name:      "optimism-testnet",
		URL:       "https://opt-goerli.g.alchemy.com/v2/jV0Mv2QaFbSUrS11K8ZsLSkjAy6xoTPj",
		Currency:  "ETH",
		IsTestnet: true,
	})
	assert.Nil(t, err)
	err = mgr.AddClient("oc", oc)
	assert.Nil(t, err)

	oc = mgr.GetClient("oc")
	assert.NotNil(t, oc, "should not be nil")

	privateKey, err := crypto.HexToECDSA("46eef390f6df8c5e66afbfed0a4399cffe88446300ecec003aad301dcab170b5")
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("Cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := oc.PendingNonceAt(context.TODO(), fromAddress)
	if err != nil {
		log.Fatalf("Failed to get nonce: %v", err)
	}

	value := big.NewInt(10000000000000) // in wei (0.0001 eth)
	gasLimit := uint64(21000)
	gasPrice, err := oc.SuggestGasPrice(context.TODO())
	if err != nil {
		log.Fatalf("Failed to suggest gas price: %v", err)
	}

	toAddress := common.Address{}

	meta := []string{
		"1", "2", "3", "4", "5",
	}

	chainID, err := oc.NetworkID(context.TODO())
	if err != nil {
		log.Fatalf("Failed to get chain ID: %v", err)
	}

	for i := range meta {

		tx := types.NewTransaction(nonce+uint64(i), toAddress, value, gasLimit, gasPrice, nil)

		signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
		if err != nil {
			log.Fatalf("Failed to sign tx: %v", err)
		}

		err = oc.SendTransaction(context.TODO(), signedTx)
		if err != nil {
			log.Fatalf("Failed to send transaction: %v", err)
		}
	}
}

func TestClientManagerBatchSend(t *testing.T) {
	mgr := cmgr.NewClientManager()
	assert.NotNil(t, mgr)

	oc, err := client.NewClient(client.Config{
		Name:      "optimism-testnet",
		URL:       "https://opt-goerli.g.alchemy.com/v2/jV0Mv2QaFbSUrS11K8ZsLSkjAy6xoTPj",
		Currency:  "ETH",
		NetworkID: 420,
		IsTestnet: true,
	})
	assert.Nil(t, err)
	err = mgr.AddClient("oc", oc)
	assert.Nil(t, err)

	oc = mgr.GetClient("oc")
	assert.NotNil(t, oc, "should not be nil")

	toAddress := common.Address{}

	cfg := client.TxConfig{
		PrivateKey: "46eef390f6df8c5e66afbfed0a4399cffe88446300ecec003aad301dcab170b5",
		GasLimit:   uint64(21000),
	}
	meta := []client.TxRequest{
		{
			ToAddress: toAddress,
			Value:     big.NewInt(1000000000000),
			Data:      nil,
		},
		{
			ToAddress: toAddress,
			Value:     big.NewInt(500000000000),
			Data:      nil,
		},
		{
			ToAddress: toAddress,
			Value:     big.NewInt(250000000000),
			Data:      nil,
		},
		{
			ToAddress: toAddress,
			Value:     big.NewInt(125000000000),
			Data:      nil,
		},
	}

	res, err := oc.BatchSend(context.Background(), cfg, meta)
	assert.Nil(t, err)
	assert.Equal(t, 4, res.SuccessCount)
}

func TestMultipleClientsForSingleChain(t *testing.T) {
	mgr := cmgr.NewClientManager()
	assert.NotNil(t, mgr)

	numOfClients := 3

	for i := 0; i < numOfClients; i++ {
		c, err := client.NewClient(
			client.Config{
				Name:      fmt.Sprintf("eth-client-%d", i),
				URL:       "https://eth-mainnet.g.alchemy.com/v2/Awv8GOY7AVq9KfdpxQ6Uo7aaRAf6Lq39",
				Currency:  "ETH",
				NetworkID: 1,
				IsTestnet: false,
			},
		)
		assert.Nil(t, err)
		assert.Nil(t, mgr.AddClient("ethereum", c))
	}

	for i := 0; i < 10; i++ {
		c := mgr.GetClient("ethereum")
		assert.NotNil(t, c)
		assert.Equal(t, fmt.Sprintf("eth-client-%d", i%numOfClients), c.Name())
	}
}
