package client_test

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/reyield-finance/reyield-blockchain-client/client"
	"github.com/stretchr/testify/assert"
)

func TestGenericClient(t *testing.T) {
	cli, err := client.NewClient(client.Config{
		Name:      "eth-mainnet",
		URL:       "https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY",
		Currency:  "ETH",
		IsTestnet: false,
	})
	assert.Nil(t, err, "should not error")

	assert.Equal(t, cli.Name(), "eth-mainnet", "should be equal")
	assert.Equal(t, cli.URL(), "https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY", "should be equal")
	assert.Equal(t, cli.Currency(), "ETH", "should be equal")
	assert.Equal(t, cli.IsTestnet(), false, "should be equal")

	ctx := context.Background()

	// Blckchain Access

	chainID, err := cli.ChainID(ctx)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, chainID, "should not be nil")

	block, err := cli.BlockByHash(ctx, common.HexToHash("0x20f593cd8720f9af63a5180044e5c0018a53f92a703c5ed758dc03db302009c5"))
	assert.Nil(t, err, err)
	assert.NotNil(t, block, "should not be nil")

	block, err = cli.BlockByNumber(context.Background(), nil)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, block, "should not be nil")

	num, err := cli.BlockNumber(ctx)
	assert.Nil(t, err, "should not error")
	assert.True(t, num > 0, "should be greater than 0")

	hash, err := cli.HeaderByHash(ctx, common.HexToHash("0x20f593cd8720f9af63a5180044e5c0018a53f92a703c5ed758dc03db302009c5"))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, hash, "should not be nil")

	head, err := cli.HeaderByNumber(ctx, big.NewInt(10000))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, head, "should not be nil")

	tx, s, err := cli.TransactionByHash(ctx, common.HexToHash("0x35c865dd0adbf6279f8dc11c17f82d66695e077592076c2048419ca8ba33e105"))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, tx, "should not be nil")
	assert.True(t, !s, "should be false")

	address, err := cli.TransactionSender(context.Background(), tx, common.HexToHash("0x20f593cd8720f9af63a5180044e5c0018a53f92a703c5ed758dc03db302009c5"), 0)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, address, "should not be nil")
	assert.Equal(t, address.String(), "0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5", "should be equal")

	count, err := cli.TransactionCount(ctx, common.HexToHash("0x20f593cd8720f9af63a5180044e5c0018a53f92a703c5ed758dc03db302009c5"))
	assert.Nil(t, err, "should not error")
	assert.True(t, count == 208, "should be equal to 208")

	tx, err = cli.TransactionInBlock(ctx, common.HexToHash("0x20f593cd8720f9af63a5180044e5c0018a53f92a703c5ed758dc03db302009c5"), 0)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, tx, "should not be nil")

	receipt, err := cli.TransactionReceipt(ctx, common.HexToHash("0x35c865dd0adbf6279f8dc11c17f82d66695e077592076c2048419ca8ba33e105"))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, receipt, "should not be nil")

	// State Access
	networkID, err := cli.NetworkID(ctx)
	assert.Nil(t, err, "should not error")
	assert.Equal(t, networkID.Cmp(big.NewInt(1)), 0, "should be equal to 1")

	balance, err := cli.BalanceAt(ctx, common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6"), big.NewInt(0))
	assert.Nil(t, err, "should not error")
	assert.Equal(t, balance.Cmp(big.NewInt(0)), 0, "should be greater than 0")

	b, err := cli.StorageAt(ctx, common.HexToAddress("0xdAC17F958D2ee523a2206206994597C13D831ec7"), common.BytesToHash([]byte("name")), big.NewInt(0))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, b, "should not be nil")

	b, err = cli.CodeAt(ctx, common.HexToAddress("0xdAC17F958D2ee523a2206206994597C13D831ec7"), big.NewInt(17925888))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, b, "should not be nil")

	num, err = cli.NonceAt(ctx, common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6"), big.NewInt(17925888))
	assert.Nil(t, err, "should not error")
	assert.True(t, num == 0, "should be equal to 0")

	// Filters

	logs, err := cli.FilterLogs(ctx, ethereum.FilterQuery{
		FromBlock: big.NewInt(17925888),
		ToBlock:   big.NewInt(17925888),
		Addresses: []common.Address{common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6")},
	})
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, logs, "should not be nil")

	// Pending State

	balance, err = cli.PendingBalanceAt(ctx, common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6"))
	assert.Nil(t, err, "should not error")
	assert.Equal(t, balance.Cmp(big.NewInt(0)), 0, "should be equal to 0")

	b, err = cli.PendingStorageAt(ctx, common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6"), common.BytesToHash([]byte("name")))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, b, "should not be nil")

	b, err = cli.PendingCodeAt(ctx, common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6"))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, b, "should not be nil")

	num, err = cli.PendingNonceAt(ctx, common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6"))
	assert.Nil(t, err, "should not error")
	assert.True(t, num == 0, "should be equal to 0")

	count, err = cli.PendingTransactionCount(ctx)
	assert.Nil(t, err, "should not error")

	// Contract Calling

	addr := common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6")
	b, err = cli.CallContract(ctx, ethereum.CallMsg{
		From:     addr,
		To:       &addr,
		Gas:      1000000,
		GasPrice: big.NewInt(1000000),
		Value:    big.NewInt(1000000),
		Data:     []byte("data"),
	}, big.NewInt(100000))
	assert.NotNil(t, err, "should insufficient gas")

	b, err = cli.CallContractAtHash(ctx, ethereum.CallMsg{
		From:     addr,
		To:       &addr,
		Gas:      1000000,
		GasPrice: big.NewInt(1000000),
		Value:    big.NewInt(1000000),
		Data:     []byte("data"),
	}, common.HexToHash("0x20f593cd8720f9af63a5180044e5c0018a53f92a703c5ed758dc03db302009c5"))
	assert.NotNil(t, err, "should insufficient gas")

	b, err = cli.PendingCallContract(ctx, ethereum.CallMsg{
		From:     addr,
		To:       &addr,
		Gas:      1000000,
		GasPrice: big.NewInt(1000000),
		Value:    big.NewInt(1000000),
		Data:     []byte("data"),
	})
	assert.NotNil(t, err, "should insufficient gas")

	gas, err := cli.SuggestGasPrice(ctx)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, gas, "should not be nil")

	gas, err = cli.SuggestGasTipCap(ctx)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, gas, "should not be nil")

	fee, err := cli.FeeHistory(ctx, 0, big.NewInt(1000000), nil)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, fee, "should not be nil")

	addr = common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6")
	num, err = cli.EstimateGas(ctx, ethereum.CallMsg{
		From:     addr,
		To:       &addr,
		Gas:      1000000,
		GasPrice: big.NewInt(1000000),
		Value:    big.NewInt(1000000),
		Data:     []byte("data"),
	})
	assert.NotNil(t, err, "should error because of insufficient funds")

}

func TestPolygonClient(t *testing.T) {
	cli, err := client.NewClient(client.Config{
		Name:      "polygon-pos-testnet",
		URL:       "https://polygon-mumbai.g.alchemy.com/v2/YOUR_API_KEY",
		Currency:  "MATIC",
		NetworkID: 80001,
		IsTestnet: true,
	})
	assert.Nil(t, err, "should not error")

	assert.Equal(t, cli.Name(), "polygon-pos-testnet", "should be equal")
	assert.Equal(t, cli.URL(), "https://polygon-mumbai.g.alchemy.com/v2/YOUR_API_KEY", "should be equal")
	assert.Equal(t, cli.CNetworkID(), uint64(80001), "should be equal")
	assert.Equal(t, cli.Currency(), "MATIC", "should be equal")
	assert.Equal(t, cli.IsTestnet(), true, "should be equal")

	ctx := context.Background()

	// Blckchain Access

	chainID, err := cli.ChainID(ctx)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, chainID, "should not be nil")

	block, err := cli.BlockByHash(ctx, common.HexToHash("0x2f5423ba780cb0a790a44e3d454c4302ddec8a65393c2054ede90c1181adc693"))
	assert.Nil(t, err, err)
	assert.NotNil(t, block, "should not be nil")

	block, err = cli.BlockByNumber(context.Background(), nil)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, block, "should not be nil")

	num, err := cli.BlockNumber(ctx)
	assert.Nil(t, err, "should not error")
	assert.True(t, num > 0, "should be greater than 0")

	hash, err := cli.HeaderByHash(ctx, common.HexToHash("0x2f5423ba780cb0a790a44e3d454c4302ddec8a65393c2054ede90c1181adc693"))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, hash, "should not be nil")

	head, err := cli.HeaderByNumber(ctx, big.NewInt(10000))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, head, "should not be nil")

	tx, s, err := cli.TransactionByHash(ctx, common.HexToHash("0x9fad6a73986f321abc43d12fca4b6878b575343f68410d78164ae4b1b43fe56a"))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, tx, "should not be nil")
	assert.True(t, !s, "should be false")

	address, err := cli.TransactionSender(context.Background(), tx, common.HexToHash("0x0d176f0037cd76b6f58f7dda4c8c1dd6037af883dcd6fdcff5994cdf5d0b0124"), 6)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, address, "should not be nil")
	assert.Equal(t, address.String(), "0x2A58cFF650bb82f77552b3F8A5B28bf0E0Dba1c8", "should be equal")

	count, err := cli.TransactionCount(ctx, common.HexToHash("0x0d176f0037cd76b6f58f7dda4c8c1dd6037af883dcd6fdcff5994cdf5d0b0124"))
	assert.Nil(t, err, "should not error")
	assert.True(t, count == 7, "should be equal to 7")

	tx, err = cli.TransactionInBlock(ctx, common.HexToHash("0x0d176f0037cd76b6f58f7dda4c8c1dd6037af883dcd6fdcff5994cdf5d0b0124"), 0)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, tx, "should not be nil")

	receipt, err := cli.TransactionReceipt(ctx, common.HexToHash("0x9fad6a73986f321abc43d12fca4b6878b575343f68410d78164ae4b1b43fe56a"))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, receipt, "should not be nil")

	// State Access
	networkID, err := cli.NetworkID(ctx)
	assert.Nil(t, err, "should not error")
	assert.Equal(t, networkID.Cmp(big.NewInt(80001)), 0, "should be equal to 1")

	balance, err := cli.BalanceAt(ctx, common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6"), big.NewInt(0))
	assert.Nil(t, err, "should not error")
	assert.Equal(t, balance.Cmp(big.NewInt(0)), 0, "should be greater than 0")

	b, err := cli.StorageAt(ctx, common.HexToAddress("0x7e43c46e6e81f11f18e7e4e97302d58bf8980c89"), common.BytesToHash([]byte("name")), big.NewInt(0))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, b, "should not be nil")

	b, err = cli.CodeAt(ctx, common.HexToAddress("0x7e43c46e6e81f11f18e7e4e97302d58bf8980c89"), big.NewInt(17925888))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, b, "should not be nil")

	num, err = cli.NonceAt(ctx, common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6"), big.NewInt(17925888))
	assert.Nil(t, err, "should not error")
	assert.True(t, num == 0, "should be equal to 0")

	// Filters

	logs, err := cli.FilterLogs(ctx, ethereum.FilterQuery{
		FromBlock: big.NewInt(17925888),
		ToBlock:   big.NewInt(17925888),
		Addresses: []common.Address{common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6")},
	})
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, logs, "should not be nil")

	// Pending State

	balance, err = cli.PendingBalanceAt(ctx, common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6"))
	assert.Nil(t, err, "should not error")
	assert.Equal(t, balance.Cmp(big.NewInt(0)), 0, "should be equal to 0")

	b, err = cli.PendingStorageAt(ctx, common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6"), common.BytesToHash([]byte("name")))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, b, "should not be nil")

	b, err = cli.PendingCodeAt(ctx, common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6"))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, b, "should not be nil")

	num, err = cli.PendingNonceAt(ctx, common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6"))
	assert.Nil(t, err, "should not error")
	assert.True(t, num == 0, "should be equal to 0")

	count, err = cli.PendingTransactionCount(ctx)
	assert.Nil(t, err, "should not error")

	// Contract Calling

	addr := common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6")
	b, err = cli.CallContract(ctx, ethereum.CallMsg{
		From:     addr,
		To:       &addr,
		Gas:      1000000,
		GasPrice: big.NewInt(1000000),
		Value:    big.NewInt(1000000),
		Data:     []byte("data"),
	}, big.NewInt(100000))
	assert.NotNil(t, err, "should insufficient gas")

	b, err = cli.CallContractAtHash(ctx, ethereum.CallMsg{
		From:     addr,
		To:       &addr,
		Gas:      1000000,
		GasPrice: big.NewInt(1000000),
		Value:    big.NewInt(1000000),
		Data:     []byte("data"),
	}, common.HexToHash("0x0d176f0037cd76b6f58f7dda4c8c1dd6037af883dcd6fdcff5994cdf5d0b0124"))
	assert.NotNil(t, err, "should insufficient gas")

	b, err = cli.PendingCallContract(ctx, ethereum.CallMsg{
		From:     addr,
		To:       &addr,
		Gas:      1000000,
		GasPrice: big.NewInt(1000000),
		Value:    big.NewInt(1000000),
		Data:     []byte("data"),
	})
	assert.NotNil(t, err, "should insufficient gas")

	gas, err := cli.SuggestGasPrice(ctx)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, gas, "should not be nil")

	gas, err = cli.SuggestGasTipCap(ctx)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, gas, "should not be nil")

	fee, err := cli.FeeHistory(ctx, 0, big.NewInt(1000000), nil)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, fee, "should not be nil")

	addr = common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6")
	num, err = cli.EstimateGas(ctx, ethereum.CallMsg{
		From:     addr,
		To:       &addr,
		Gas:      1000000,
		GasPrice: big.NewInt(1000000),
		Value:    big.NewInt(1000000),
		Data:     []byte("data"),
	})
	assert.NotNil(t, err, "should error because of insufficient funds")
}

func TestPolygonClientSendTransaction(t *testing.T) {
	cli, err := client.NewClient(client.Config{
		Name:      "polygon-pos-testnet",
		URL:       "https://polygon-mumbai.g.alchemy.com/v2/YOUR_API_KEY",
		Currency:  "MATIC",
		NetworkID: 80001,
		IsTestnet: true,
	})

	privateKey, err := crypto.HexToECDSA("YOUR PRIVATE KEY")
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("Cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := cli.PendingNonceAt(context.TODO(), fromAddress)
	if err != nil {
		log.Fatalf("Failed to get nonce: %v", err)
	}

	value := big.NewInt(100000000000000) // in wei (1 eth)
	gasLimit := uint64(21000)
	gasPrice, err := cli.SuggestGasPrice(context.TODO())
	if err != nil {
		log.Fatalf("Failed to suggest gas price: %v", err)
	}

	toAddress := common.Address{}
	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, nil)

	chainID, err := cli.NetworkID(context.TODO())
	if err != nil {
		log.Fatalf("Failed to get chain ID: %v", err)
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		log.Fatalf("Failed to sign tx: %v", err)
	}

	err = cli.SendTransaction(context.TODO(), signedTx)
	if err != nil {
		log.Fatalf("Failed to send transaction: %v", err)
	}
}

func TestOptimismClient(t *testing.T) {
	cli, err := client.NewClient(client.Config{
		Name:      "optimism-testnet",
		URL:       "https://opt-goerli.g.alchemy.com/v2/YOUR_API_KEY",
		Currency:  "ETH",
		NetworkID: 420,
		IsTestnet: true,
	})

	assert.Equal(t, cli.Name(), "optimism-testnet", "should be equal")
	assert.Equal(t, cli.URL(), "https://opt-goerli.g.alchemy.com/v2/YOUR_API_KEY", "should be equal")
	assert.Equal(t, cli.CNetworkID(), uint64(420), "should be equal")
	assert.Equal(t, cli.Currency(), "ETH", "should be equal")
	assert.Equal(t, cli.IsTestnet(), true, "should be equal")

	ctx := context.Background()

	// Blckchain Access

	chainID, err := cli.ChainID(ctx)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, chainID, "should not be nil")

	block, err := cli.BlockByHash(ctx, common.HexToHash("0x4d8fedd95bcae3672d6f51cc8f40d4bfdf184fd71ea716409a960986c1d8b302"))
	assert.Nil(t, err, err)
	assert.NotNil(t, block, "should not be nil")

	block, err = cli.BlockByNumber(context.Background(), nil)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, block, "should not be nil")

	num, err := cli.BlockNumber(ctx)
	assert.Nil(t, err, "should not error")
	assert.True(t, num > 0, "should be greater than 0")

	hash, err := cli.HeaderByHash(ctx, common.HexToHash("0x4d8fedd95bcae3672d6f51cc8f40d4bfdf184fd71ea716409a960986c1d8b302"))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, hash, "should not be nil")

	head, err := cli.HeaderByNumber(ctx, big.NewInt(10000))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, head, "should not be nil")

	tx, s, err := cli.TransactionByHash(ctx, common.HexToHash("0x07039df130d741d38398fc0ff59dab7879bbe7bbe57d19a342724a46ea322491"))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, tx, "should not be nil")
	assert.True(t, !s, "should be false")

	address, err := cli.TransactionSender(context.Background(), tx, common.HexToHash("0x288e4143b335ad55fd8829c8cc907de0d1a70b8ad78bee5bcc029191488a97a3"), 0)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, address, "should not be nil")
	assert.Equal(t, address.String(), "0xDeaDDEaDDeAdDeAdDEAdDEaddeAddEAdDEAd0001", "should be equal")

	count, err := cli.TransactionCount(ctx, common.HexToHash("0x288e4143b335ad55fd8829c8cc907de0d1a70b8ad78bee5bcc029191488a97a3"))
	assert.Nil(t, err, "should not error")
	assert.True(t, count == 1, "should be equal to 1")

	tx, err = cli.TransactionInBlock(ctx, common.HexToHash("0x288e4143b335ad55fd8829c8cc907de0d1a70b8ad78bee5bcc029191488a97a3"), 0)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, tx, "should not be nil")

	receipt, err := cli.TransactionReceipt(ctx, common.HexToHash("0x07039df130d741d38398fc0ff59dab7879bbe7bbe57d19a342724a46ea322491"))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, receipt, "should not be nil")

	// State Access
	networkID, err := cli.NetworkID(ctx)
	assert.Nil(t, err, "should not error")
	assert.Equal(t, networkID.Cmp(big.NewInt(420)), 0, "should be equal to 1")

	balance, err := cli.BalanceAt(ctx, common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6"), big.NewInt(0))
	assert.Nil(t, err, "should not error")
	assert.Equal(t, balance.Cmp(big.NewInt(0)), 0, "should be greater than 0")

	b, err := cli.StorageAt(ctx, common.HexToAddress("0x466869e807dd3D332D9b034Fa0F0bebE55CFaf82"), common.BytesToHash([]byte("name")), big.NewInt(0))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, b, "should not be nil")

	b, err = cli.CodeAt(ctx, common.HexToAddress("0x466869e807dd3D332D9b034Fa0F0bebE55CFaf82"), big.NewInt(563196))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, b, "should not be nil")

	num, err = cli.NonceAt(ctx, common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6"), big.NewInt(563196))
	assert.Nil(t, err, "should not error")
	assert.True(t, num == 0, "should be equal to 0")

	// Filters

	logs, err := cli.FilterLogs(ctx, ethereum.FilterQuery{
		FromBlock: big.NewInt(563196),
		ToBlock:   big.NewInt(563196),
		Addresses: []common.Address{common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6")},
	})
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, logs, "should not be nil")

	// Pending State

	balance, err = cli.PendingBalanceAt(ctx, common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6"))
	assert.Nil(t, err, "should not error")
	assert.Equal(t, balance.Cmp(big.NewInt(0)), 0, "should be equal to 0")

	b, err = cli.PendingStorageAt(ctx, common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6"), common.BytesToHash([]byte("name")))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, b, "should not be nil")

	b, err = cli.PendingCodeAt(ctx, common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6"))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, b, "should not be nil")

	num, err = cli.PendingNonceAt(ctx, common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6"))
	assert.Nil(t, err, "should not error")
	assert.True(t, num == 0, "should be equal to 0")

	count, err = cli.PendingTransactionCount(ctx)
	assert.Nil(t, err, "should not error")

	// Contract Calling

	addr := common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6")
	b, err = cli.CallContract(ctx, ethereum.CallMsg{
		From:     addr,
		To:       &addr,
		Gas:      1000000,
		GasPrice: big.NewInt(1000000),
		Value:    big.NewInt(1000000),
		Data:     []byte("data"),
	}, big.NewInt(100000))
	assert.NotNil(t, err, "should insufficient gas")

	b, err = cli.CallContractAtHash(ctx, ethereum.CallMsg{
		From:     addr,
		To:       &addr,
		Gas:      1000000,
		GasPrice: big.NewInt(1000000),
		Value:    big.NewInt(1000000),
		Data:     []byte("data"),
	}, common.HexToHash("0x288e4143b335ad55fd8829c8cc907de0d1a70b8ad78bee5bcc029191488a97a3"))
	assert.NotNil(t, err, "should insufficient gas")

	b, err = cli.PendingCallContract(ctx, ethereum.CallMsg{
		From:     addr,
		To:       &addr,
		Gas:      1000000,
		GasPrice: big.NewInt(1000000),
		Value:    big.NewInt(1000000),
		Data:     []byte("data"),
	})
	assert.NotNil(t, err, "should insufficient gas")

	gas, err := cli.SuggestGasPrice(ctx)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, gas, "should not be nil")

	gas, err = cli.SuggestGasTipCap(ctx)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, gas, "should not be nil")

	fee, err := cli.FeeHistory(ctx, 0, big.NewInt(1000000), nil)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, fee, "should not be nil")

	addr = common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6")
	num, err = cli.EstimateGas(ctx, ethereum.CallMsg{
		From:     addr,
		To:       &addr,
		Gas:      1000000,
		GasPrice: big.NewInt(1000000),
		Value:    big.NewInt(1000000),
		Data:     []byte("data"),
	})
	assert.NotNil(t, err, "should error because of insufficient funds")

}

func TestOptimismClientSendTransaction(t *testing.T) {
	cli, err := client.NewClient(client.Config{
		Name:      "optimism-testnet",
		URL:       "https://opt-goerli.g.alchemy.com/v2/YOUR_API_KEY",
		Currency:  "ETH",
		IsTestnet: true,
	})

	privateKey, err := crypto.HexToECDSA("YOUR_PRIVATE_KEY")
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("Cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := cli.PendingNonceAt(context.TODO(), fromAddress)
	if err != nil {
		log.Fatalf("Failed to get nonce: %v", err)
	}

	value := big.NewInt(100000000000000) // in wei (1 eth)
	gasLimit := uint64(21000)
	gasPrice, err := cli.SuggestGasPrice(context.TODO())
	if err != nil {
		log.Fatalf("Failed to suggest gas price: %v", err)
	}

	toAddress := common.Address{}
	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, nil)

	chainID, err := cli.NetworkID(context.TODO())
	if err != nil {
		log.Fatalf("Failed to get chain ID: %v", err)
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		log.Fatalf("Failed to sign tx: %v", err)
	}

	err = cli.SendTransaction(context.TODO(), signedTx)
	if err != nil {
		log.Fatalf("Failed to send transaction: %v", err)
	}
}

func TestArbitrumClient(t *testing.T) {
	cli, err := client.NewClient(client.Config{
		Name:      "arbitrum-testnet",
		URL:       "https://arb-goerli.g.alchemy.com/v2/YOUR_API_KEY",
		Currency:  "ETH",
		IsTestnet: true,
	})

	assert.Equal(t, cli.Name(), "arbitrum-testnet", "should be equal")
	assert.Equal(t, cli.URL(), "https://arb-goerli.g.alchemy.com/v2/YOUR_API_KEY", "should be equal")
	assert.Equal(t, cli.CNetworkID(), uint64(421613), "should be equal")
	assert.Equal(t, cli.Currency(), "ETH", "should be equal")
	assert.Equal(t, cli.IsTestnet(), true, "should be equal")

	ctx := context.Background()

	// Blckchain Access

	chainID, err := cli.ChainID(ctx)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, chainID, "should not be nil")

	// Arbitrum not compatible
	//block, err := cli.BlockByHash(ctx, common.HexToHash("0xcce095b690a450ede1a30918bf922bd4197bffa76f5e3e1373099719cd31153f"))
	//assert.Nil(t, err, err)
	//assert.NotNil(t, block, "should not be nil")

	// Arbitrum not compatible
	//block, err = cli.BlockByNumber(context.Background(), nil)
	//assert.Nil(t, err, "should not error")
	//assert.NotNil(t, block, "should not be nil")

	num, err := cli.BlockNumber(ctx)
	assert.Nil(t, err, "should not error")
	assert.True(t, num > 0, "should be greater than 0")
	fmt.Println(num)

	hash, err := cli.HeaderByHash(ctx, common.HexToHash("0xcce095b690a450ede1a30918bf922bd4197bffa76f5e3e1373099719cd31153f"))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, hash, "should not be nil")

	head, err := cli.HeaderByNumber(ctx, big.NewInt(10000))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, head, "should not be nil")

	tx, s, err := cli.TransactionByHash(ctx, common.HexToHash("0x90c5a3e5ca41e7969f50435af48e5edfb3034bbd79668017514e5011346d54ed"))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, tx, "should not be nil")
	assert.True(t, !s, "should be false")

	address, err := cli.TransactionSender(context.Background(), tx, common.HexToHash("0xcce095b690a450ede1a30918bf922bd4197bffa76f5e3e1373099719cd31153f"), 0)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, address, "should not be nil")
	assert.Equal(t, address.String(), "0x650451fC0cbAF95061e45DEc45CbAfd8aB168575", "should be equal")

	count, err := cli.TransactionCount(ctx, common.HexToHash("0xcce095b690a450ede1a30918bf922bd4197bffa76f5e3e1373099719cd31153f"))
	assert.Nil(t, err, "should not error")
	assert.True(t, count == 3, "should be equal to 3")

	// Arbitrum not compatible
	//tx, err = cli.TransactionInBlock(ctx, common.HexToHash("0xcce095b690a450ede1a30918bf922bd4197bffa76f5e3e1373099719cd31153f"), 0)
	//assert.Nil(t, err, "should not error")
	//assert.NotNil(t, tx, "should not be nil")

	receipt, err := cli.TransactionReceipt(ctx, common.HexToHash("0x90c5a3e5ca41e7969f50435af48e5edfb3034bbd79668017514e5011346d54ed"))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, receipt, "should not be nil")

	// State Access
	networkID, err := cli.NetworkID(ctx)
	assert.Nil(t, err, "should not error")
	assert.Equal(t, networkID.Cmp(big.NewInt(421613)), 0, "should be equal to 1")

	balance, err := cli.BalanceAt(ctx, common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6"), big.NewInt(0))
	assert.Nil(t, err, "should not error")
	assert.Equal(t, balance.Cmp(big.NewInt(0)), 0, "should be greater than 0")

	b, err := cli.StorageAt(ctx, common.HexToAddress("0xa9bCd145978a575694923b88028998FA9AbB5547"), common.BytesToHash([]byte("name")), big.NewInt(0))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, b, "should not be nil")

	b, err = cli.CodeAt(ctx, common.HexToAddress("0xa9bCd145978a575694923b88028998FA9AbB5547"), big.NewInt(563196))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, b, "should not be nil")

	num, err = cli.NonceAt(ctx, common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6"), big.NewInt(563196))
	assert.Nil(t, err, "should not error")
	assert.True(t, num == 0, "should be equal to 0")

	// Filters

	logs, err := cli.FilterLogs(ctx, ethereum.FilterQuery{
		FromBlock: big.NewInt(563196),
		ToBlock:   big.NewInt(563196),
		Addresses: []common.Address{common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6")},
	})
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, logs, "should not be nil")

	// Pending State

	balance, err = cli.PendingBalanceAt(ctx, common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6"))
	assert.Nil(t, err, "should not error")
	assert.Equal(t, balance.Cmp(big.NewInt(0)), 0, "should be equal to 0")

	b, err = cli.PendingStorageAt(ctx, common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6"), common.BytesToHash([]byte("name")))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, b, "should not be nil")

	b, err = cli.PendingCodeAt(ctx, common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6"))
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, b, "should not be nil")

	num, err = cli.PendingNonceAt(ctx, common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6"))
	assert.Nil(t, err, "should not error")
	assert.True(t, num == 0, "should be equal to 0")

	count, err = cli.PendingTransactionCount(ctx)
	assert.Nil(t, err, "should not error")

	// Contract Calling

	addr := common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6")
	b, err = cli.CallContract(ctx, ethereum.CallMsg{
		From:     addr,
		To:       &addr,
		Gas:      1000000,
		GasPrice: big.NewInt(1000000),
		Value:    big.NewInt(1000000),
		Data:     []byte("data"),
	}, big.NewInt(100000))
	assert.NotNil(t, err, "should insufficient gas")

	b, err = cli.CallContractAtHash(ctx, ethereum.CallMsg{
		From:     addr,
		To:       &addr,
		Gas:      1000000,
		GasPrice: big.NewInt(1000000),
		Value:    big.NewInt(1000000),
		Data:     []byte("data"),
	}, common.HexToHash("0xcce095b690a450ede1a30918bf922bd4197bffa76f5e3e1373099719cd31153f"))
	assert.NotNil(t, err, "should insufficient gas")

	b, err = cli.PendingCallContract(ctx, ethereum.CallMsg{
		From:     addr,
		To:       &addr,
		Gas:      1000000,
		GasPrice: big.NewInt(1000000),
		Value:    big.NewInt(1000000),
		Data:     []byte("data"),
	})
	assert.NotNil(t, err, "should insufficient gas")

	gas, err := cli.SuggestGasPrice(ctx)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, gas, "should not be nil")

	gas, err = cli.SuggestGasTipCap(ctx)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, gas, "should not be nil")

	fee, err := cli.FeeHistory(ctx, 0, big.NewInt(1000000), nil)
	assert.Nil(t, err, "should not error")
	assert.NotNil(t, fee, "should not be nil")

	addr = common.HexToAddress("0x71191236d8e7f259B77459f4d87a33fbe30C17D6")
	num, err = cli.EstimateGas(ctx, ethereum.CallMsg{
		From:     addr,
		To:       &addr,
		Gas:      1000000,
		GasPrice: big.NewInt(1000000),
		Value:    big.NewInt(1000000),
		Data:     []byte("data"),
	})
	assert.NotNil(t, err, "should error because of insufficient funds")

}

func TestArbitrumClientSendTransaction(t *testing.T) {
	cli, err := client.NewClient(client.Config{
		Name:      "arbitrum-testnet",
		URL:       "https://arb-goerli.g.alchemy.com/v2/YOUR_API_KEY",
		Currency:  "ETH",
		IsTestnet: true,
	})

	privateKey, err := crypto.HexToECDSA("YOUR_PRIVATE_KEY")
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("Cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := cli.PendingNonceAt(context.TODO(), fromAddress)
	if err != nil {
		log.Fatalf("Failed to get nonce: %v", err)
	}

	value := big.NewInt(100000000000000) // in wei (1 eth)
	gasLimit := uint64(21000)
	gasPrice, err := cli.SuggestGasPrice(context.TODO())
	if err != nil {
		log.Fatalf("Failed to suggest gas price: %v", err)
	}

	toAddress := common.Address{}
	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, nil)

	chainID, err := cli.NetworkID(context.TODO())
	if err != nil {
		log.Fatalf("Failed to get chain ID: %v", err)
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		log.Fatalf("Failed to sign tx: %v", err)
	}

	err = cli.SendTransaction(context.TODO(), signedTx)
	if err != nil {
		log.Fatalf("Failed to send transaction: %v", err)
	}
}

func TestOptimismBatchSend(t *testing.T) {

	cli, err := client.NewClient(client.Config{
		Name:      "optimism-testnet",
		URL:       "https://opt-goerli.g.alchemy.com/v2/jV0Mv2QaFbSUrS11K8ZsLSkjAy6xoTPj",
		Currency:  "ETH",
		IsTestnet: true,
	})

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

	count, err := cli.BatchSend(context.Background(), cfg, meta)
	assert.Nil(t, err)
	assert.Equal(t, 4, count)
}
