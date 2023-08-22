package client

import (
	"context"
	"crypto/ecdsa"
	"log"
	"math/big"
	"sync"
	"time"

	ge "github.com/ethereum-optimism/optimism/op-service/client"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/reyield-finance/reyield-blockchain-client/errors"
)

type client interface {

	// Close closes the client

	Close()

	// Blckchain Access

	ChainID(ctx context.Context) (*big.Int, error)
	BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error)
	BlockByNumber(ctx context.Context, number *big.Int) (*types.Block, error)
	BlockNumber(ctx context.Context) (uint64, error)
	//Alchemy not support
	//PeerCount(ctx context.Context) (uint64, error)
	HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error)
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)

	TransactionByHash(ctx context.Context, hash common.Hash) (tx *types.Transaction, isPending bool, err error)
	TransactionSender(ctx context.Context, tx *types.Transaction, block common.Hash, index uint) (common.Address, error)
	TransactionCount(ctx context.Context, blockHash common.Hash) (uint, error)
	TransactionInBlock(ctx context.Context, blockHash common.Hash, index uint) (*types.Transaction, error)
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
	SyncProgress(ctx context.Context) (*ethereum.SyncProgress, error)
	//Alchemy not support
	//SubscribeNewHead(ctx context.Context, ch chan<- *types.Header) (ethereum.Subscription, error)

	// State Access

	NetworkID(ctx context.Context) (*big.Int, error)
	BalanceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (*big.Int, error)
	StorageAt(ctx context.Context, account common.Address, key common.Hash, blockNumber *big.Int) ([]byte, error)
	CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error)
	NonceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (uint64, error)

	// Filters

	FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error)
	//Alchemy not support
	SubscribeFilterLogs(ctx context.Context, q ethereum.FilterQuery, ch chan<- types.Log) (ethereum.Subscription, error)

	// Pending State

	PendingBalanceAt(ctx context.Context, account common.Address) (*big.Int, error)
	PendingStorageAt(ctx context.Context, account common.Address, key common.Hash) ([]byte, error)
	PendingCodeAt(ctx context.Context, account common.Address) ([]byte, error)
	PendingNonceAt(ctx context.Context, account common.Address) (uint64, error)
	PendingTransactionCount(ctx context.Context) (uint, error)

	// Contract Calling

	CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
	CallContractAtHash(ctx context.Context, msg ethereum.CallMsg, blockHash common.Hash) ([]byte, error)
	PendingCallContract(ctx context.Context, msg ethereum.CallMsg) ([]byte, error)
	SuggestGasPrice(ctx context.Context) (*big.Int, error)
	SuggestGasTipCap(ctx context.Context) (*big.Int, error)
	FeeHistory(ctx context.Context, blockCount uint64, lastBlock *big.Int, rewardPercentiles []float64) (*ethereum.FeeHistory, error)
	EstimateGas(ctx context.Context, msg ethereum.CallMsg) (uint64, error)
	SendTransaction(ctx context.Context, tx *types.Transaction) error
}

type Client struct {
	client

	name      string
	url       string
	networkID uint64
	currency  string

	isTestnet bool
}

type Config struct {
	Name      string
	URL       string
	NetworkID uint64
	Currency  string
	IsTestnet bool
}

func NewClient(c Config) (*Client, error) {
	var (
		cli client
		err error
	)

	if c.NetworkID == 10 || c.NetworkID == 420 {
		cli, err = ge.DialEthClientWithTimeout(context.Background(), c.URL, time.Duration(100*time.Millisecond))
		//cli, err = ge.Dial(c.URL)
	} else {
		cli, err = ethclient.Dial(c.URL)
	}

	if err != nil {
		return nil, err
	}

	return &Client{
		client:    cli,
		name:      c.Name,
		url:       c.URL,
		networkID: c.NetworkID,
		currency:  c.Currency,
		isTestnet: c.IsTestnet,
	}, nil
}

func (c *Client) Name() string {
	return c.name
}

func (c *Client) URL() string {
	return c.url
}

func (c *Client) CNetworkID() uint64 {
	return c.networkID
}

func (c *Client) Currency() string {
	return c.currency
}

func (c *Client) IsTestnet() bool {
	return c.isTestnet
}

type TxConfig struct {
	PrivateKey string
	GasLimit   uint64
	GasPrice   *big.Int
}

type TxRequest struct {
	ToAddress common.Address
	Value     *big.Int
	Data      []byte
}

type TxResponse struct {
	SuccessCount int
	Txs          []*types.Transaction
	Errs         []error
}

func (c *Client) BatchSend(ctx context.Context, cfg TxConfig, txs []TxRequest) (res *TxResponse, err error) {

	privateKey, err := crypto.HexToECDSA(cfg.PrivateKey)
	if err != nil {
		err = errors.ErrPrivateKeyInvalid
		return
	}
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("Cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	if cfg.GasLimit == 0 {
		cfg.GasLimit = 21000
	}

	if cfg.GasPrice == nil {
		cfg.GasPrice, err = c.SuggestGasPrice(ctx)
		if err != nil {
			err = errors.ErrGetGasPriceFailed
			return
		}
	}

	nonce, err := c.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		err = errors.ErrGetNonceFailed
		return
	}

	var (
		wg   sync.WaitGroup
		lock sync.RWMutex
	)

	res = &TxResponse{
		Txs: make([]*types.Transaction, len(txs)),
	}

	sendTx := func(i int, tx TxRequest) {
		wrapTx := types.NewTransaction(nonce+uint64(i), tx.ToAddress, tx.Value, cfg.GasLimit, cfg.GasPrice, tx.Data)
		signedTx, txErr := types.SignTx(
			wrapTx,
			types.NewEIP155Signer(big.NewInt(int64(c.networkID))),
			privateKey,
		)
		if txErr != nil {
			lock.RLock()
			res.Errs = append(res.Errs, txErr)
			lock.RUnlock()
		}
		txErr = c.SendTransaction(ctx, signedTx)
		if txErr != nil {
			lock.RLock()
			res.Errs = append(res.Errs, txErr)
			lock.RUnlock()
		}
		res.Txs[i] = signedTx

		wg.Done()
	}

	for i, tx := range txs {
		wg.Add(1)

		go sendTx(i, tx)
	}

	wg.Wait()

	res.SuccessCount = len(txs) - len(res.Errs)
	if len(res.Errs) > 0 {
		err = errors.ErrBatchSendTransactionFailed
		return
	}

	return
}
