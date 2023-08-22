package errors

import (
	"errors"
)

var (
	// ErrClientIsNil is returned when a client is nil
	ErrClientIsNil                = errors.New("client is nil")
	ErrBatchSendTransactionFailed = errors.New("batch send transaction failed")
	ErrGetNonceFailed             = errors.New("get nonce failed")
	ErrClientNotFound             = errors.New("client not found")
	ErrPrivateKeyInvalid          = errors.New("private key invalid")
	ErrGetGasPriceFailed          = errors.New("get gas price failed")
	ErrGetChainIDFailed           = errors.New("get chain ID failed")
)
