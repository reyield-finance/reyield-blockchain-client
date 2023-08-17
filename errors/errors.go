package errors

import (
	"errors"
)

var (
	// ErrClientIsNil is returned when a client is nil
	ErrClientIsNil = errors.New("client is nil")
)
