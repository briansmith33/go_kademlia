package models

import (
	"math/big"
)

type KeyOffer struct {
	Type  string   `json:"type"`
	Nonce int      `json:"nonce"`
	Prime *big.Int `json:"prime"`
	Key   *big.Int `json:"key"`
}
