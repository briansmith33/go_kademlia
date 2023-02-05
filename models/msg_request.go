package models

type MsgRequest struct {
	Msg       string `json:"msg"`
	Signature []byte `json:"signature"`
}
