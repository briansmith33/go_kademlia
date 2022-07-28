package models

type CmdRequest struct {
	Cmd       string `json:"cmd"`
	Signature []byte `json:"signature"`
}
