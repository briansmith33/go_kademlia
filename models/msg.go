package models

type Msg struct {
	Type string `json:"type"`
	Data []byte `json:"data"`
}
