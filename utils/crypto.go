package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
)

func Encrypt(data []byte, key []byte) string {
	block, err := aes.NewCipher(key)
	CheckError(err)
	gcm, err := cipher.NewGCM(block)
	CheckError(err)
	iv := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, iv)
	ciphertext := gcm.Seal(iv, iv, data, nil)
	buf := make([]byte, 5)
	_, err = rand.Read(buf)
	CheckError(err)
	ciphertext = append(buf, ciphertext...)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func Decrypt(ciphertext string, key []byte) string {
	textBytes, _ := base64.StdEncoding.DecodeString(ciphertext)
	block, err := aes.NewCipher(key)
	CheckError(err)
	if len(textBytes) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := textBytes[5:17]
	textBytes = textBytes[17:]
	gcm, err := cipher.NewGCM(block)
	CheckError(err)
	plaintext, err := gcm.Open(nil, iv, textBytes, nil)
	CheckError(err)
	return string(plaintext)
}
