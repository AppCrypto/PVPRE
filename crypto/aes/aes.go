package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

// AES GCM 加密
func AESEncrypt(plainText []byte, key []byte) ([]byte, error) {
	// 创建加密器
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 创建 GCM 模式加密器
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 创建一个随机的 nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// 对数据进行加密
	ciphertext := aead.Seal(nonce, nonce, plainText, nil)
	return ciphertext, nil
}

// AES GCM 解密
func AESDecrypt(ciphertext, key []byte) ([]byte, error) {
	// 创建加密器
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 创建 GCM 模式解密器
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 获取 nonce 和密文
	if len(ciphertext) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]

	// 解密并验证
	plainText, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}
