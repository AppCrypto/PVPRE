package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// AESGCMEncrypt 加密函数，支持任意长度的明文
func AESGCMEncrypt(key, plaintext, associatedData []byte) ([]byte, []byte, error) {
	// 创建 AES 密钥对称加密器
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	// fmt.Println("密钥长度为：", len(key))

	// 生成随机的 nonce (12 字节)
	nonce := make([]byte, 12) // 确保 nonce 长度为 12 字节
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	// 创建 GCM 实例
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	// 加密数据
	ciphertext := gcm.Seal(nil, nonce, plaintext, associatedData)

	// 返回加密后的密文和 nonce
	return ciphertext, nonce, nil
}

// AESGCMDecrypt 解密函数
func AESGCMDecrypt(key, ciphertext, nonce, associatedData []byte) ([]byte, error) {
	// 检查 nonce 长度是否正确
	if len(nonce) != 12 {
		return nil, fmt.Errorf("invalid nonce length, expected 12 bytes, got %d", len(nonce))
	}

	// 创建 AES 密钥对称加密器
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 创建 GCM 实例
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 解密数据并验证 TAG
	plaintext, err := gcm.Open(nil, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
