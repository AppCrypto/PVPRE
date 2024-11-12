package aes

import (
	"bytes"
	"fmt"
	"testing"
)

func TestAES(t *testing.T) {
	// 测试数据
	originalMessage := "这是一个测试消息，用来验证AES加密解密是否正确。"
	key := []byte("1234567890abcdef") // 16字节的密钥（AES-128）

	// 加密
	ciphertext, err := AESEncrypt([]byte(originalMessage), key)
	if err != nil {
		t.Errorf("Encryption failed: %v", err)
	}

	// 解密
	decryptedMessage, err := AESDecrypt(ciphertext, key)
	if err != nil {
		t.Errorf("Decryption failed: %v", err)
	}

	// 检查解密后的明文是否与原始明文一致
	if !bytes.Equal(decryptedMessage, []byte(originalMessage)) {
		t.Errorf("Decrypted message doesn't match original. Expected %s but got %s", originalMessage, string(decryptedMessage))
	} else {
		// 成功解密并匹配，打印解密结果
		fmt.Println("Decrypted Message:", string(decryptedMessage))
	}
}
