package aead

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// TestAESGCMEncryptDecrypt 测试 AESGCMEncrypt 和 AESGCMDecrypt 函数的正确性
func TestAESGCMEncryptDecrypt(t *testing.T) {
	// 定义 256 位密钥（32 字节）
	key1 := sha256.Sum256([]byte("your secret key")) // 32 字节
	key := key1[:]

	// 确保密钥长度是 32 字节
	if len(key) != 32 {
		t.Fatalf("Invalid key size: %d, expected 32 bytes", len(key))
	}

	// 明文和附加数据
	plaintext := []byte("This is a test message for AES GCM encryption.")
	// plaintext := make([]byte, 1024*1024)
	associatedData := []byte("This is associated data.")

	// 使用 AESGCMEncrypt 加密明文
	ciphertext, nonce, err := AESGCMEncrypt(key, plaintext, associatedData)
	if err != nil {
		t.Fatalf("AESGCMEncrypt failed: %v", err)
	}

	// 打印密文（仅用于调试，实际测试时可以省略）
	t.Logf("Ciphertext: %x", ciphertext)

	// 使用 AESGCMDecrypt 解密密文
	decryptedText, err := AESGCMDecrypt(key, ciphertext, nonce, associatedData)
	if err != nil {
		t.Fatalf("AESGCMDecrypt failed: %v", err)
	}

	// 验证解密后的明文是否与原始明文一致
	if !bytes.Equal(decryptedText, plaintext) {
		t.Errorf("Decrypted text does not match original plaintext. Got: %s, Expected: %s", decryptedText, plaintext)
	}
}

// TestAESGCMDecryptInvalidNonce 测试使用无效 nonce 解密时的错误处理
func TestAESGCMDecryptInvalidNonce(t *testing.T) {
	// 使用 sha256 生成 256 位（32 字节）密钥
	key := sha256.Sum256([]byte("your secret key"))

	// 明文和附加数据
	plaintext := []byte("This is a test message for AES GCM encryption.")
	associatedData := []byte("This is associated data.")

	// 使用 AESGCMEncrypt 加密明文
	ciphertext, nonce, err := AESGCMEncrypt(key[:], plaintext, associatedData)
	if err != nil {
		t.Fatalf("AESGCMEncrypt failed: %v", err)
	}

	// 篡改 nonce 长度，故意传递错误的 nonce 长度
	invalidNonce := nonce[:11] // 截断 nonce 长度

	// 使用 AESGCMDecrypt 解密时传递无效的 nonce
	_, err = AESGCMDecrypt(key[:], ciphertext, invalidNonce, associatedData)
	if err == nil {
		t.Fatalf("Expected error when using invalid nonce, but got nil")
	}

	// 打印错误信息
	t.Logf("Expected error: %v", err)
}

// TestAESGCMDecryptInvalidAssociatedData 测试使用错误的附加数据解密时的错误处理
func TestAESGCMDecryptInvalidAssociatedData(t *testing.T) {
	// 生成一个 32 字节的密钥（用于 AES-256）
	key1 := sha256.Sum256([]byte("your secret key")) // 32 字节
	key := key1[:]

	// 明文和附加数据
	plaintext := []byte("This is a test message for AES GCM encryption.")
	associatedData := []byte("This is associated data.")

	// 使用 AESGCMEncrypt 加密明文
	ciphertext, nonce, err := AESGCMEncrypt(key, plaintext, associatedData)
	if err != nil {
		t.Fatalf("AESGCMEncrypt failed: %v", err)
	}

	// 修改附加数据
	invalidAssociatedData := []byte("Invalid associated data.")

	// 尝试使用错误的附加数据解密
	_, err = AESGCMDecrypt(key, ciphertext, nonce, invalidAssociatedData)
	if err == nil {
		t.Fatal("Expected error but got nil when decrypting with invalid associated data")
	}
}
