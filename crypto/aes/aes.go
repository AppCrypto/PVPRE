package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

func PKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// PKCS7Unpadding 去填充
func PKCS7Unpadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("data is empty")
	}
	padding := int(data[length-1])
	if padding > aes.BlockSize || padding <= 0 {
		return nil, errors.New("invalid padding size")
	}
	return data[:length-padding], nil
}

// AES 加密
func AESEncrypt(plainText []byte, key []byte) ([]byte, error) {
	// 使用 AES-128, AES-192 或 AES-256 根据 key 长度创建加密器
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 添加填充
	plainText = PKCS7Padding(plainText, block.BlockSize())

	ciphertext := make([]byte, aes.BlockSize+len(plainText))
	iv := ciphertext[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plainText)
	return ciphertext, nil
}

// AESDecrypt AES CBC模式解密
func AESDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(ciphertext)) // 创建一个新的切片存储解密后的数据
	mode.CryptBlocks(decrypted, ciphertext)    // 将解密结果存储在新的切片中

	// 去填充
	return PKCS7Unpadding(decrypted)
}

// // 生成 AES 密钥，使用 SHA256 来确保密钥长度为 256 位
// func generateKey(password string) []byte {
// 	hash := sha256.New()
// 	hash.Write([]byte(password))
// 	return hash.Sum(nil)
// }

// func main() {
// 	// 示例数据
// 	plainText := []byte("This is a secret message.")
// 	password := "mysecretpassword"

// 	// 生成 AES 密钥
// 	key := generateKey(password)

// 	// 加密
// 	cipherText, err := AESEncrypt(plainText, key)
// 	if err != nil {
// 		fmt.Println("Error during encryption:", err)
// 		return
// 	}
// 	fmt.Printf("Encrypted: %x\n", cipherText)

// 	// 解密
// 	decryptedText, err := AESDecrypt(cipherText, key)
// 	if err != nil {
// 		fmt.Println("Error during decryption:", err)
// 		return
// 	}
// 	fmt.Printf("Decrypted: %s\n", decryptedText)
// }
