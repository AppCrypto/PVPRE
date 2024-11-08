// go与区块链交互需要的函数
package utils

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/joho/godotenv"
)

// deploy contract and obtain abi interface and bin of source code
func Deploy(client *ethclient.Client, contract_name string, auth *bind.TransactOpts) (common.Address, *types.Transaction) {

	abiBytes, err := os.ReadFile("compile/contract/" + contract_name + ".abi")
	if err != nil {
		log.Fatalf("Failed to read ABI file: %v", err)
	}

	bin, err := os.ReadFile("compile/contract/" + contract_name + ".bin")
	if err != nil {
		log.Fatalf("Failed to read BIN file: %v", err)
	}

	parsedABI, err := abi.JSON(strings.NewReader(string(abiBytes)))
	if err != nil {
		log.Fatalf("Failed to parse ABI: %v", err)
	}

	address, tx, _, err := bind.DeployContract(auth, parsedABI, common.FromHex(string(bin)), client)
	if err != nil {
		log.Fatalf("Failed to deploy contract: %v", err)
	}
	fmt.Printf("Basics.sol deployed! Address: %s\n", address.Hex())
	fmt.Printf("Transaction hash: %s\n", tx.Hash().Hex())
	return address, tx
}

// construct a transaction
func Transact(client *ethclient.Client, privatekey string, value *big.Int) *bind.TransactOpts {
	key, _ := crypto.HexToECDSA(privatekey)
	publicKey := key.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatalf("Failed to get nonce: %v", err)
	}

	//gasLimit := uint64(90071992547)
	//gasPrice, err := client.SuggestGasPrice(context.Background())
	//if err != nil {
	//	log.Fatalf("Failed to get gas price: %v", err)
	//}
	chainID, err := client.ChainID(context.Background())
	auth, _ := bind.NewKeyedTransactorWithChainID(key, chainID)
	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = value
	auth.GasLimit = uint64(900719925)       //gasLimit
	auth.GasPrice = big.NewInt(20000000000) //gasPrice
	return auth
}

func GetENV(key string) string {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Some error occured. Err: %s", err)
	}
	return os.Getenv(key)
}

func randomOperand(operands []string) (string, []string) {
	index := rand.Intn(len(operands))
	operand := operands[index]
	operands = append(operands[:index], operands[index+1:]...)
	return operand, operands
}

func RandomACP(operands []string) string {

	operand1, remainingOperands := randomOperand(operands)
	operands = remainingOperands

	if len(operands) == 0 {
		return operand1
	}
	operand2, remainingOperands := randomOperand(operands)
	operands = remainingOperands

	operator := ""
	if rand.Intn(2) == 0 {
		operator = " AND "
	} else {
		operator = " OR "
	}

	expression := "(" + operand1 + operator + operand2 + ")"

	if len(operands) > 0 {
		expression += operator + RandomACP(operands)
	}

	return expression
}
