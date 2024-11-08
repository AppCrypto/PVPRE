package main
import (
	//"basics/ma_abe/bn128"
	"basics/compile/contract"
	"basics/utils"
	"context"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	//"github.com/fentec-project/bn256"
	//"github.com/fentec-project/gofe/abe"
)

func main() {
	contract_name := "Basics"

	client, err := ethclient.Dial("http://127.0.0.1:8545")
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}
	privatekey1 := utils.GetENV("PRIVATE_KEY_1")
	deployTX := utils.Transact(client, privatekey1, big.NewInt(0))
	address, _ := utils.Deploy(client, contract_name, deployTX)
	ctc, err := contract.NewContract(common.HexToAddress(address.Hex()), client)
	myBigInt := new(big.Int).SetInt64(int64(111))
	auth1 := utils.Transact(client, privatekey1, big.NewInt(0))
	tx1, _ := ctc.Expect(auth1, "gid", myBigInt)
	receipt1, err := bind.WaitMined(context.Background(), client, tx1)
	fmt.Printf("Sending transaction to Expect %d\n", receipt1.GasUsed)
	auth2 := utils.Transact(client, privatekey1, big.NewInt(0))
	tx2, _ := ctc.Deposit(auth2, "gid")
	receipt2, err := bind.WaitMined(context.Background(), client, tx2)
	fmt.Printf("Sending transaction to Deposit %d\n", receipt2.GasUsed)
	auth3 := utils.Transact(client, privatekey1, big.NewInt(0))
	tx3, _ := ctc.Deposit(auth3, "gid")
	receipt3, err := bind.WaitMined(context.Background(), client, tx3)
	fmt.Printf("Sending transaction to Withdraw %d\n", receipt3.GasUsed)
	owner_Address := common.HexToAddress(utils.GetENV("ACCOUNT_2"))
	user_Address := common.HexToAddress(utils.GetENV("ACCOUNT_3"))

	var AddressArr []common.Address
	const n int = 100 //number of accounts
	for i := 2; i < n+2; i++ {
		account := "ACCOUNT_" + strconv.Itoa(i%10)
		AddressArr = append(AddressArr, common.HexToAddress(utils.GetENV(account)))
	}
	fmt.Printf("AddressArr%v\n", AddressArr)
	//fmt.Println(AddressArr)
	auth4 := utils.Transact(client, privatekey1, big.NewInt(0))
	tx4, _ := ctc.Reward(auth4, owner_Address, user_Address, AddressArr, "gid")
	receipt4, err := bind.WaitMined(context.Background(), client, tx4)
	fmt.Printf("Sending transaction to Reward %d\n", receipt4.GasUsed)
}