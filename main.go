package main

import (
	"fmt"
	"log"
	"math/big"
	contract "pvpre/compile/contract"
	"pvpre/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	// bn128 "github.com/fentec-project/bn256"
	bn128 "github.com/ethereum/go-ethereum/crypto/bn256/google"
)

func G1ToPoint(point *bn128.G1) contract.PvpreG1Point {
	// Marshal the G1 point to get the X and Y coordinates as bytes
	pointBytes := point.Marshal()
	//fmt.Println(point.Marshal())
	//fmt.Println(g.Marshal())
	// Create big.Int for X and Y coordinates
	x := new(big.Int).SetBytes(pointBytes[:32])
	y := new(big.Int).SetBytes(pointBytes[32:64])

	g1Point := contract.PvpreG1Point{
		X: x,
		Y: y,
	}
	return g1Point
}

func main() {
	contract_name := "Pvpre"

	client, err := ethclient.Dial("http://127.0.0.1:8545")
	if err != nil {
		log.Fatal("Failed to connect to the Ethereum client: %v", err)
	}

	privatekey1 := utils.GetENV("PRIVATE_KEY_1")

	deployTX := utils.Transact(client, privatekey1, big.NewInt(0))

	address, _ := utils.Deploy(client, contract_name, deployTX)

	ctc, _ := contract.NewContract(common.HexToAddress(address.Hex()), client)

	fmt.Println("...........................................................Setup............................................................")

	const num int = 100               //number of auths
	const times int64 = 5             //test times
	const CTsize1M = int(1024 * 1024) //the msg  iinit set 1M

}
