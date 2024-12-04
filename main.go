package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	contract "pvpre/compile/contract"
	"time"

	// "pvpre/test/umbral/pre"
	// "pvpre/test/umbral/ukem"

	shell "github.com/ipfs/go-ipfs-api"

	"pvpre/crypto/dleq"
	"pvpre/crypto/gss"
	"pvpre/crypto/pvpre"
	"pvpre/utils"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	bn128 "pvpre/bn128"
)

type Metadata struct {
	ID          string
	Hash        string
	size        *big.Int
	description string
	timestamp   *big.Int
}

type Request struct {
	User_ID   string
	Owner_ID  string
	Hash      string
	timestamp *big.Int
}

func G1ToPoint(point *bn128.G1) contract.VerificationG1Point {
	// Marshal the G1 point to get the X and Y coordinates as bytes
	pointBytes := point.Marshal()
	//fmt.Println(point.Marshal())
	//fmt.Println(g.Marshal())
	// Create big.Int for X and Y coordinates
	x := new(big.Int).SetBytes(pointBytes[:32])
	y := new(big.Int).SetBytes(pointBytes[32:64])

	g1Point := contract.VerificationG1Point{
		X: x,
		Y: y,
	}
	return g1Point
}

func G1sToPoints(par *pvpre.PrePar, points []*bn128.G1) []contract.VerificationG1Point {
	g1Points := make([]contract.VerificationG1Point, par.Par.PP.N)
	for i := 0; i < len(points); i++ {
		g1Points[i] = G1ToPoint(points[i])
	}
	return g1Points
}

var size int64

func main() {
	contract_name := "Verification"
	client, err := ethclient.Dial("http://127.0.0.1:8545")
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}

	privatekey := utils.GetENV("PRIVATE_KEY_1")

	deployTX := utils.Transact(client, privatekey, big.NewInt(0))
	if deployTX == nil {
		log.Fatalf("Failed to create transaction")
	}
	address, _ := utils.Deploy(client, contract_name, deployTX)
	if err != nil {
		log.Fatalf("Failed to deploy contract: %v\n", err)
	}
	// 创建合约实例
	ctc, _ := contract.NewContract(common.HexToAddress(address.Hex()), client)

	numShares, l := 10, 256 //l为AES-256，即密钥长度

	threshold := 2*numShares/3 + 1

	// var n int64 = 1

	fmt.Printf("The number of shares is %v\n", numShares)
	fmt.Printf("The threshold value is %v\n", threshold)
	// var g1Point contract.VerificationG1Point

	fmt.Println("...........................................................Setup............................................................")

	// 生成公共参数Par和全局参数s,Par中部分数值被上传到区块连
	par, s, _ := pvpre.PRESetup(numShares, threshold, l)
	auth0 := utils.Transact(client, privatekey, big.NewInt(0))
	tx0, _ := ctc.UploadParams(auth0, G1ToPoint(par.Par.PP.G), big.NewInt(int64(numShares)), big.NewInt(int64(threshold)), par.Par.PP.Alpah, par.Par.Vi)

	receipt0, err := bind.WaitMined(context.Background(), client, tx0)
	if err != nil {
		log.Fatalf("Tx receipt failedd: %v", err)
	}
	fmt.Printf("Upload the par Gas used: %d\n", receipt0.GasUsed)

	fmt.Println("..........................................................KeyGen............................................................")

	// 生成各方的密钥对，并将公钥上传到区块链
	pka, ska, pkb, skb, PKs, SKs := pvpre.PREKeyGen(par)
	// delegator's public key pka is uploaded to chain
	auth1 := utils.Transact(client, privatekey, big.NewInt(0))
	tx1, _ := ctc.UploadDelegatorPubkicKey(auth1, G1ToPoint(pka))

	receipt1, err := bind.WaitMined(context.Background(), client, tx1)
	if err != nil {
		log.Fatalf("Tx receipt failedd: %v", err)
	}

	// delegatee's public key pkb is uploaded to chain
	auth2 := utils.Transact(client, privatekey, big.NewInt(0))
	tx2, _ := ctc.UploadDelegateePublicKey(auth2, G1ToPoint(pkb))
	receipt2, err := bind.WaitMined(context.Background(), client, tx2)
	if err != nil {
		log.Fatalf("Tx receipt failedd: %v", err)
	}

	// proxies' public keys PKs are uploaded to chain
	auth3 := utils.Transact(client, privatekey, big.NewInt(0))
	tx3, _ := ctc.UploadProxyPublicKey(auth3, G1sToPoints(par, PKs))
	receipt3, err := bind.WaitMined(context.Background(), client, tx3)
	if err != nil {
		log.Fatalf("Tx receipt failedd: %v", err)
	}
	fmt.Printf("Upload the pubkic keys pka, pkb, and PKs Gas used: %d\n", receipt1.GasUsed+receipt2.GasUsed+receipt3.GasUsed)

	fmt.Println("..........................................................Encrypt...........................................................")

	// 加密
	// 生成 size MB 的随机数据
	size = 5
	M := make([]byte, size*1024*1024)
	_, err = rand.Read(M)
	if err != nil {
		fmt.Println("Error generating random data:", err)
		return
	}

	C := pvpre.PREEnc2(par, pka, M, s)

	var file []byte
	file = append(file, C.C1...)
	file = append(file, C.C2.Marshal()...)

	sh := shell.NewShell("http://127.0.0.1:5001")
	cid, err := sh.Add(bytes.NewReader(file))
	if err != nil {
		fmt.Println("Error upload IPFS:", err)
	}
	// 输出文件的CID（即IPFS哈希值）
	fmt.Println("Encrypted data uploaded to IPFS with CID:", cid)

	fmt.Println(".........................................................ReKeyGen...........................................................")
	// 生成重加密密钥并上传到区块链上验证
	ckFrag, pi_sh := pvpre.PREReKeyGen(par, pkb, ska, pka, PKs, s)

	// 上传重加密密钥
	auth4 := utils.Transact(client, privatekey, big.NewInt(0))
	tx4, _ := ctc.UploadckFrag(auth4, G1sToPoints(par, ckFrag))
	receipt4, err := bind.WaitMined(context.Background(), client, tx4)
	if err != nil {
		log.Fatalf("Tx receipt failed %v", err)
	}
	fmt.Printf("Upload ReKey ckFrag Gas used: %d\n", receipt4.GasUsed)

	// 上传重加密密钥的NIZK证明
	auth5 := utils.Transact(client, privatekey, big.NewInt(0))
	tx5, _ := ctc.UploadDLEQProofReKey(auth5, pi_sh.C, G1ToPoint(pi_sh.RG), G1ToPoint(pi_sh.RH), pi_sh.Z)
	receipt5, err := bind.WaitMined(context.Background(), client, tx5)
	if err != nil {
		log.Fatalf("Tx receipt failed %v", err)
	}
	fmt.Printf("Upload ReKey NIZK proof pi_sh Gas used: %d\n", receipt5.GasUsed)

	fmt.Println("......................................................ReKeyGenVerify........................................................")

	result := pvpre.PREReKeyVerify(par, pka, pkb, ckFrag, PKs, pi_sh)
	fmt.Printf("The off-chain result of PREREKeyVerify is %v\n", result)

	auth6 := utils.Transact(client, privatekey, big.NewInt(0))
	tx6, _ := ctc.ReKeyVerify(auth6)
	ReKeyVerifyResult, _ := ctc.GetReKeyVrfResult(&bind.CallOpts{})
	receipt6, err := bind.WaitMined(context.Background(), client, tx6)

	if err != nil {
		log.Fatalf("Tx receipt failed %v", err)
	}

	fmt.Printf("ReKeyVerify Result: %v\n", ReKeyVerifyResult)
	fmt.Printf("ReKeyVerify Gas used: %d\n", receipt6.GasUsed)

	// Test
	var input []byte

	input = append(input, pka.Marshal()...)
	input = append(input, pkb.Marshal()...)
	for i := 0; i < len(PKs); i++ {
		input = append(input, PKs[i].Marshal()...)
		input = append(input, ckFrag[i].Marshal()...)
	}
	onchaininput, _ := ctc.Connect(&bind.CallOpts{})
	// fmt.Println("onchaininput = ", onchaininput)
	// fmt.Println("ofchaininput = ", input)
	if string(onchaininput) == string(input) {
		fmt.Print("Yes\n")
	} else {
		fmt.Print("No\n")
	}

	fmt.Println("..........................................................ReEnc.............................................................")

	// 重加密
	Cp, pi_re := pvpre.PREReEnc(par, pka, ckFrag, PKs, SKs, C)
	// 将Cp.C2p和Pi_re上传到区块链做验证

	auth13 := utils.Transact(client, privatekey, big.NewInt(0))
	tx13, _ := ctc.UploadC2p(auth13, G1sToPoints(par, Cp.C2p))
	receipt13, err := bind.WaitMined(context.Background(), client, tx13)
	if err != nil {
		log.Fatalf("Tx receipt failed %v\n", err)
	}
	fmt.Printf("Upload C2p Gas used: %d\n", receipt13.GasUsed)

	auth7 := utils.Transact(client, privatekey, big.NewInt(0))
	tx7, _ := ctc.UploadDLEQProofReEnc(auth7, pi_re.C, G1sToPoints(par, pi_re.RG), G1sToPoints(par, pi_re.RH), pi_re.Z)

	receipt7, err := bind.WaitMined(context.Background(), client, tx7)
	if err != nil {
		log.Fatalf("Tx receipt failed %v\n", err)
	}
	fmt.Printf("Upload ReEnc NIZK proofs pi_re Gas used: %d\n", receipt7.GasUsed)

	fmt.Println(".......................................................ReEncVerify..........................................................")

	// 重加密密文验证
	reEncValidity := pvpre.PREReEncVerify(par, ckFrag, Cp, pi_re, PKs, pka)
	fmt.Printf("The off-chain result of ReEncVerify(pi_re) is %v\n", reEncValidity)
	auth8 := utils.Transact(client, privatekey, big.NewInt(0))
	tx8, _ := ctc.ReEncVerify(auth8)
	ReEncVerifyResult, _ := ctc.GetReEncVrfResult(&bind.CallOpts{})
	receipt8, err := bind.WaitMined(context.Background(), client, tx8)
	fmt.Printf("ReEnc Verify Gas used: %d\n", receipt8.GasUsed)
	if err != nil {
		log.Fatalf("Tx receipt failed %v", err)
	}
	fmt.Printf("ReEncVerify Result: %v\n", ReEncVerifyResult)

	fmt.Println(".........................................................Decrypt............................................................")

	// delegator解密原始密文
	M_dec2 := pvpre.PREDec2(par, ska, C)
	I := make([]int, par.Par.PP.T)
	for i := 0; i < par.Par.PP.T; i++ {
		I[i] = i + 1
	}

	lambda, _ := gss.PrecomputeLagrangeCoefficients(par.Par.PP, I)

	// delegatee解密原始密文
	M_dec1 := pvpre.PREDec1(par, pka, skb, Cp, I, lambda)

	// 验证解密
	if string(M_dec1) == string(M) && string(M_dec2) == string(M) {
		fmt.Print("Test passed: message was correctly encrypted, re-encrypted, and decrypted.\n")
		// fmt.Println("Original plaintext : ", M)
		// fmt.Println("Decrypted by delegator : ", M_dec2)
		// fmt.Println("Decrypted by delegatee : ", M_dec1)
	} else {
		fmt.Print("Test failed: decrypted message does not match the original message.\n")
	}
	// ==========================================================================================================================================================
	// Test Data right confirmation 40+

	fmt.Println("..................................................TestDateRightConfirmation....................................................")

	fmt.Println("The size of M is : ", size, " MB")
	fmt.Println("N = ", numShares, ", threshold = ", threshold)

	// Hhash := "QmXBvED4QfqjWjMAiWnqp6HHX2JEgrJJZUxFutBa6A5kpS"

	metadata := &Metadata{
		ID:          pka.String(),
		Hash:        cid,
		size:        big.NewInt(size),
		description: "This is a test file data",
		timestamp:   big.NewInt(time.Now().Unix()),
	}

	// 上传Metadata 并 记载在区块链上，（相当于执行查找过程） 的Gas开销
	auth40 := utils.Transact(client, privatekey, big.NewInt(0))
	tx40, _ := ctc.UploadMetadata(auth40, metadata.ID, metadata.Hash, metadata.size, metadata.description, metadata.timestamp)
	receipt40, err := bind.WaitMined(context.Background(), client, tx40)
	if err != nil {
		log.Fatalf("Tx receipt failed %v", err)
	}
	// fmt.Printf("Upload and Record \"Metadata\" Gas used: %d\n", receipt40.GasUsed)

	auth41 := utils.Transact(client, privatekey, big.NewInt(0))
	tx41, _ := ctc.AddMetadata(auth41)
	receipt41, err := bind.WaitMined(context.Background(), client, tx41)
	if err != nil {
		log.Fatalf("Tx receipt failed %v", err)
	}
	fmt.Printf("Upload and Recorded \"Metadata\" Gas used: %d\n", receipt40.GasUsed+receipt41.GasUsed)

	// 上传Request的Gas开销
	Request := &Request{
		User_ID:   pkb.String(),
		Owner_ID:  pka.String(),
		Hash:      cid,
		timestamp: big.NewInt(time.Now().Unix()),
	}
	auth42 := utils.Transact(client, privatekey, big.NewInt(0))
	tx42, _ := ctc.UploadRequest(auth42, Request.User_ID, Request.Owner_ID, Request.Hash, Request.timestamp)
	receipt42, err := bind.WaitMined(context.Background(), client, tx42)
	if err != nil {
		log.Fatalf("Tx receipt failed %v", err)
	}
	fmt.Printf("Upload \"Request\" Gas used: %d\n", receipt42.GasUsed)

	auth44 := utils.Transact(client, privatekey, big.NewInt(0))
	tx44, _ := ctc.GenerateAuthorizersID(auth44)
	_, _ = bind.WaitMined(context.Background(), client, tx44)

	// 记录使用权授权记录 RightsofUseAudit
	auth43 := utils.Transact(client, privatekey, big.NewInt(0))
	tx43, _ := ctc.AddRightsofuseAudit(auth43)
	receipt43, err := bind.WaitMined(context.Background(), client, tx43)
	if err != nil {
		log.Fatalf("Tx receipt failed %v", err)
	}
	fmt.Printf("Record \"RightofUseAudit\" Gas used: %d\n", receipt43.GasUsed)

	// Dispute 50+
	fmt.Println(".........................................................Dispute............................................................")
	pkaskb := new(bn128.G1).ScalarMult(pka, skb)
	disc, disz, disrG, disrH, err := dleq.NewDLEQProof(par.Par.PP.G, pka, pkb, pkaskb, skb)
	if err != nil {
		fmt.Println("Failed to create DLEQ proof:", err)
	}
	auth51 := utils.Transact(client, privatekey, big.NewInt(0))
	tx51, _ := ctc.UploadDispute(auth51, disc, G1ToPoint(disrG), G1ToPoint(disrH), disz, G1ToPoint(pkaskb))
	receipt51, err := bind.WaitMined(context.Background(), client, tx51)
	if err != nil {
		log.Fatalf("Tx receipt failed %v", err)
	}
	fmt.Printf("Upload Dispute Gas used: %d\n", receipt51.GasUsed)

	// 链上验证Dispute
	disValidity := dleq.Verify(disc, disz, par.Par.PP.G, pka, pkb, pkaskb, disrG, disrH)
	if disValidity == nil {
		fmt.Print("The off-chain result of DisputeVerify(pi_dis) is true\n")
	}

	auth52 := utils.Transact(client, privatekey, big.NewInt(0))
	tx52, _ := ctc.DisputeVerify(auth52)
	DisputeVerifyResult, _ := ctc.GetDisputeVrfResult(&bind.CallOpts{})
	receipt52, err := bind.WaitMined(context.Background(), client, tx52)
	fmt.Printf("ReEnc Verify Gas used: %d\n", receipt52.GasUsed)
	if err != nil {
		log.Fatalf("Tx receipt failed %v", err)
	}
	fmt.Printf("DisputeVerify Result: %v\n", DisputeVerifyResult)

	// ==========================================================================================================================================================

	// ==========================================================================================================================================================
	// Test Umbral's ReEncVerify Gas cost: 30+

	// fmt.Println(".........................................................TestUmbral............................................................")

	// upar := ukem.Setup(numShares, threshold)
	// upka, uska, upkb, _, uPKs, _ := pre.KeyGen(upar)
	// uC := pre.Encrypt(upar, upka, M)
	// ukFrag := pre.ReKeyGen(upar, uska, upka, upkb)
	// uCp, upi := pre.ReEncrypt(upar, ukFrag, uC, uPKs)
	// pre.ReEncVerify(upar, uC.Capsule, uCp.Cfrag, upi)

	// auth30 := utils.Transact(client, privatekey, big.NewInt(0))
	// tx30, _ := ctc.UploadPar(auth30, G1ToPoint(upar.G), upar.Q, G1ToPoint(upar.U), big.NewInt(int64(numShares)), big.NewInt(int64(threshold)))
	// receipt30, err := bind.WaitMined(context.Background(), client, tx30)
	// if err != nil {
	// 	log.Fatalf("Tx receipt failed %v", err)
	// }
	// fmt.Printf("Upload upar Gas used: %d\n", receipt30.GasUsed)

	// auth31 := utils.Transact(client, privatekey, big.NewInt(0))
	// tx31, _ := ctc.UploadCapsule(auth31, G1ToPoint(uC.Capsule.E), G1ToPoint(uC.Capsule.V))
	// receipt31, err := bind.WaitMined(context.Background(), client, tx31)
	// if err != nil {
	// 	log.Fatalf("Tx receipt failed %v", err)
	// }
	// fmt.Printf("Upload Capsule Gas used: %d\n", receipt31.GasUsed)

	// E1 := make([]*bn128.G1, upar.N)
	// V1 := make([]*bn128.G1, upar.N)
	// Id := make([]*big.Int, upar.N)
	// X := make([]*bn128.G1, upar.N)
	// for i := 0; i < upar.N; i++ {
	// 	E1[i] = uCp.Cfrag[i].E1
	// 	V1[i] = uCp.Cfrag[i].V1
	// 	Id[i] = uCp.Cfrag[i].Id
	// 	X[i] = uCp.Cfrag[i].X
	// }

	// auth32 := utils.Transact(client, privatekey, big.NewInt(0))
	// tx32, _ := ctc.UploadCFrag(auth32, G1sToPoints(par, E1), G1sToPoints(par, V1), Id, G1sToPoints(par, X))
	// receipt32, err := bind.WaitMined(context.Background(), client, tx32)
	// if err != nil {
	// 	log.Fatalf("Tx receipt failed %v", err)
	// }
	// fmt.Printf("Upload CFrag Gas used: %d\n", receipt32.GasUsed)

	// E2 := make([]*bn128.G1, upar.N)
	// V2 := make([]*bn128.G1, upar.N)
	// U2 := make([]*bn128.G1, upar.N)
	// U1 := make([]*bn128.G1, upar.N)
	// Z1 := make([]*big.Int, upar.N)
	// Z2 := make([]*big.Int, upar.N)
	// Rou := make([]*big.Int, upar.N)
	// Aux := make([]*bn128.G1, upar.N)
	// for i := 0; i < upar.N; i++ {
	// 	E2[i] = upi[i].E2
	// 	V2[i] = upi[i].V2
	// 	U2[i] = upi[i].U2
	// 	U1[i] = upi[i].U1
	// 	Z1[i] = new(big.Int).Mod(upi[i].Z1, bn128.Order)
	// 	Z2[i] = new(big.Int).Mod(upi[i].Z2, bn128.Order)
	// 	Rou[i] = new(big.Int).Mod(upi[i].Rou, bn128.Order)
	// 	Aux[i] = upi[i].Aux
	// }

	// auth33 := utils.Transact(client, privatekey, big.NewInt(0))
	// tx33, _ := ctc.UploadPi(auth33, G1sToPoints(par, E2), G1sToPoints(par, V2), G1sToPoints(par, U2), G1sToPoints(par, U1), Z1, Z2, Rou, G1sToPoints(par, Aux))
	// receipt33, err := bind.WaitMined(context.Background(), client, tx33)
	// if err != nil {
	// 	log.Fatalf("Tx receipt failed %v", err)
	// }
	// fmt.Printf("Upload Pi Gas used: %d\n", receipt33.GasUsed)

	// auth34 := utils.Transact(client, privatekey, big.NewInt(0))
	// tx34, _ := ctc.UmbralVerify(auth34)
	// receipt34, err := bind.WaitMined(context.Background(), client, tx34)
	// if err != nil {
	// 	log.Fatalf("Tx receipt failed %v", err)
	// }
	// fmt.Printf("Upload Umbral Verify Gas used: %d\n", receipt34.GasUsed)
	// Umbralverifyresult, _ := ctc.GetUmbralVerificationResult(&bind.CallOpts{})
	// fmt.Println("Umbral Verify result on-chain: ", Umbralverifyresult)

	// // 连下验证：
	// fmt.Print("Umbral Verify result off-chain: ")
	// pre.ReEncVerify(upar, uC.Capsule, uCp.Cfrag, upi)

	// ==========================================================================================================================================================

}
