// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package contract

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// DexG1Point is an auto generated low-level Go binding around an user-defined struct.
type DexG1Point struct {
	X *big.Int
	Y *big.Int
}

// ContractMetaData contains all meta data concerning the Contract contract.
var ContractMetaData = &bind.MetaData{
	ABI: "[{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"token\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"from\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"TokensReceived\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"GID\",\"type\":\"string\"}],\"name\":\"Deposit\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"pt1xx\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"pt1xy\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"pt1yx\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"pt1yy\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"pt2xx\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"pt2xy\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"pt2yx\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"pt2yy\",\"type\":\"uint256\"}],\"name\":\"ECTwistAdd\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"s\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"pt1xx\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"pt1xy\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"pt1yx\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"pt1yy\",\"type\":\"uint256\"}],\"name\":\"ECTwistMul\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"GID\",\"type\":\"string\"},{\"internalType\":\"uint256\",\"name\":\"ownerVal\",\"type\":\"uint256\"}],\"name\":\"Expect\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"GetFieldModulus\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"pure\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"str\",\"type\":\"string\"}],\"name\":\"HashToG1\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"X\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"Y\",\"type\":\"uint256\"}],\"internalType\":\"structDex.G1Point\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"addrU\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"addrO\",\"type\":\"address\"},{\"internalType\":\"address[]\",\"name\":\"addrsAA\",\"type\":\"address[]\"},{\"internalType\":\"string\",\"name\":\"GID\",\"type\":\"string\"}],\"name\":\"Reward\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"GID\",\"type\":\"string\"}],\"name\":\"Withdraw\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"balances\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"empty\",\"outputs\":[],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"name\":\"expects\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"token\",\"type\":\"address\"}],\"name\":\"getTokenBalance\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"X\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"Y\",\"type\":\"uint256\"}],\"internalType\":\"structDex.G1Point\",\"name\":\"p\",\"type\":\"tuple\"}],\"name\":\"negate\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"X\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"Y\",\"type\":\"uint256\"}],\"internalType\":\"structDex.G1Point\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"},{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"name\":\"pool\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"token\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"receiveTokens\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
	Bin: "0x60016080819052600260a08190526000829055908190557f198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c26101009081527f1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed6101205260c08181526101806040527f090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b6101409081527f12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa6101605260e05291906100ca908290816100f5565b5060208201516100e090600280840191906100f5565b5050503480156100ef57600080fd5b50610148565b8260028101928215610123579160200282015b82811115610123578251825591602001919060010190610108565b5061012f929150610133565b5090565b5b8082111561012f5760008155600101610134565b6118a0806101576000396000f3fe6080604052600436106100e85760003560e01c806380dfa4051161008a578063d1bef29f11610059578063d1bef29f146102b0578063e752b54b146102c3578063f2a75fe4146102fb578063fb6b9e9a1461030757600080fd5b806380dfa40514610247578063a12988bd1461026a578063b73ab75d1461027d578063cb36594c1461029d57600080fd5b806335729130116100c657806335729130146101a45780633aecd0e3146101c657806355a3e90f146101e657806361a931ec1461020757600080fd5b8063129ee0f6146100ed578063187622621461012057806327e235e314610177575b600080fd5b6101006100fb366004611412565b61031a565b604080518251815260209283015192810192909252015b60405180910390f35b34801561012c57600080fd5b5061016961013b36600461146b565b6009602090815260009283526040909220815180830184018051928152908401929093019190912091525481565b604051908152602001610117565b34801561018357600080fd5b506101696101923660046114b9565b600a6020526000908152604090205481565b3480156101b057600080fd5b506101c46101bf3660046114db565b610392565b005b3480156101d257600080fd5b506101696101e13660046114b9565b6104d0565b3480156101f257600080fd5b5060008051602061184b833981519152610169565b34801561021357600080fd5b50610227610222366004611505565b61053b565b604080519485526020850193909352918301526060820152608001610117565b61025a610255366004611412565b610691565b6040519015158152602001610117565b61025a61027836600461155a565b6106c9565b34801561028957600080fd5b5061022761029836600461164c565b610941565b61025a6102ab366004611412565b6109c8565b61025a6102be366004611687565b610ab1565b3480156102cf57600080fd5b506101696102de366004611412565b805160208183018101805160088252928201919093012091525481565b3480156101c457600080fd5b6101006103153660046116cc565b610add565b604080518082019091526000808252602082015261038c61035d604080518082018252600080825260209182015281518083019092526001825260029082015290565b8360405160200161036e919061171b565b6040516020818303038152906040528051906020012060001c610b6a565b92915050565b600081116103e75760405162461bcd60e51b815260206004820152601d60248201527f416d6f756e74206d7573742062652067726561746572207468616e203000000060448201526064015b60405180910390fd5b6040516323b872dd60e01b8152336004820152306024820152604481018290526001600160a01b038316906323b872dd906064016020604051808303816000875af115801561043a573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061045e919061174a565b506001600160a01b0382166000908152600a602052604081208054839290610487908490611782565b909155505060405181815233906001600160a01b038416907f0af1239547617509a79d1ff0ee4be9ca943bc8410cb0b282dda97d27995a0acd9060200160405180910390a35050565b6040516370a0823160e01b81523060048201526000906001600160a01b038316906370a0823190602401602060405180830381865afa158015610517573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061038c9190611795565b60008080808b15801561054c57508a155b8015610556575089155b8015610560575088155b156105b15787158015610571575086155b801561057b575085155b8015610585575084155b6105a15761059588888888610bbf565b6105a1576105a16117ae565b5086925085915084905083610682565b871580156105bd575086155b80156105c7575085155b80156105d1575084155b156105fe576105e28c8c8c8c610bbf565b6105ee576105ee6117ae565b508a925089915088905087610682565b61060a8c8c8c8c610bbf565b610616576106166117ae565b61062288888888610bbf565b61062e5761062e6117ae565b60006106488d8d8d8d600160008f8f8f8f60016000610c74565b90506106788160005b602090810291909101519083015160408401516060850151608086015160a0870151610efd565b9450945094509450505b98509850985098945050505050565b3360009081526009602052604080822090513491906106b190859061171b565b90815260405190819003602001902055506001919050565b604051600090859085906008906106e190869061171b565b90815260200160405180910390205460096000846001600160a01b03166001600160a01b0316815260200190815260200160002085604051610723919061171b565b908152602001604051809103902054116107755760405162461bcd60e51b81526020600482015260136024820152721393c819195c1bdcda5d1cc81a5b881c1bdbdb606a1b60448201526064016103de565b806001600160a01b03166108fc600886604051610792919061171b565b90815260405190819003602001812054801590920291906000818181858888f193505050501580156107c8573d6000803e3d6000fd5b506008846040516107d9919061171b565b90815260200160405180910390205460096000846001600160a01b03166001600160a01b031681526020019081526020016000208560405161081b919061171b565b90815260200160405180910390205461083491906117da565b6001600160a01b03831660009081526009602052604090819020905161085b90879061171b565b9081526040519081900360200190205560005b85518160ff161015610933576000868260ff1681518110610891576108916117c4565b60200260200101519050806001600160a01b03166108fc885160096000886001600160a01b03166001600160a01b03168152602001908152602001600020896040516108dd919061171b565b9081526020016040518091039020546108f69190611803565b6040518115909202916000818181858888f1935050505015801561091e573d6000803e3d6000fd5b5050808061092b90611817565b91505061086e565b506001979650505050505050565b6000808080600188158015610954575087155b801561095e575086155b8015610968575085155b1561097c5750600197508795506000610994565b61098889898989610bbf565b610994576109946117ae565b60006109a68b8b8b8b8b876000610f47565b90506109b3816000610651565b929e919d509b50909950975050505050505050565b3360009081526009602052604080822090518291906109e890859061171b565b90815260200160405180910390205411610a3a5760405162461bcd60e51b81526020600482015260136024820152721393c819195c1bdcda5d1cc81a5b881c1bdbdb606a1b60448201526064016103de565b336000818152600960205260409081902090516108fc9190610a5d90869061171b565b90815260405190819003602001812054801590920291906000818181858888f19350505050158015610a93573d6000803e3d6000fd5b503360009081526009602052604080822090516106b190859061171b565b600081600884604051610ac4919061171b565b9081526040519081900360200190205550600192915050565b6040805180820190915260008082526020820152815160008051602061184b83398151915290158015610b1257506020830151155b15610b325750506040805180820190915260008082526020820152919050565b604051806040016040528084600001518152602001828560200151610b579190611836565b610b6190846117da565b90529392505050565b6040805180820190915260008082526020820152610b8661131f565b835181526020808501519082015260408101839052600060608360808460076107d05a03fa905080610bb757600080fd5b505092915050565b6000806000806000610bd387878989610fca565b9094509250610be489898181610fca565b9092509050610bf582828b8b610fca565b9092509050610c068484848461103b565b9094509250610c5684847f2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e57e9713b03af0fed4cd2cafadeed8fdf4a74fa084e52d1852e4a2bd0685c315d261103b565b909450925083158015610c67575082155b9998505050505050505050565b610c7c61133d565b88158015610c88575087155b15610cca578686868686868660005b60a08901929092526080880192909252606087019290925260408601929092526020858101939093529091020152610eed565b82158015610cd6575081155b15610ce9578c8c8c8c8c8c866000610c97565b610cf585858b8b610fca565b9095509350610d068b8b8585610fca565b60608301526040820152610d1c87878b8b610fca565b9097509550610d2d8d8d8585610fca565b60a08301526080820181905287148015610d4a575060a081015186145b15610d8f57604081015185148015610d655750606081015184145b15610d8057610d788d8d8d8d8d8d61107d565b866000610c97565b60016000818180808681610c97565b610d9b89898585610fca565b9093509150610dbb858583600260200201518460035b602002015161103b565b909d509b50610dd587878360046020020151846005610db1565b909b509950610de68b8b8181610fca565b9099509750610e06898983600460200201518460055b6020020151610fca565b9095509350610e1789898d8d610fca565b9099509750610e2889898585610fca565b60a08301526080820152610e3e8d8d8181610fca565b9097509550610e4f87878585610fca565b9097509550610e6087878b8b61103b565b9097509550610e71858560026111ec565b9093509150610e828787858561103b565b9097509550610e938b8b8989610fca565b60208301528152610ea68585898961103b565b909b509950610eb78d8d8d8d610fca565b909b509950610ed189898360026020020151846003610dfc565b909d509b50610ee28b8b8f8f61103b565b606083015260408201525b9c9b505050505050505050505050565b600080600080600080610f10888861121f565b9092509050610f218c8c8484610fca565b9096509450610f328a8a8484610fca565b969d959c509a50949850929650505050505050565b610f4f61133d565b8715610fbf576001881615610f90578051602082015160408301516060840151608085015160a0860151610f8d9594939291908d8d8d8d8d8d610c74565b90505b610f9e87878787878761107d565b949b50929950909750955093509150610fb8600289611803565b9750610f4f565b979650505050505050565b60008061100860008051602061184b83398151915285880960008051602061184b83398151915285880960008051602061184b8339815191526112aa565b60008051602061184b8339815191528086880960008051602061184b833981519152868a09089150915094509492505050565b600080611057868560008051602061184b8339815191526112aa565b611070868560008051602061184b8339815191526112aa565b9150915094509492505050565b6000806000806000806110928c8c60036111ec565b90965094506110a386868e8e610fca565b90965094506110b48a8a8a8a610fca565b90985096506110c58c8c8c8c610fca565b90945092506110d684848a8a610fca565b90945092506110e786868181610fca565b909c509a506110f8848460086111ec565b90925090506111098c8c848461103b565b909c509a5061111a88888181610fca565b909250905061112b848460046111ec565b909450925061113c84848e8e61103b565b909450925061114d84848888610fca565b909450925061115e8a8a60086111ec565b909650945061116f86868c8c610fca565b909650945061118086868484610fca565b90965094506111918484888861103b565b90945092506111a28c8c60026111ec565b90965094506111b386868a8a610fca565b90965094506111c488888484610fca565b90925090506111d5828260086111ec565b809250819350505096509650965096509650969050565b60008060008051602061184b83398151915283860960008051602061184b83398151915284860991509150935093915050565b6000808061126060008051602061184b8339815191528087880960008051602061184b8339815191528788090860008051602061184b8339815191526112ce565b905060008051602061184b83398151915281860960008051602061184b83398151915282860961129e9060008051602061184b8339815191526117da565b92509250509250929050565b600081806112ba576112ba6117ed565b6112c484846117da565b8508949350505050565b60008060405160208152602080820152602060408201528460608201526002840360808201528360a082015260208160c08360056107d05a03fa9051925090508061131857600080fd5b5092915050565b60405180606001604052806003906020820280368337509192915050565b6040518060c001604052806006906020820280368337509192915050565b634e487b7160e01b600052604160045260246000fd5b604051601f8201601f1916810167ffffffffffffffff8111828210171561139a5761139a61135b565b604052919050565b600082601f8301126113b357600080fd5b813567ffffffffffffffff8111156113cd576113cd61135b565b6113e0601f8201601f1916602001611371565b8181528460208386010111156113f557600080fd5b816020850160208301376000918101602001919091529392505050565b60006020828403121561142457600080fd5b813567ffffffffffffffff81111561143b57600080fd5b611447848285016113a2565b949350505050565b80356001600160a01b038116811461146657600080fd5b919050565b6000806040838503121561147e57600080fd5b6114878361144f565b9150602083013567ffffffffffffffff8111156114a357600080fd5b6114af858286016113a2565b9150509250929050565b6000602082840312156114cb57600080fd5b6114d48261144f565b9392505050565b600080604083850312156114ee57600080fd5b6114f78361144f565b946020939093013593505050565b600080600080600080600080610100898b03121561152257600080fd5b505086359860208801359850604088013597606081013597506080810135965060a0810135955060c0810135945060e0013592509050565b6000806000806080858703121561157057600080fd5b6115798561144f565b9350602061158881870161144f565b9350604086013567ffffffffffffffff808211156115a557600080fd5b818801915088601f8301126115b957600080fd5b8135818111156115cb576115cb61135b565b8060051b6115da858201611371565b918252838101850191858101908c8411156115f457600080fd5b948601945b838610156116195761160a8661144f565b825294860194908601906115f9565b9750505050606088013592508083111561163257600080fd5b5050611640878288016113a2565b91505092959194509250565b600080600080600060a0868803121561166457600080fd5b505083359560208501359550604085013594606081013594506080013592509050565b6000806040838503121561169a57600080fd5b823567ffffffffffffffff8111156116b157600080fd5b6116bd858286016113a2565b95602094909401359450505050565b6000604082840312156116de57600080fd5b6040516040810181811067ffffffffffffffff821117156117015761170161135b565b604052823581526020928301359281019290925250919050565b6000825160005b8181101561173c5760208186018101518583015201611722565b506000920191825250919050565b60006020828403121561175c57600080fd5b815180151581146114d457600080fd5b634e487b7160e01b600052601160045260246000fd5b8082018082111561038c5761038c61176c565b6000602082840312156117a757600080fd5b5051919050565b634e487b7160e01b600052600160045260246000fd5b634e487b7160e01b600052603260045260246000fd5b8181038181111561038c5761038c61176c565b634e487b7160e01b600052601260045260246000fd5b600082611812576118126117ed565b500490565b600060ff821660ff810361182d5761182d61176c565b60010192915050565b600082611845576118456117ed565b50069056fe30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47a2646970667358221220f867eebda0cc41be03734bcc11357c286ec4dbc522ad3b0d7d7eb33caf0f069864736f6c63430008190033",
}

// ContractABI is the input ABI used to generate the binding from.
// Deprecated: Use ContractMetaData.ABI instead.
var ContractABI = ContractMetaData.ABI

// ContractBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use ContractMetaData.Bin instead.
var ContractBin = ContractMetaData.Bin

// DeployContract deploys a new Ethereum contract, binding an instance of Contract to it.
func DeployContract(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *Contract, error) {
	parsed, err := ContractMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(ContractBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Contract{ContractCaller: ContractCaller{contract: contract}, ContractTransactor: ContractTransactor{contract: contract}, ContractFilterer: ContractFilterer{contract: contract}}, nil
}

// Contract is an auto generated Go binding around an Ethereum contract.
type Contract struct {
	ContractCaller     // Read-only binding to the contract
	ContractTransactor // Write-only binding to the contract
	ContractFilterer   // Log filterer for contract events
}

// ContractCaller is an auto generated read-only Go binding around an Ethereum contract.
type ContractCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContractTransactor is an auto generated write-only Go binding around an Ethereum contract.
type ContractTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContractFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type ContractFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContractSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type ContractSession struct {
	Contract     *Contract         // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// ContractCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type ContractCallerSession struct {
	Contract *ContractCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts   // Call options to use throughout this session
}

// ContractTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type ContractTransactorSession struct {
	Contract     *ContractTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// ContractRaw is an auto generated low-level Go binding around an Ethereum contract.
type ContractRaw struct {
	Contract *Contract // Generic contract binding to access the raw methods on
}

// ContractCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type ContractCallerRaw struct {
	Contract *ContractCaller // Generic read-only contract binding to access the raw methods on
}

// ContractTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type ContractTransactorRaw struct {
	Contract *ContractTransactor // Generic write-only contract binding to access the raw methods on
}

// NewContract creates a new instance of Contract, bound to a specific deployed contract.
func NewContract(address common.Address, backend bind.ContractBackend) (*Contract, error) {
	contract, err := bindContract(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Contract{ContractCaller: ContractCaller{contract: contract}, ContractTransactor: ContractTransactor{contract: contract}, ContractFilterer: ContractFilterer{contract: contract}}, nil
}

// NewContractCaller creates a new read-only instance of Contract, bound to a specific deployed contract.
func NewContractCaller(address common.Address, caller bind.ContractCaller) (*ContractCaller, error) {
	contract, err := bindContract(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &ContractCaller{contract: contract}, nil
}

// NewContractTransactor creates a new write-only instance of Contract, bound to a specific deployed contract.
func NewContractTransactor(address common.Address, transactor bind.ContractTransactor) (*ContractTransactor, error) {
	contract, err := bindContract(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &ContractTransactor{contract: contract}, nil
}

// NewContractFilterer creates a new log filterer instance of Contract, bound to a specific deployed contract.
func NewContractFilterer(address common.Address, filterer bind.ContractFilterer) (*ContractFilterer, error) {
	contract, err := bindContract(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &ContractFilterer{contract: contract}, nil
}

// bindContract binds a generic wrapper to an already deployed contract.
func bindContract(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := ContractMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Contract *ContractRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Contract.Contract.ContractCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Contract *ContractRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Contract.Contract.ContractTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Contract *ContractRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Contract.Contract.ContractTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Contract *ContractCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Contract.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Contract *ContractTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Contract.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Contract *ContractTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Contract.Contract.contract.Transact(opts, method, params...)
}

// ECTwistAdd is a free data retrieval call binding the contract method 0x61a931ec.
//
// Solidity: function ECTwistAdd(uint256 pt1xx, uint256 pt1xy, uint256 pt1yx, uint256 pt1yy, uint256 pt2xx, uint256 pt2xy, uint256 pt2yx, uint256 pt2yy) view returns(uint256, uint256, uint256, uint256)
func (_Contract *ContractCaller) ECTwistAdd(opts *bind.CallOpts, pt1xx *big.Int, pt1xy *big.Int, pt1yx *big.Int, pt1yy *big.Int, pt2xx *big.Int, pt2xy *big.Int, pt2yx *big.Int, pt2yy *big.Int) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "ECTwistAdd", pt1xx, pt1xy, pt1yx, pt1yy, pt2xx, pt2xy, pt2yx, pt2yy)

	if err != nil {
		return *new(*big.Int), *new(*big.Int), *new(*big.Int), *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)
	out1 := *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)
	out2 := *abi.ConvertType(out[2], new(*big.Int)).(**big.Int)
	out3 := *abi.ConvertType(out[3], new(*big.Int)).(**big.Int)

	return out0, out1, out2, out3, err

}

// ECTwistAdd is a free data retrieval call binding the contract method 0x61a931ec.
//
// Solidity: function ECTwistAdd(uint256 pt1xx, uint256 pt1xy, uint256 pt1yx, uint256 pt1yy, uint256 pt2xx, uint256 pt2xy, uint256 pt2yx, uint256 pt2yy) view returns(uint256, uint256, uint256, uint256)
func (_Contract *ContractSession) ECTwistAdd(pt1xx *big.Int, pt1xy *big.Int, pt1yx *big.Int, pt1yy *big.Int, pt2xx *big.Int, pt2xy *big.Int, pt2yx *big.Int, pt2yy *big.Int) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
	return _Contract.Contract.ECTwistAdd(&_Contract.CallOpts, pt1xx, pt1xy, pt1yx, pt1yy, pt2xx, pt2xy, pt2yx, pt2yy)
}

// ECTwistAdd is a free data retrieval call binding the contract method 0x61a931ec.
//
// Solidity: function ECTwistAdd(uint256 pt1xx, uint256 pt1xy, uint256 pt1yx, uint256 pt1yy, uint256 pt2xx, uint256 pt2xy, uint256 pt2yx, uint256 pt2yy) view returns(uint256, uint256, uint256, uint256)
func (_Contract *ContractCallerSession) ECTwistAdd(pt1xx *big.Int, pt1xy *big.Int, pt1yx *big.Int, pt1yy *big.Int, pt2xx *big.Int, pt2xy *big.Int, pt2yx *big.Int, pt2yy *big.Int) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
	return _Contract.Contract.ECTwistAdd(&_Contract.CallOpts, pt1xx, pt1xy, pt1yx, pt1yy, pt2xx, pt2xy, pt2yx, pt2yy)
}

// ECTwistMul is a free data retrieval call binding the contract method 0xb73ab75d.
//
// Solidity: function ECTwistMul(uint256 s, uint256 pt1xx, uint256 pt1xy, uint256 pt1yx, uint256 pt1yy) view returns(uint256, uint256, uint256, uint256)
func (_Contract *ContractCaller) ECTwistMul(opts *bind.CallOpts, s *big.Int, pt1xx *big.Int, pt1xy *big.Int, pt1yx *big.Int, pt1yy *big.Int) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "ECTwistMul", s, pt1xx, pt1xy, pt1yx, pt1yy)

	if err != nil {
		return *new(*big.Int), *new(*big.Int), *new(*big.Int), *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)
	out1 := *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)
	out2 := *abi.ConvertType(out[2], new(*big.Int)).(**big.Int)
	out3 := *abi.ConvertType(out[3], new(*big.Int)).(**big.Int)

	return out0, out1, out2, out3, err

}

// ECTwistMul is a free data retrieval call binding the contract method 0xb73ab75d.
//
// Solidity: function ECTwistMul(uint256 s, uint256 pt1xx, uint256 pt1xy, uint256 pt1yx, uint256 pt1yy) view returns(uint256, uint256, uint256, uint256)
func (_Contract *ContractSession) ECTwistMul(s *big.Int, pt1xx *big.Int, pt1xy *big.Int, pt1yx *big.Int, pt1yy *big.Int) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
	return _Contract.Contract.ECTwistMul(&_Contract.CallOpts, s, pt1xx, pt1xy, pt1yx, pt1yy)
}

// ECTwistMul is a free data retrieval call binding the contract method 0xb73ab75d.
//
// Solidity: function ECTwistMul(uint256 s, uint256 pt1xx, uint256 pt1xy, uint256 pt1yx, uint256 pt1yy) view returns(uint256, uint256, uint256, uint256)
func (_Contract *ContractCallerSession) ECTwistMul(s *big.Int, pt1xx *big.Int, pt1xy *big.Int, pt1yx *big.Int, pt1yy *big.Int) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
	return _Contract.Contract.ECTwistMul(&_Contract.CallOpts, s, pt1xx, pt1xy, pt1yx, pt1yy)
}

// GetFieldModulus is a free data retrieval call binding the contract method 0x55a3e90f.
//
// Solidity: function GetFieldModulus() pure returns(uint256)
func (_Contract *ContractCaller) GetFieldModulus(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "GetFieldModulus")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetFieldModulus is a free data retrieval call binding the contract method 0x55a3e90f.
//
// Solidity: function GetFieldModulus() pure returns(uint256)
func (_Contract *ContractSession) GetFieldModulus() (*big.Int, error) {
	return _Contract.Contract.GetFieldModulus(&_Contract.CallOpts)
}

// GetFieldModulus is a free data retrieval call binding the contract method 0x55a3e90f.
//
// Solidity: function GetFieldModulus() pure returns(uint256)
func (_Contract *ContractCallerSession) GetFieldModulus() (*big.Int, error) {
	return _Contract.Contract.GetFieldModulus(&_Contract.CallOpts)
}

// Balances is a free data retrieval call binding the contract method 0x27e235e3.
//
// Solidity: function balances(address ) view returns(uint256)
func (_Contract *ContractCaller) Balances(opts *bind.CallOpts, arg0 common.Address) (*big.Int, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "balances", arg0)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// Balances is a free data retrieval call binding the contract method 0x27e235e3.
//
// Solidity: function balances(address ) view returns(uint256)
func (_Contract *ContractSession) Balances(arg0 common.Address) (*big.Int, error) {
	return _Contract.Contract.Balances(&_Contract.CallOpts, arg0)
}

// Balances is a free data retrieval call binding the contract method 0x27e235e3.
//
// Solidity: function balances(address ) view returns(uint256)
func (_Contract *ContractCallerSession) Balances(arg0 common.Address) (*big.Int, error) {
	return _Contract.Contract.Balances(&_Contract.CallOpts, arg0)
}

// Empty is a free data retrieval call binding the contract method 0xf2a75fe4.
//
// Solidity: function empty() view returns()
func (_Contract *ContractCaller) Empty(opts *bind.CallOpts) error {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "empty")

	if err != nil {
		return err
	}

	return err

}

// Empty is a free data retrieval call binding the contract method 0xf2a75fe4.
//
// Solidity: function empty() view returns()
func (_Contract *ContractSession) Empty() error {
	return _Contract.Contract.Empty(&_Contract.CallOpts)
}

// Empty is a free data retrieval call binding the contract method 0xf2a75fe4.
//
// Solidity: function empty() view returns()
func (_Contract *ContractCallerSession) Empty() error {
	return _Contract.Contract.Empty(&_Contract.CallOpts)
}

// Expects is a free data retrieval call binding the contract method 0xe752b54b.
//
// Solidity: function expects(string ) view returns(uint256)
func (_Contract *ContractCaller) Expects(opts *bind.CallOpts, arg0 string) (*big.Int, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "expects", arg0)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// Expects is a free data retrieval call binding the contract method 0xe752b54b.
//
// Solidity: function expects(string ) view returns(uint256)
func (_Contract *ContractSession) Expects(arg0 string) (*big.Int, error) {
	return _Contract.Contract.Expects(&_Contract.CallOpts, arg0)
}

// Expects is a free data retrieval call binding the contract method 0xe752b54b.
//
// Solidity: function expects(string ) view returns(uint256)
func (_Contract *ContractCallerSession) Expects(arg0 string) (*big.Int, error) {
	return _Contract.Contract.Expects(&_Contract.CallOpts, arg0)
}

// GetTokenBalance is a free data retrieval call binding the contract method 0x3aecd0e3.
//
// Solidity: function getTokenBalance(address token) view returns(uint256)
func (_Contract *ContractCaller) GetTokenBalance(opts *bind.CallOpts, token common.Address) (*big.Int, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "getTokenBalance", token)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetTokenBalance is a free data retrieval call binding the contract method 0x3aecd0e3.
//
// Solidity: function getTokenBalance(address token) view returns(uint256)
func (_Contract *ContractSession) GetTokenBalance(token common.Address) (*big.Int, error) {
	return _Contract.Contract.GetTokenBalance(&_Contract.CallOpts, token)
}

// GetTokenBalance is a free data retrieval call binding the contract method 0x3aecd0e3.
//
// Solidity: function getTokenBalance(address token) view returns(uint256)
func (_Contract *ContractCallerSession) GetTokenBalance(token common.Address) (*big.Int, error) {
	return _Contract.Contract.GetTokenBalance(&_Contract.CallOpts, token)
}

// Pool is a free data retrieval call binding the contract method 0x18762262.
//
// Solidity: function pool(address , string ) view returns(uint256)
func (_Contract *ContractCaller) Pool(opts *bind.CallOpts, arg0 common.Address, arg1 string) (*big.Int, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "pool", arg0, arg1)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// Pool is a free data retrieval call binding the contract method 0x18762262.
//
// Solidity: function pool(address , string ) view returns(uint256)
func (_Contract *ContractSession) Pool(arg0 common.Address, arg1 string) (*big.Int, error) {
	return _Contract.Contract.Pool(&_Contract.CallOpts, arg0, arg1)
}

// Pool is a free data retrieval call binding the contract method 0x18762262.
//
// Solidity: function pool(address , string ) view returns(uint256)
func (_Contract *ContractCallerSession) Pool(arg0 common.Address, arg1 string) (*big.Int, error) {
	return _Contract.Contract.Pool(&_Contract.CallOpts, arg0, arg1)
}

// Deposit is a paid mutator transaction binding the contract method 0x80dfa405.
//
// Solidity: function Deposit(string GID) payable returns(bool)
func (_Contract *ContractTransactor) Deposit(opts *bind.TransactOpts, GID string) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "Deposit", GID)
}

// Deposit is a paid mutator transaction binding the contract method 0x80dfa405.
//
// Solidity: function Deposit(string GID) payable returns(bool)
func (_Contract *ContractSession) Deposit(GID string) (*types.Transaction, error) {
	return _Contract.Contract.Deposit(&_Contract.TransactOpts, GID)
}

// Deposit is a paid mutator transaction binding the contract method 0x80dfa405.
//
// Solidity: function Deposit(string GID) payable returns(bool)
func (_Contract *ContractTransactorSession) Deposit(GID string) (*types.Transaction, error) {
	return _Contract.Contract.Deposit(&_Contract.TransactOpts, GID)
}

// Expect is a paid mutator transaction binding the contract method 0xd1bef29f.
//
// Solidity: function Expect(string GID, uint256 ownerVal) payable returns(bool)
func (_Contract *ContractTransactor) Expect(opts *bind.TransactOpts, GID string, ownerVal *big.Int) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "Expect", GID, ownerVal)
}

// Expect is a paid mutator transaction binding the contract method 0xd1bef29f.
//
// Solidity: function Expect(string GID, uint256 ownerVal) payable returns(bool)
func (_Contract *ContractSession) Expect(GID string, ownerVal *big.Int) (*types.Transaction, error) {
	return _Contract.Contract.Expect(&_Contract.TransactOpts, GID, ownerVal)
}

// Expect is a paid mutator transaction binding the contract method 0xd1bef29f.
//
// Solidity: function Expect(string GID, uint256 ownerVal) payable returns(bool)
func (_Contract *ContractTransactorSession) Expect(GID string, ownerVal *big.Int) (*types.Transaction, error) {
	return _Contract.Contract.Expect(&_Contract.TransactOpts, GID, ownerVal)
}

// HashToG1 is a paid mutator transaction binding the contract method 0x129ee0f6.
//
// Solidity: function HashToG1(string str) payable returns((uint256,uint256))
func (_Contract *ContractTransactor) HashToG1(opts *bind.TransactOpts, str string) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "HashToG1", str)
}

// HashToG1 is a paid mutator transaction binding the contract method 0x129ee0f6.
//
// Solidity: function HashToG1(string str) payable returns((uint256,uint256))
func (_Contract *ContractSession) HashToG1(str string) (*types.Transaction, error) {
	return _Contract.Contract.HashToG1(&_Contract.TransactOpts, str)
}

// HashToG1 is a paid mutator transaction binding the contract method 0x129ee0f6.
//
// Solidity: function HashToG1(string str) payable returns((uint256,uint256))
func (_Contract *ContractTransactorSession) HashToG1(str string) (*types.Transaction, error) {
	return _Contract.Contract.HashToG1(&_Contract.TransactOpts, str)
}

// Reward is a paid mutator transaction binding the contract method 0xa12988bd.
//
// Solidity: function Reward(address addrU, address addrO, address[] addrsAA, string GID) payable returns(bool)
func (_Contract *ContractTransactor) Reward(opts *bind.TransactOpts, addrU common.Address, addrO common.Address, addrsAA []common.Address, GID string) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "Reward", addrU, addrO, addrsAA, GID)
}

// Reward is a paid mutator transaction binding the contract method 0xa12988bd.
//
// Solidity: function Reward(address addrU, address addrO, address[] addrsAA, string GID) payable returns(bool)
func (_Contract *ContractSession) Reward(addrU common.Address, addrO common.Address, addrsAA []common.Address, GID string) (*types.Transaction, error) {
	return _Contract.Contract.Reward(&_Contract.TransactOpts, addrU, addrO, addrsAA, GID)
}

// Reward is a paid mutator transaction binding the contract method 0xa12988bd.
//
// Solidity: function Reward(address addrU, address addrO, address[] addrsAA, string GID) payable returns(bool)
func (_Contract *ContractTransactorSession) Reward(addrU common.Address, addrO common.Address, addrsAA []common.Address, GID string) (*types.Transaction, error) {
	return _Contract.Contract.Reward(&_Contract.TransactOpts, addrU, addrO, addrsAA, GID)
}

// Withdraw is a paid mutator transaction binding the contract method 0xcb36594c.
//
// Solidity: function Withdraw(string GID) payable returns(bool)
func (_Contract *ContractTransactor) Withdraw(opts *bind.TransactOpts, GID string) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "Withdraw", GID)
}

// Withdraw is a paid mutator transaction binding the contract method 0xcb36594c.
//
// Solidity: function Withdraw(string GID) payable returns(bool)
func (_Contract *ContractSession) Withdraw(GID string) (*types.Transaction, error) {
	return _Contract.Contract.Withdraw(&_Contract.TransactOpts, GID)
}

// Withdraw is a paid mutator transaction binding the contract method 0xcb36594c.
//
// Solidity: function Withdraw(string GID) payable returns(bool)
func (_Contract *ContractTransactorSession) Withdraw(GID string) (*types.Transaction, error) {
	return _Contract.Contract.Withdraw(&_Contract.TransactOpts, GID)
}

// Negate is a paid mutator transaction binding the contract method 0xfb6b9e9a.
//
// Solidity: function negate((uint256,uint256) p) payable returns((uint256,uint256))
func (_Contract *ContractTransactor) Negate(opts *bind.TransactOpts, p DexG1Point) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "negate", p)
}

// Negate is a paid mutator transaction binding the contract method 0xfb6b9e9a.
//
// Solidity: function negate((uint256,uint256) p) payable returns((uint256,uint256))
func (_Contract *ContractSession) Negate(p DexG1Point) (*types.Transaction, error) {
	return _Contract.Contract.Negate(&_Contract.TransactOpts, p)
}

// Negate is a paid mutator transaction binding the contract method 0xfb6b9e9a.
//
// Solidity: function negate((uint256,uint256) p) payable returns((uint256,uint256))
func (_Contract *ContractTransactorSession) Negate(p DexG1Point) (*types.Transaction, error) {
	return _Contract.Contract.Negate(&_Contract.TransactOpts, p)
}

// ReceiveTokens is a paid mutator transaction binding the contract method 0x35729130.
//
// Solidity: function receiveTokens(address token, uint256 amount) returns()
func (_Contract *ContractTransactor) ReceiveTokens(opts *bind.TransactOpts, token common.Address, amount *big.Int) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "receiveTokens", token, amount)
}

// ReceiveTokens is a paid mutator transaction binding the contract method 0x35729130.
//
// Solidity: function receiveTokens(address token, uint256 amount) returns()
func (_Contract *ContractSession) ReceiveTokens(token common.Address, amount *big.Int) (*types.Transaction, error) {
	return _Contract.Contract.ReceiveTokens(&_Contract.TransactOpts, token, amount)
}

// ReceiveTokens is a paid mutator transaction binding the contract method 0x35729130.
//
// Solidity: function receiveTokens(address token, uint256 amount) returns()
func (_Contract *ContractTransactorSession) ReceiveTokens(token common.Address, amount *big.Int) (*types.Transaction, error) {
	return _Contract.Contract.ReceiveTokens(&_Contract.TransactOpts, token, amount)
}

// ContractTokensReceivedIterator is returned from FilterTokensReceived and is used to iterate over the raw logs and unpacked data for TokensReceived events raised by the Contract contract.
type ContractTokensReceivedIterator struct {
	Event *ContractTokensReceived // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ContractTokensReceivedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ContractTokensReceived)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ContractTokensReceived)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ContractTokensReceivedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ContractTokensReceivedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ContractTokensReceived represents a TokensReceived event raised by the Contract contract.
type ContractTokensReceived struct {
	Token  common.Address
	From   common.Address
	Amount *big.Int
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterTokensReceived is a free log retrieval operation binding the contract event 0x0af1239547617509a79d1ff0ee4be9ca943bc8410cb0b282dda97d27995a0acd.
//
// Solidity: event TokensReceived(address indexed token, address indexed from, uint256 amount)
func (_Contract *ContractFilterer) FilterTokensReceived(opts *bind.FilterOpts, token []common.Address, from []common.Address) (*ContractTokensReceivedIterator, error) {

	var tokenRule []interface{}
	for _, tokenItem := range token {
		tokenRule = append(tokenRule, tokenItem)
	}
	var fromRule []interface{}
	for _, fromItem := range from {
		fromRule = append(fromRule, fromItem)
	}

	logs, sub, err := _Contract.contract.FilterLogs(opts, "TokensReceived", tokenRule, fromRule)
	if err != nil {
		return nil, err
	}
	return &ContractTokensReceivedIterator{contract: _Contract.contract, event: "TokensReceived", logs: logs, sub: sub}, nil
}

// WatchTokensReceived is a free log subscription operation binding the contract event 0x0af1239547617509a79d1ff0ee4be9ca943bc8410cb0b282dda97d27995a0acd.
//
// Solidity: event TokensReceived(address indexed token, address indexed from, uint256 amount)
func (_Contract *ContractFilterer) WatchTokensReceived(opts *bind.WatchOpts, sink chan<- *ContractTokensReceived, token []common.Address, from []common.Address) (event.Subscription, error) {

	var tokenRule []interface{}
	for _, tokenItem := range token {
		tokenRule = append(tokenRule, tokenItem)
	}
	var fromRule []interface{}
	for _, fromItem := range from {
		fromRule = append(fromRule, fromItem)
	}

	logs, sub, err := _Contract.contract.WatchLogs(opts, "TokensReceived", tokenRule, fromRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ContractTokensReceived)
				if err := _Contract.contract.UnpackLog(event, "TokensReceived", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseTokensReceived is a log parse operation binding the contract event 0x0af1239547617509a79d1ff0ee4be9ca943bc8410cb0b282dda97d27995a0acd.
//
// Solidity: event TokensReceived(address indexed token, address indexed from, uint256 amount)
func (_Contract *ContractFilterer) ParseTokensReceived(log types.Log) (*ContractTokensReceived, error) {
	event := new(ContractTokensReceived)
	if err := _Contract.contract.UnpackLog(event, "TokensReceived", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
