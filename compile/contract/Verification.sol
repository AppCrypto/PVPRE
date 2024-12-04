// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
//pragma experimental ABIEncoderV2;

contract Verification
{
    struct Metadata {
        string ID;
        string Hash;
        int256 size;
        string description;
        uint timestamp;
    }

    // 存储已存在的 Metadata，映射 Hash 到 Metadata
    mapping(string => Metadata) public metadataRecords;


    // 所有权确权过程
    function UploadMetadata(string memory id, string memory filehash, int256 size, string memory desp, uint time) public payable {
        // require(bytes(metadataRecords[metadata.Hash].Hash).length == 0, "Metadata with this Hash already exists, the person does not have the ownership over the data");
        metadata.ID = id;
        metadata.Hash = filehash;
        metadata.size = size;
        metadata.description = desp;
        metadata.timestamp = time;
    }


    
    function addMetadata() public {
        // 检查是否已经有相同的Hash
        require(bytes(metadataRecords[metadata.Hash].Hash).length == 0, "Metadata with this Hash already exists, the person does not have the ownership over the data");
        // 存储新的Metadata
        metadataRecords[metadata.Hash] = metadata;
    }


    // struct OwnershipCertificate {
    //     string owner_ID;
    //     string Hash;
    //     int256 size;
    //     bool states;
    //     uint timestamp;
    // }

    // // 存储已存在的 OwnershipCertificate，映射 Hash 到 Metadata
    // mapping(string => OwnershipCertificate) public OwnershipCertificateRecords;

    // function addOwnerShipCertificate() public {
    //     require(bytes(OwnershipCertificateRecords[metadata.Hash].Hash).length == 0, "OwnershipCertificate with this Hash already exists, the person does not own the data");
    //     OwnershipCertificate memory newownership = OwnershipCertificate({
    //         owner_ID: metadata.ID,
    //         Hash : metadata.Hash,
    //         size : metadata.size,
    //         states : true,
    //         timestamp : block.timestamp
    //     });
    //     OwnershipCertificateRecords[metadata.Hash] = newownership;
    // }

    struct Request {
        string user_ID;
        string owner_ID;
        string Hash;
        uint timestamp;
    }

   
    // 申请使用权
    function UploadRequest(string memory user, string memory owner, string memory filehash, uint time) public payable {
        request.user_ID = user;
        request.owner_ID = owner;
        request.Hash = filehash;
        request.timestamp = time;
    }

    struct RightsofuseAudit {
        string user_ID;
        string[] authorizers_ID;
        string Hash;
        bool states;
        uint timestamp;
    }

    // 存储已存在的 RightsofuseAudit，映射 Hash 到 RightsofuseAudit
    mapping(string => RightsofuseAudit) public RightsofuseAuditRecords;

    // The authorizer who agrees to grant the right of use:
    string[] Authorizers_ID;
    function generateAuthorizers_ID() public returns (string[] memory) {
        for (uint i = 0; i < pp.t; i++) {
            Authorizers_ID.push(G1PointtoString(PKs[i]));
        }
        return Authorizers_ID;
    }

    // 行使控制权，记录使用权
    function addRightsofuseAudit() public {
        generateAuthorizers_ID();

        require(ReEncVerify(), "ReEncVerify failed, proxies do not to grant the right of use to the user.");
        
        RightsofuseAudit memory newuseAudit = RightsofuseAudit({
            user_ID: request.user_ID,
            authorizers_ID : Authorizers_ID,
            Hash : request.Hash,
            states : true,
            timestamp : block.timestamp
        });
        RightsofuseAuditRecords[request.Hash] = newuseAudit;
    }


    // OwnershipCertificate[] OCs;
    RightsofuseAudit[] RUAs;

    int public MDA_i = 50; // minimum deposited assets
    int public a = 6;
    int public b = 3;


    // 有限域的阶
    // p = p(u) = 36u^4 + 36u^3 + 24u^2 + 6u + 1
    uint256 constant FIELD_ORDER = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

    // Number of elements in the field (often called `q`)
    // n = n(u) = 36u^4 + 36u^3 + 18u^2 + 6u + 1
    // 循环群的阶

    uint256 constant GEN_ORDER = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    // 表示 bn128 椭圆曲线的一个常数参数 b 
    uint256 constant CURVE_B = 3;

    // a = (p+1) / 4,也是一个参数
    // 在一些算法中，这个值用来加速点乘法。
    uint256 constant CURVE_A = 0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52;

    // 定义群G1上的元素
    struct G1Point {
        uint X;
        uint Y;
    }

    // (P+1) / 4
    // 用于加速有限域中的平方根计算
    function A() pure internal returns (uint256) {
		return CURVE_A;
	}

    function P() pure internal returns (uint256) {
        return FIELD_ORDER;
    }

    // 返回有限域的阶
    function N() pure internal returns (uint256) {
		return GEN_ORDER;
	}

    /// return the generator of G1
	function P1() pure internal returns (G1Point memory) {
		return G1Point(1, 2);
	}

    // G1Point G1 = G1Point(1, 2);

    // 以太方上作模幂运算
    function expMod(uint256 _base, uint256 _exponent, uint256 _modulus)
        internal view returns (uint256 retval)
    {
        bool success;
        uint256[1] memory output;
        uint[6] memory input;
        input[0] = 0x20;        // baseLen = new(big.Int).SetBytes(getData(input, 0, 32))
        input[1] = 0x20;        // expLen  = new(big.Int).SetBytes(getData(input, 32, 32))
        input[2] = 0x20;        // modLen  = new(big.Int).SetBytes(getData(input, 64, 32))
        input[3] = _base;
        input[4] = _exponent;
        input[5] = _modulus;
        assembly {
            success := staticcall(sub(gas(), 2000), 5, input, 0xc0, output, 0x20)
            // Use "invalid" to make gas estimation work
            //switch success case 0 { invalid }
        }
        require(success);
        return output[0];
    }

    /// return the sum of two points of G1
	function g1add(G1Point memory p1, G1Point memory p2) view internal returns (G1Point memory r) {
		uint[4] memory input;
		input[0] = p1.X;
		input[1] = p1.Y;
		input[2] = p2.X;
		input[3] = p2.Y;
		bool success;
		assembly {
			success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
			// Use "invalid" to make gas estimation work
			//switch success case 0 { invalid }
            // success := call(not(0), 0x06, 0, input, 128, r, 64)
		}
		// require(success);
        require(success, "elliptic curve addition failed");
	}


    function g1mul(G1Point memory p, uint s) view internal returns (G1Point memory r) {
		uint[3] memory input;
		input[0] = p.X;
		input[1] = p.Y;
		input[2] = s;
		bool success;
		assembly {
			success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
			// Use "invalid" to make gas estimation work
			//switch success case 0 { invalid }
		}
		require(success, "elliptic curve multiplication failed");
	}

    function G1PointtoString(G1Point memory point) internal pure returns (string memory) {
        // 使用 abi.encodePacked 生成字节数组，然后将其转换为字符串
        return string(abi.encodePacked(point.X, point.Y));
    }

    
    // 将 G1Point 序列化为字节数组
    function serializeG1Point(G1Point memory point) internal pure returns (bytes memory) {
        return abi.encodePacked(point.X, point.Y);
    }

    function connect() public view returns (bytes memory) {
        // 拼接 pka 和 pkb
        bytes memory input = abi.encodePacked(serializeG1Point(pka),serializeG1Point(pkb));

        // 遍历 PKs 和 ckFrag，逐步拼接
        for (uint256 i = 0; i < PKs.length; i++) {
            input = abi.encodePacked(input, serializeG1Point(PKs[i]), serializeG1Point(ckFrag[i]));
        }
        return input;

    }

    function setBytes(bytes32 inputHash, uint256 start, uint256 end) internal pure returns (uint256) {
        uint256 value;
        for (uint256 i = start; i < end && i < 32; i++) {
            value = (value << 8) | uint8(inputHash[i]);
        }
        return value;
    }

    function hFunc(bytes memory input, uint256 n, uint256 t) public pure returns (uint256[] memory) {
        if (t == n || t == n - 1) {
            uint256[] memory singleValue = new uint256[](1);
            singleValue[0] = 1;
            return singleValue;
        }

        bytes32 Inputhash = sha256(input);
        uint256 numCoefficients = n - t - 1;
        uint256[] memory Coefficients = new uint256[](numCoefficients);
        uint256 coefLength = 32 / numCoefficients;

        if(coefLength == 0) {
            coefLength = 1;
        }

        uint256 index = 0;
        for(uint256 i = 0; i < numCoefficients; i++){
            uint256 start = index;
            uint256 end = index + coefLength;

            if(end > Inputhash.length) {
                end = Inputhash.length;
            }

            Coefficients[i] = setBytes(Inputhash, start, end);
            index = end;
        }

        if (numCoefficients > 32) {
            numCoefficients = 32;
        }

        uint256 leftoverBytes = 32 - (coefLength * numCoefficients);
         // 处理多余字节
        if (leftoverBytes > 0) {
            for (uint256 i = 0; i < leftoverBytes; i++) {
                
                // 从输入哈希中提取从i到末尾的字节片段
                uint256 start = i;
                uint256 end = Inputhash.length; // 我们提取从i到hash的末尾
                uint256 extractedBytes = setBytes(Inputhash, start, end);

                // 将提取的字节填充到系数中
                Coefficients[i%Coefficients.length] = extractedBytes;
            }
        }

        if (n - t - 1 >= 32) {
            for(uint i = 32; i < n-t-1; i++){
                Coefficients[i] = Coefficients[i % 32];
            }
        }

        return Coefficients;
    }


    function TestUV() public view returns (uint256[] memory) {
        bytes memory Hinput = connect();
        uint256[] memory Coefficients = new uint256[](pp.n - pp.t - 1);
        Coefficients = hFunc(Hinput, pp.n, pp.t);
        return Coefficients;
    }


    function evaluatePolynomial(uint256 x,uint256[] memory coefficients) public pure returns (uint256) {
        uint256 result = coefficients[0]; 
        uint256 xPower = x;
        // 遍历每个系数进行相应运算
        for (uint256 i = 1; i < coefficients.length; i++) {
            uint256 term = mulmod(coefficients[i], xPower, GEN_ORDER);

            result = addmod(result, term, GEN_ORDER);
            
            // 更新xPoewr = x^i
            xPower = mulmod(xPower, x, GEN_ORDER);
        }
        return result;
    }

    // 2
    function encodeG1Point(G1Point memory point) internal pure returns (bytes memory) {
    // 确保点的编码方式和 Go 的 Marshal 方法一致，使用非压缩格式
        bytes memory output;

        // 直接编码 X 和 Y 坐标为 32 字节大端格式，不再额外添加 0x04 前缀
        output = abi.encodePacked(toFixedBytes(point.X));
        output = abi.encodePacked(output, toFixedBytes(point.Y));

        return output;
    }

    // 将 uint 转换为固定的 32 字节大端格式
    function toFixedBytes(uint value) internal pure returns (bytes memory) {
        bytes memory result = new bytes(32);
        for (uint i = 0; i < 32; i++) {
            result[i] = bytes1(uint8(value >> (248 - i * 8))); // 每次右移 8 位，高位填充
        }
        return result;
    }

    function TestEvakuatePolvnomialcost() public payable {
        bytes memory Hinput = connect();
        // Hinput = connect();
        
        uint256[] memory coefficients = new uint256[](pp.n - pp.t - 1);
        coefficients = hFunc(Hinput, pp.n, pp.t);
        uint256[] memory mi = new uint256[] (pp.n);
        for (uint256 i = 0; i < PKs.length; i++) {
            // ReKeyVerificationResult.push(true);
            // return true;
            mi[i] = evaluatePolynomial(pp.Alpha[i+1],coefficients);
        }
    }

    function ReKeyVerify() public payable returns (bool) {

        bytes memory Hinput = connect();
        // Hinput = connect();
        
        uint256[] memory coefficients = new uint256[](pp.n - pp.t - 1);
        coefficients = hFunc(Hinput, pp.n, pp.t);
        // coefficients = hFunc(Hinput, pp.n, pp.t);

        G1Point memory V1;
        G1Point memory U1;
        uint256[] memory mi = new uint256[] (pp.n);
        for (uint256 i = 0; i < PKs.length; i++) {
            // ReKeyVerificationResult.push(true);
            // return true;
            mi[i] = evaluatePolynomial(pp.Alpha[i+1],coefficients);
        
            uint256 exp = mulmod(mi[i], pp.Vi[i], GEN_ORDER);
            // exp = exp % GEN_ORDER;
            G1Point memory result1 = g1mul(ckFrag[i], exp);
            V1 = g1add(result1, V1);
            G1Point memory result2 = g1mul(g1add(PKs[i], pkb), exp);
            U1 = g1add(result2, U1);

        }
        G1Point memory gG = g1mul(pp.g, DLEQProofReKey.z);
        G1Point memory y1G = g1mul(pka, DLEQProofReKey.c);
        G1Point memory hG = g1mul(U1, DLEQProofReKey.z);
        G1Point memory y2G = g1mul(V1, DLEQProofReKey.c);
        
        G1Point memory pt1 = g1add(gG, y1G);
        G1Point memory pt2 = g1add(hG, y2G);

        if ((DLEQProofReKey.a1.X != pt1.X) || (DLEQProofReKey.a1.Y != pt1.Y) || (DLEQProofReKey.a2.X != pt2.X) || (DLEQProofReKey.a2.Y != pt2.Y)) {
            ReKeyVerificationResult.push(false);
            return false;
        }
        ReKeyVerificationResult.push(true);
        return true;
    }

    function DisputeVerify() public payable returns (bool) {
        G1Point memory gG = g1mul(pp.g, DLEQProofDispute.z);
        G1Point memory y1G = g1mul(pkb, DLEQProofDispute.c);
        G1Point memory hG = g1mul(pka, DLEQProofDispute.z);
        G1Point memory y2G = g1mul(Dis.pkaskb, DLEQProofDispute.c);
        
        G1Point memory pt1 = g1add(gG, y1G);
        G1Point memory pt2 = g1add(hG, y2G);

        if ((DLEQProofDispute.a1.X != pt1.X) || (DLEQProofDispute.a1.Y != pt1.Y) || (DLEQProofDispute.a2.X != pt2.X) || (DLEQProofDispute.a2.Y != pt2.Y)) {
            DisputeVerificationResult.push(false);
            return false;
        }
        DisputeVerificationResult.push(true);
        return true;
    }

    function ReEncVerify() public payable returns (bool) {
       uint256 nums = 0;//记录通过验证的个数
        for (uint256 i = 0; i < DLEQProofReEncs.length; i++) {
            G1Point memory gG = g1mul(pp.g, DLEQProofReEncs[i].z);
            G1Point memory y1G = g1mul(PKs[i], DLEQProofReEncs[i].c);
            G1Point memory hG = g1mul(pka, DLEQProofReEncs[i].z);
            G1Point memory c2pneg = G1Point(C2p[i].X,FIELD_ORDER - C2p[i].Y % FIELD_ORDER);
            G1Point memory y2G = g1mul(g1add(ckFrag[i], c2pneg), DLEQProofReEncs[i].c);

            G1Point memory pt1 = g1add(gG, y1G);
            G1Point memory pt2 = g1add(hG, y2G);

            if ((DLEQProofReEncs[i].a1.X != pt1.X) || (DLEQProofReEncs[i].a1.Y != pt1.Y) || (DLEQProofReEncs[i].a2.X != pt2.X) || (DLEQProofReEncs[i].a2.Y != pt2.Y)) {
                ReEncVerificationResult.push(false);
            }
            else{
                nums = nums + 1;
                ReEncVerificationResult.push(true);
            }
        }
        if(nums >= pp.t) return true;
        else return false;
    }



    struct DleqProof {
        uint256 c;
        uint256 z;
        G1Point XG;
        G1Point XH;
        G1Point RG;
        G1Point RH;
    }


    struct DLEQProof {
        G1Point a1;
        G1Point a2;
        uint256 c;
        uint256 z;
    }

    struct Dispute {
        DLEQProof dleq;
        G1Point pkaskb;
    }

    struct Param {
        G1Point g;
        uint256 n;
        uint256 t;
        uint256[] Alpha;
        uint256[] Vi;
    }
    
    DLEQProof DLEQProofReKey;
    DLEQProof[] DLEQProofReEncs;
    DLEQProof DLEQProofDispute;
    Dispute Dis;
    // DleqProof[] dleqproofReEncs;
    G1Point pka;
    G1Point pkb;
    G1Point[] PKs;
    G1Point[] ckFrag;
    Param pp;
    bool[] ReKeyVerificationResult;
    bool[] ReEncVerificationResult;
    bool[] DisputeVerificationResult;
    G1Point[] C2p;
    
    // uint256[] coefficients;
    Metadata public metadata;
    Request request;
    RightsofuseAudit useAudit;
    G1Point U;
    G1Point V; 

    // bytes Hinput;

    function UploadParams(G1Point memory g,uint256 n, uint256 t, uint256[] memory Alpha, uint256[] memory Vi) public payable {
        
        pp.g = g;
        pp.n = n;
        pp.t = t;
        for (uint i = 0; i < Alpha.length; i++) {
            pp.Alpha.push(Alpha[i]);
        }
        for (uint i = 0; i < Vi.length; i++) {
            pp.Vi.push(Vi[i]);
        }
    }

    function UploadDelegatorPubkicKey(G1Point memory pkA) public payable {
        pka = pkA;
    }

    function UploadDelegateePublicKey(G1Point memory pkB) public payable {
        pkb = pkB;
    }

    function UploadProxyPublicKey(G1Point[] memory PKS) public payable {
        for (uint i = 0; i < PKS.length; i++) {
            PKs.push(PKS[i]);
        }
        // PKs = PKS;
    }

    function UploadckFrag(G1Point[] memory c) public payable {
        for (uint i = 0; i < c.length; i++) {
            ckFrag.push(c[i]);
        }
        // ckFrag = c;
    }

    function UploadC2p(G1Point[] memory c2p) public payable {
        for (uint i = 0; i < c2p.length; i++) {
            C2p.push(c2p[i]);
        }
        // C2p = c2p;
    }

    function UploadDLEQProofReKey(uint256 c, G1Point memory a1, G1Point memory a2, uint256 z) public payable {
        DLEQProofReKey.c = c;
        DLEQProofReKey.a1 = a1;
        DLEQProofReKey.a2 = a2;
        DLEQProofReKey.z = z;
    }

    function UploadDispute(uint256 c, G1Point memory a1, G1Point memory a2, uint256 z, G1Point memory PKAskb) public payable {
        DLEQProofDispute.c = c;
        DLEQProofDispute.a1 = a1;
        DLEQProofDispute.a2 = a2;
        DLEQProofDispute.z = z;
        Dis.pkaskb = PKAskb;
        Dis.dleq = DLEQProofDispute;
    }

    function UploadDLEQProofReEnc(uint256[] memory _c, G1Point[] memory _a1, G1Point[] memory _a2, uint256[] memory _z) public payable {
        DLEQProof memory DLEQProofReEnc;
        for (uint i = 0; i < _c.length; i++) {
            DLEQProofReEnc.a1 = _a1[i];
            DLEQProofReEnc.a2 = _a2[i];
            DLEQProofReEnc.c = _c[i];
            DLEQProofReEnc.z = _z[i];
            DLEQProofReEncs.push(DLEQProofReEnc);
        }
    }


    function GetReKeyVrfResult() public view returns (bool []memory) {
        return ReKeyVerificationResult;
    }

    function GetReEncVrfResult() public view returns (bool [] memory) {
        return ReEncVerificationResult;
    }

    function GetDisputeVrfResult() public view returns (bool [] memory){
        return DisputeVerificationResult;
    }



    // ==========================================================================================================================================================
    // Test Umbral:
    // Function to hash concatenated G1 points into a single value


    // struct Par {
    //     G1Point G;
    //     uint256 Q;
    //     G1Point U;
    //     uint256 N;
    //     uint256 T;
    // }

    // struct Capsule {
    //     G1Point E;
    //     G1Point Vv;
    //     // uint256 s;
    // }

    // struct CFrag {
    //     G1Point E1;
    //     G1Point V1;
    //     uint256 Id;
    //     G1Point X;
    // }

    // struct Pi {
    //     G1Point E2;
    //     G1Point V2;
    //     G1Point U2;
    //     G1Point U1;  
    //     uint256 Z1;  
    //     uint256 Z2;  
    //     uint256 Rou; 
    //     G1Point Aux; 
    // }


    // struct G1Points {
    //     G1Point E;
    //     G1Point E1;
    //     G1Point E2;
    //     G1Point Vv;
    //     G1Point V1;
    //     G1Point V2;
    //     G1Point Uu;
    //     G1Point U1;
    //     G1Point U2;
    //     G1Point aux;
    // }

    // Par par;
    // Capsule cap;
    // CFrag[] cfrags;
    // Pi[] pis;
    // bool[] UmbralVerificationResult;

    // function UploadPar(G1Point memory g,uint256 q,G1Point memory u, uint256 n, uint256 t) public payable {
    //     par.G = g;
    //     par.Q = q;
    //     par.U = u;
    //     par.N = n;
    //     par.T = t;
    // }

    // function UploadCapsule(G1Point memory e, G1Point memory vv) public payable {
    //     cap.E = e;
    //     cap.Vv = vv;
    //     // cap.s = s;
    // }

    // function UploadCFrag(G1Point[] memory e1, G1Point[] memory v1, uint256[] memory id, G1Point[] memory x) public payable {
    //     CFrag memory cfrag;
    //     for(uint i = 0;i < e1.length; i ++){
    //         cfrag.E1 = e1[i];
    //         cfrag.V1 = v1[i];
    //         cfrag.Id = id[i];
    //         cfrag.X = x[i];
    //         cfrags.push(cfrag);
    //     }
    // }

    // function UploadPi(G1Point[] memory e2, G1Point[] memory v2, G1Point[] memory u2, G1Point[] memory u1, uint256[] memory z1, uint256[] memory z2, uint256[] memory rou, G1Point[] memory aux) public payable {
    //     Pi memory pi;
    //     for(uint i = 0; i < e2.length; i ++) {
    //         pi.E2 = e2[i];
    //         pi.V2 = v2[i];
    //         pi.U2 = u2[i];
    //         pi.U1 = u1[i];
    //         pi.Z1 = z1[i] % GEN_ORDER;
    //         pi.Z2 = z2[i] % GEN_ORDER;
    //         pi.Rou = rou[i] % GEN_ORDER;
    //         pi.Aux = aux[i];
    //         pis.push(pi);
    //     }
    // }

    // function H(
    //     G1Points memory points
    // ) public view returns (uint256) {
    //     // Concatenate all G1 points' X and Y values
    //     // 第一组数据：E 和 E1
    //     bytes memory part1 = abi.encode(points.E.X, points.E.Y, points.E1.X, points.E1.Y);

    //     // 第二组数据：E2 和 Vv
    //     bytes memory part2 = abi.encode(points.E2.X, points.E2.Y, points.Vv.X, points.Vv.Y);

    //     // 第三组数据：V1 和 V2
    //     bytes memory part3 = abi.encode(points.V1.X, points.V1.Y, points.V2.X, points.V2.Y);

    //     // 第四组数据：Uu 和 U1
    //     bytes memory part4 = abi.encode(points.Uu.X, points.Uu.Y, points.U1.X, points.U1.Y);

    //     // 第五组数据：U2 和 aux
    //     bytes memory part5 = abi.encode(points.U2.X, points.U2.Y, points.aux.X, points.aux.Y);

    //     // 合并所有小块数据
    //     bytes memory data = abi.encodePacked(part1, part2, part3, part4, part5);

    //     // Perform the sha256 hash of the concatenated data
    //     bytes32 hash = sha256(data);
        
    //     // Convert the hash to uint256 and mod by Q
    //     uint256 hashInt = uint256(hash);
    //     return hashInt % par.Q;
    // }


    // function UmbralVerify() public payable returns (bool) {
    //     uint256 nums = 0;//记录通过验证的个数
    //     for(uint i = 0; i < par.N; i++) {
    //         G1Points memory points = G1Points({
    //             E: cap.E,
    //             E1: cfrags[i].E1,
    //             E2: pis[i].E2,
    //             Vv: cap.Vv,
    //             V1: cfrags[i].V1,
    //             V2: pis[i].V2,
    //             Uu: par.U,
    //             U1: pis[i].U1,
    //             U2: pis[i].U2,
    //             aux: pis[i].Aux
    //         });
    //         uint256 h = H(points);
    //         G1Point memory l1 = g1mul(cap.E, pis[i].Rou);
    //         G1Point memory temp1 = g1mul(cfrags[i].E1, h);
    //         G1Point memory r1 = g1add(pis[i].E2, temp1);
    //         G1Point memory l2 = g1mul(cap.Vv, pis[i].Rou);
    //         G1Point memory temp2 = g1mul(cfrags[i].V1, h);
    //         G1Point memory r2 = g1add(pis[i].V2, temp2);
    //         G1Point memory l3 = g1mul(par.U, pis[i].Rou);
    //         G1Point memory temp3 = g1mul(pis[i].U1, h);
    //         G1Point memory r3 = g1add(pis[i].U2, temp3);
    //         // || (l2.X != r2.X) || (l2.Y != r2.Y) || (l3.X != r3.X) || (l3.Y != r3.Y)

    //         if ((l1.X != r1.X) || (l1.Y != r1.Y) || (l2.X != r2.X) || (l2.Y != r2.Y) || (l3.X != r3.X) || (l3.Y != r3.Y)) {
    //             UmbralVerificationResult.push(false);
    //         }
    //         else {
    //             UmbralVerificationResult.push(true);
    //             nums = nums + 1;
    //         }
    //     }
    //     if(nums >= par.T) return true;
    //     else return false;
    // }

    // function GetUmbralVerificationResult() public view returns (bool []memory) {
    //     return UmbralVerificationResult;
    // }

    // ==========================================================================================================================================================
}