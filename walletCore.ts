import { v4 as uuidv4 } from 'uuid';
import { syncScrypt } from 'scrypt-js'
import { hdkey } from "ethereumjs-wallet";
import * as ethUtil from 'ethereumjs-util';
import * as sigUtil from "das-eth-sig-util";
import * as crypto from 'crypto'
import * as bip39 from "bip39";

interface V3Keystore {
    version: number;
    id: string;
    address: string;
    crypto: {
        cipher: string;
        cipherparams: {
            iv: string;
        }
        ciphertext: string;
        kdf: string;
        kdfparams: {
            dklen: number;
            salt: string;
            n?: number;
            r?: number;
            p?: number;
            c?: number;
            prf?: string;
        };
        mac: string;
    };
}

export interface SigUtilMessageTypeProperty {
    name: string;
    type: string;
}

export interface SigUtilMessageTypes {
    EIP712Domain: SigUtilMessageTypeProperty[];
    [additionalProperties: string]: SigUtilMessageTypeProperty[];
}

export interface TransactionConfig {
    nonce: number;
    to: string;
    gas: number | string;
    gasPrice?: number | string;
    maxPriorityFeePerGas?: number | string;
    maxFeePerGas?: number | string;
    value?: number | string;
    data?: string;
    chainId?: number;
    accessList?: Array<{
        address: string;
        storageKeys: string[];
    }>;
}

export interface SignedTransaction {
    messageHash: string;
    rawTransaction: string;
    transactionHash: string;
    r: string;
    s: string;
    v: string;
}

export class Account {

    /**
     * 地址
     */
    public address: string;

    /**
     * 私钥
     */
    public privateKey: string;

    /**
     * 私钥
     */
    private privateKeyBuffer: Buffer;

    /**
     * 初始化
     * @param privateKey 私钥
     */
    constructor(privateKey: string) {
        this.privateKey = privateKey;
        this.privateKeyBuffer = Buffer.from("0x" === privateKey.slice(0, 2)
            ? privateKey.slice(2)
            : privateKey, "hex"
        );
        let address = ethUtil.privateToAddress(this.privateKeyBuffer);
        this.address = ethUtil.toChecksumAddress(ethUtil.bufferToHex(address));
    }

    /**
     * 签名交易
     * @param config
     */
    public signTransaction(config: TransactionConfig): SignedTransaction {

        let result = null;
        let EIP155 = "number" === typeof (config.chainId);
        let EIP1559 = "string" === typeof (config.maxFeePerGas) || "number" === typeof (config.maxFeePerGas);
        let EIP2930 = true === Array.isArray(config.accessList) && config.accessList.length > 0;

        // 验证发送地址
        if (false === Util.isValidAddress(config.to)) {
            throw new Error("address " + config.to + " is invalid");
        }

        // 验证数据
        if (typeof (config.data) === "string" && false === Util.isHexString(config.data)) {
            throw new Error("data " + config.data + " is invalid");
        }

        if (true === EIP1559) {

            // 访问列表
            let accessList = [];
            if (true === Array.isArray(config.accessList)) {
                accessList = Util.toBufferAccessList(config.accessList);
            }

            // 交易类型2
            let TRANSACTION_TYPE = 2;
            let TRANSACTION_TYPE_BUFFER = Buffer.from(TRANSACTION_TYPE.toString(16).padStart(2, '0'), 'hex');

            // 使用 maxFeePerGas 和 maxPriorityFeePerGas
            let values = [
                ethUtil.bnToUnpaddedBuffer(Util.toBN(config.chainId)),
                ethUtil.bnToUnpaddedBuffer(Util.toBN(config.nonce)),
                ethUtil.bnToUnpaddedBuffer(Util.toBN(config.maxPriorityFeePerGas)),
                ethUtil.bnToUnpaddedBuffer(Util.toBN(config.maxFeePerGas)),
                ethUtil.bnToUnpaddedBuffer(Util.toBN(config.gas)),
                Buffer.from(config.to.slice(2), "hex"),
                ethUtil.bnToUnpaddedBuffer(Util.toBN(config.value)),
                "string" === typeof (config.data)
                    ? Buffer.from(config.data.slice(2), "hex")
                    : Buffer.from([]),
                accessList
            ];

            // 签名
            let msgHash = ethUtil.keccak256(Buffer.concat([TRANSACTION_TYPE_BUFFER, ethUtil.rlp.encode(values)]));
            let sig = ethUtil.ecsign(msgHash, this.privateKeyBuffer);
            let v = "0x" + (sig.v - 27).toString(16);
            let r = "0x" + sig.r.toString("hex");
            let s = "0x" + sig.s.toString("hex");

            // 交易信息
            values.push(ethUtil.bnToUnpaddedBuffer(Util.toBN(v)));
            values.push(ethUtil.bnToUnpaddedBuffer(Util.toBN(r)));
            values.push(ethUtil.bnToUnpaddedBuffer(Util.toBN(s)));
            let rawTransaction = Buffer.concat([TRANSACTION_TYPE_BUFFER, ethUtil.rlp.encode(values)]);
            let transactionHash = ethUtil.keccak256(rawTransaction);

            result = {
                messageHash: "0x" + msgHash.toString("hex"),
                rawTransaction: "0x" + rawTransaction.toString("hex"),
                transactionHash: "0x" + transactionHash.toString("hex"),
                v: v,
                r: r,
                s: s
            };
        }
        else if (true === EIP2930) {

            // 访问列表
            let accessList = [];
            if (true === Array.isArray(config.accessList)) {
                accessList = Util.toBufferAccessList(config.accessList);
            }

            // 交易类型1
            let TRANSACTION_TYPE = 1;
            let TRANSACTION_TYPE_BUFFER = Buffer.from(TRANSACTION_TYPE.toString(16).padStart(2, '0'), 'hex');

            // 增加了 accessList
            let values = [
                ethUtil.bnToUnpaddedBuffer(Util.toBN(config.chainId)),
                ethUtil.bnToUnpaddedBuffer(Util.toBN(config.nonce)),
                ethUtil.bnToUnpaddedBuffer(Util.toBN(config.gasPrice)),
                ethUtil.bnToUnpaddedBuffer(Util.toBN(config.gas)),
                Buffer.from(config.to.slice(2), "hex"),
                ethUtil.bnToUnpaddedBuffer(Util.toBN(config.value)),
                "string" === typeof (config.data)
                    ? Buffer.from(config.data.slice(2), "hex")
                    : Buffer.from([]),
                accessList,
            ];

            // 签名
            let msgHash = ethUtil.keccak256(Buffer.concat([TRANSACTION_TYPE_BUFFER, ethUtil.rlp.encode(values)]));
            let sig = ethUtil.ecsign(msgHash, this.privateKeyBuffer);
            let v = "0x" + (sig.v - 27).toString(16);
            let r = "0x" + sig.r.toString("hex");
            let s = "0x" + sig.s.toString("hex");

            // 交易信息
            values.push(ethUtil.bnToUnpaddedBuffer(Util.toBN(v)));
            values.push(ethUtil.bnToUnpaddedBuffer(Util.toBN(r)));
            values.push(ethUtil.bnToUnpaddedBuffer(Util.toBN(s)));
            let rawTransaction = Buffer.concat([TRANSACTION_TYPE_BUFFER, ethUtil.rlp.encode(values)]);
            let transactionHash = ethUtil.keccak256(rawTransaction);

            result = {
                messageHash: "0x" + msgHash.toString("hex"),
                rawTransaction: "0x" + rawTransaction.toString("hex"),
                transactionHash: "0x" + transactionHash.toString("hex"),
                v: v,
                r: r,
                s: s
            };
        }
        else {

            // 旧版本
            let values = [
                ethUtil.bnToUnpaddedBuffer(Util.toBN(config.nonce)),
                ethUtil.bnToUnpaddedBuffer(Util.toBN(config.gasPrice)),
                ethUtil.bnToUnpaddedBuffer(Util.toBN(config.gas)),
                Buffer.from(config.to.slice(2), "hex"),
                ethUtil.bnToUnpaddedBuffer(Util.toBN(config.value)),
                "string" === typeof (config.data)
                    ? Buffer.from(config.data.slice(2), "hex")
                    : Buffer.from([])
            ];

            // 增加了链ID校验
            if (true === EIP155) {
                values.push(ethUtil.toBuffer(config.chainId));
                values.push(ethUtil.unpadBuffer(ethUtil.toBuffer(0)));
                values.push(ethUtil.unpadBuffer(ethUtil.toBuffer(0)));
            }

            // 签名
            let msgHash = ethUtil.keccak256(ethUtil.rlp.encode(values));
            let sig = ethUtil.ecsign(msgHash, this.privateKeyBuffer);
            let v = "0x" + (sig.v).toString(16);
            let r = "0x" + sig.r.toString("hex");
            let s = "0x" + sig.s.toString("hex");

            // 特殊处理
            if (true === EIP155) {
                v = "0x" + (sig.v + config.chainId * 2 + 8).toString(16);
            }

            // 交易信息
            values = values.slice(0, 6);
            values.push(ethUtil.bnToUnpaddedBuffer(Util.toBN(v)));
            values.push(ethUtil.bnToUnpaddedBuffer(Util.toBN(r)));
            values.push(ethUtil.bnToUnpaddedBuffer(Util.toBN(s)));
            let rawTransaction = ethUtil.rlp.encode(values);
            let transactionHash = ethUtil.keccak256(rawTransaction);

            result = {
                messageHash: "0x" + msgHash.toString("hex"),
                rawTransaction: "0x" + rawTransaction.toString("hex"),
                transactionHash: "0x" + transactionHash.toString("hex"),
                v: v,
                r: r,
                s: s
            };
        }

        return result;
    }

    /**
     * 签名
     * @param data
     * @param hashMessage
     * @param chainId
     */
    public sign(data: string, hashMessage?: boolean, chainId?: number): string {
        let message = Util.legacyToBuffer(data);
        let msgHash = hashMessage ? message : ethUtil.keccak256(message);
        let sig = ethUtil.ecsign(msgHash, this.privateKeyBuffer, chainId);
        let serialized = sigUtil.concatSig(ethUtil.toBuffer(sig.v), sig.r, sig.s);
        return serialized;
    }

    /**
     * 签名
     * @param msg
     */
    public personalSign(msg: string): string {
        return sigUtil.personalSign(this.privateKeyBuffer, { data: msg });
    }

    /**
     * 签名
     * @param data
     * @param version
     */
    public signTypedData(data: sigUtil.TypedMessage<SigUtilMessageTypes>, version: sigUtil.Version = "V4"): string {
        return sigUtil.signTypedData(this.privateKeyBuffer, {
            data: data
        }, version);
    }
}

export class WalletCore {

    /**
     * 创建助记词
     * @param strength 128 = 12个词， 256 = 24个词
     */
    public createMnemonic(strength: 128 | 256 = 128): string {
        let mnemonic = bip39.generateMnemonic(strength);
        return mnemonic;
    }

    /**
     * 创建账户
     * @param mnemonic 助记词
     * @param i 推导序号
     */
    public createAccount(mnemonic: string, i: number = 0): Account {

        let seed = bip39.mnemonicToSeedSync(mnemonic)
        let hdWallet = hdkey.fromMasterSeed(seed);

        // BIP44规范 m / purpose' / coin_type' / account' / change / address_index
        let key = hdWallet.derivePath("m/44'/60'/0'/0/" + i.toString());
        let privateKey = key.getWallet().getPrivateKeyString();
        
        return new Account(privateKey);
    }

    /**
     * 加密私钥
     * @param privateKey 私钥
     * @param password 密码
     */
    public privateKeyToKeystore(privateKey: string, password: string): string {

        if ("0x" !== privateKey.slice(0, 2)) {
            privateKey = "0x" + privateKey;
        }

        let v3Params = {
            cipher: 'aes-128-ctr',
            kdf: 'scrypt',
            salt: crypto.randomBytes(32),
            iv: crypto.randomBytes(16),
            uuid: crypto.randomBytes(16),
            dklen: 32,
            c: 262144,
            n: 262144,
            r: 8,
            p: 1
        };

        let kdfParams, derivedKey: Uint8Array;
        if (v3Params.kdf === 'pbkdf2') {
            kdfParams = {
                dklen: v3Params.dklen,
                salt: v3Params.salt,
                c: v3Params.c,
                prf: 'hmac-sha256',
            };
            derivedKey = crypto.pbkdf2Sync(
                Buffer.from(password),
                kdfParams.salt,
                kdfParams.c,
                kdfParams.dklen,
                'sha256'
            );
        }
        else if (v3Params.kdf === 'scrypt') {
            kdfParams = {
                dklen: v3Params.dklen,
                salt: v3Params.salt,
                n: v3Params.n,
                r: v3Params.r,
                p: v3Params.p,
            };
            derivedKey = syncScrypt(
                Buffer.from(password),
                kdfParams.salt,
                kdfParams.n,
                kdfParams.r,
                kdfParams.p,
                kdfParams.dklen
            );
        }
        else {
            throw new Error('Unsupported kdf')
        }

        let cipher: crypto.Cipher = crypto.createCipheriv(
            v3Params.cipher,
            derivedKey.slice(0, 16),
            v3Params.iv
        );

        if (!cipher) {
            throw new Error('Unsupported cipher');
        }

        let ciphertext = Buffer.concat([
            cipher.update(Buffer.from(privateKey.slice(2), 'hex')),
            cipher.final()
        ]);

        let mac = ethUtil.keccak256(
            Buffer.concat([Buffer.from(derivedKey.slice(16, 32)), Buffer.from(ciphertext)])
        );

        let json: V3Keystore = {
            version: 3,
            id: uuidv4({ random: v3Params.uuid }),
            // the official V3 keystore spec omits the address key
            address: ethUtil.bufferToHex(ethUtil.privateToAddress(Buffer.from(privateKey.slice(2), 'hex'))),
            crypto: {
                ciphertext: ciphertext.toString('hex'),
                cipherparams: { iv: v3Params.iv.toString('hex') },
                cipher: v3Params.cipher,
                kdf: v3Params.kdf,
                kdfparams: {
                    ...kdfParams,
                    salt: kdfParams.salt.toString('hex'),
                },
                mac: mac.toString('hex')
            }
        };

        return JSON.stringify(json);
    }

    /**
     * 解密私钥
     * @param keystore 安全文件
     * @param password 密码
     */
    public keystoreToPrivateKey(keystore: string, password: string): string {

        let json: V3Keystore = JSON.parse(keystore.toLowerCase());

        if (json.version !== 3) {
            throw new Error('Not a V3 wallet');
        }

        let derivedKey: Uint8Array;
        let kdfparams = json.crypto.kdfparams;
        if (json.crypto.kdf === 'scrypt') {

            // FIXME: support progress reporting callback
            derivedKey = syncScrypt(
                Buffer.from(password),
                Buffer.from(kdfparams.salt, 'hex'),
                kdfparams.n,
                kdfparams.r,
                kdfparams.p,
                kdfparams.dklen
            );
        }
        else if (json.crypto.kdf === 'pbkdf2') {

            if (kdfparams.prf !== 'hmac-sha256') {
                throw new Error('Unsupported parameters to PBKDF2');
            }

            derivedKey = crypto.pbkdf2Sync(
                Buffer.from(password),
                Buffer.from(kdfparams.salt, 'hex'),
                kdfparams.c,
                kdfparams.dklen,
                'sha256'
            );
        }
        else {
            throw new Error('Unsupported key derivation scheme');
        }

        let ciphertext = Buffer.from(json.crypto.ciphertext, 'hex');
        let mac = ethUtil.keccak256(Buffer.concat([Buffer.from(derivedKey.slice(16, 32)), ciphertext]));
        if (mac.toString('hex').toLowerCase() !== json.crypto.mac) {
            throw new Error('Key derivation failed - possibly wrong passphrase');
        }

        let decipher = crypto.createDecipheriv(json.crypto.cipher, derivedKey.slice(0, 16), Buffer.from(json.crypto.cipherparams.iv, 'hex'));
        let seed = '0x' + Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('hex');
        return seed;
    }

    /**
     * 私钥转为账户
     * @param privateKey 私钥
     */
    public privateKeyToAccount(privateKey: string): Account {
        return new Account(privateKey);
    }

    /**
     * 验证签名
     * @param data
     * @param signature
     * @param hashMessage
     * @param chainId
     */
    public recoverSignature(data: string, signature: string, hashMessage?: boolean, chainId?: number): string {

        let message = Util.legacyToBuffer(data);
        let msgHash = hashMessage ? message : ethUtil.keccak256(message);

        let sigParams = ethUtil.fromRpcSig(signature);
        let publicKey = ethUtil.ecrecover(msgHash, sigParams.v, sigParams.r, sigParams.s, chainId);

        let sender = ethUtil.publicToAddress(publicKey);
        let senderHex = ethUtil.bufferToHex(sender);
        return senderHex;
    }

    /**
     * 验证签名
     * @param msg
     * @param signature
     */
    public recoverPersonalSignature(msg: string, signature: string): string {
        return sigUtil.recoverPersonalSignature({ data: msg, sig: signature });
    }

    /**
     * 验证签名
     * @param data
     * @param version
     */
    public recoverTypedSignature(data: sigUtil.TypedMessage<SigUtilMessageTypes>, signature: string, version: sigUtil.Version = "V4"): string {
        return sigUtil.recoverTypedSignature({ data: data, sig: signature }, version);
    }

    /**
     * 验证签名
     * @param rawTransaction
     */
    public recoverTransaction(rawTransaction: string): string {

        let result = "";
        let type = parseInt(rawTransaction.slice(0, 4), 16);
        if (type >= 128) type = 0; // 0 - 127

        if (0 === type) {

            let values = <Buffer[]>ethUtil.rlp.decode(rawTransaction);
            let v = Util.bufferToNumber(values[values.length - 3]);
            let r = values[values.length - 2];
            let s = values[values.length - 1];
            values = values.slice(0, values.length - 3);
            
            // EIP155 spec:
            // Txs need either v = 27/28 or v >= 37 (EIP-155 replay protection)
            // If block.number >= 2,675,000 and v = CHAIN_ID * 2 + 35 or v = CHAIN_ID * 2 + 36, then when computing the hash of a transaction for purposes of signing or recovering, instead of hashing only the first six elements (i.e. nonce, gasprice, startgas, to, value, data), hash nine elements, with v replaced by CHAIN_ID, r = 0 and s = 0.
            let EIP155 = v >= 37;
            if (true === EIP155) {
                let chainId = Util.isEven(v - 35)
                    ? (v - 35) / 2
                    : (v - 36) / 2;
                v = v - chainId * 2 - 8;
                values.push(ethUtil.toBuffer(chainId));
                values.push(ethUtil.unpadBuffer(ethUtil.toBuffer(0)));
                values.push(ethUtil.unpadBuffer(ethUtil.toBuffer(0)));
            }

            let msg = ethUtil.rlp.encode(values);
            let msgHash = ethUtil.keccak256(msg);

            let publicKey = ethUtil.ecrecover(msgHash, v, r, s);
            let sender = ethUtil.publicToAddress(publicKey);
            let senderHex = ethUtil.bufferToHex(sender);

            result = senderHex;
        }
        else if (1 === type) {

            let TRANSACTION_TYPE = 1;
            let TRANSACTION_TYPE_BUFFER = Buffer.from(TRANSACTION_TYPE.toString(16).padStart(2, '0'), 'hex');

            let values = <Buffer[]>ethUtil.rlp.decode("0x" + rawTransaction.slice(4));
            let v = Util.bufferToNumber(values[values.length - 3]) + 27;
            let r = values[values.length - 2];
            let s = values[values.length - 1];
            values = values.slice(0, values.length - 3);

            let msg = Buffer.concat([TRANSACTION_TYPE_BUFFER, ethUtil.rlp.encode(values)]);
            let msgHash = ethUtil.keccak256(msg);

            let publicKey = ethUtil.ecrecover(msgHash, v, r, s);
            let sender = ethUtil.publicToAddress(publicKey);
            let senderHex = ethUtil.bufferToHex(sender);

            result = senderHex;
        }
        else if (2 === type) {

            let TRANSACTION_TYPE = 2;
            let TRANSACTION_TYPE_BUFFER = Buffer.from(TRANSACTION_TYPE.toString(16).padStart(2, '0'), 'hex');

            let values = <Buffer[]>ethUtil.rlp.decode("0x" + rawTransaction.slice(4));
            let v = Util.bufferToNumber(values[values.length - 3]) + 27;
            let r = values[values.length - 2];
            let s = values[values.length - 1];
            values = values.slice(0, values.length - 3);

            let msg = Buffer.concat([TRANSACTION_TYPE_BUFFER, ethUtil.rlp.encode(values)]);
            let msgHash = ethUtil.keccak256(msg);

            let publicKey = ethUtil.ecrecover(msgHash, v, r, s);
            let sender = ethUtil.publicToAddress(publicKey);
            let senderHex = ethUtil.bufferToHex(sender);

            result = senderHex;
        }

        return result;
    }

    /**
     * 解析交易信息
     * @param rawTransaction
     */
    public decodeRawTransaction(rawTransaction: string): TransactionConfig {

        let result = null;
        let type = parseInt(rawTransaction.slice(0, 4), 16);
        if (type >= 128) type = 0;

        if (0 === type) {

            let chainId = void 0;
            let values = <Buffer[]>ethUtil.rlp.decode(rawTransaction);
            let v = Util.bufferToNumber(values[values.length - 3]);

            let EIP155 = v >= 37;
            if (true === EIP155) {
                chainId = Util.isEven(v - 35) ? (v - 35) / 2 : (v - 36) / 2;
                v = v - chainId * 2 - 8;
            }

            result = {
                nonce: Util.bufferToNumber(values[0]),
                to: Util.bufferToHex(values[3]),
                gas: Util.bufferToNumber(values[2]),
                gasPrice: Util.bufferToStringNumber(values[1]),
                value: Util.bufferToStringNumber(values[4]),
                data: Util.bufferToHex(values[5]),
                chainId: chainId
            };
        }
        else if (1 === type) {

            let values = <Buffer[]>ethUtil.rlp.decode("0x" + rawTransaction.slice(4));
            result = {
                nonce: Util.bufferToNumber(values[1]),
                to: Util.bufferToHex(values[4]),
                gas: Util.bufferToNumber(values[3]),
                gasPrice: Util.bufferToStringNumber(values[2]),
                value: Util.bufferToStringNumber(values[5]),
                data: Util.bufferToHex(values[6]),
                chainId: Util.bufferToNumber(values[0]),
                accessList: Util.toJsonAccessList(values[7] as any)
            };
        }
        else if (2 === type) {

            let values = <Buffer[]>ethUtil.rlp.decode("0x" + rawTransaction.slice(4));
            result = {
                nonce: Util.bufferToNumber(values[1]),
                to: Util.bufferToHex(values[5]),
                gas: Util.bufferToNumber(values[4]),
                maxPriorityFeePerGas: Util.bufferToStringNumber(values[2]),
                maxFeePerGas: Util.bufferToStringNumber(values[3]),
                value: Util.bufferToStringNumber(values[6]),
                data: Util.bufferToHex(values[7]),
                chainId: Util.bufferToNumber(values[0]),
                accessList: Util.toJsonAccessList(values[8] as any)
            };
        }

        return result;
    }

    /**
     * 编码签名
     * @param v
     * @param r
     * @param s
     */
    public encodeSignature(v: string, r: string, s: string): string {
        return r + s.slice(2) + v.slice(2);
    }

    /**
     * 解码签名
     * @param hex
     */
    public decodeSignature(hex: string): { v: string, r: string, s: string } {
        return {
            v: "0x" + hex.slice(130),
            r: "0x" + hex.slice(2, 66),
            s: "0x" + hex.slice(66, 130)
        };
    }
}

class Util {

    /**
     * 是否偶数
     * @param n
     */
    public static isEven(n: number): boolean {
        return n === 0 || !!(n && !(n % 2));
    }

    /**
     * 验证hex字符串
     * @param value
     * @param length
     */
    public static isHexString(value: string, length?: number): boolean {

        if (typeof (value) !== 'string' || !value.match(/^0x[0-9A-Fa-f]*$/)) {
            return false;
        }

        if (length && value.length !== 2 + 2 * length) {
            return false;
        }

        return true;
    }

    /**
     * 验证地址
     * @param address
     */
    public static isValidAddress(address: string): boolean {

        if (42 !== address.length || !ethUtil.isValidAddress(address)) {
            return false;
        }

        if (null === address.match(/^0x[0-9a-f]+$/) && null === address.match(/^0x[0-9A-F]+$/) && !ethUtil.isValidChecksumAddress(address)) {
            return false;
        }

        return true;
    }

    /**
     * 转到BN
     * @param n
     */
    public static toBN(n: number | string): ethUtil.BN {

        if ("string" === typeof (n)) {
            n = "" === n ? "0x" : n;
            return "0x" === n.slice(0, 2)
                ? new ethUtil.BN(n.slice(2), "hex")
                : new ethUtil.BN(n)
        }

        return new ethUtil.BN(n);
    }

    /**
     * 字符串或者Hex转Buffer
     * @param value
     */
    public static legacyToBuffer(value: string): Buffer {
        return typeof (value) === 'string' && !Util.isHexString(value)
            ? Buffer.from(value, "utf-8")
            : ethUtil.toBuffer(value);
    }

    /**
     * 到数值
     * @param val
     */
    public static bufferToNumber = (val: Buffer): number => {
        let hex = Util.bufferToHex(val);
        return "0x" === hex ? 0 : parseInt(hex, 16);
    }

    /**
     * 到10进制文本数值
     * @param val
     */
    public static bufferToStringNumber = (val: Buffer): string => {
        let hex = Util.bufferToHex(val);
        return "0x" === hex ? "0" : Util.toBN(hex).toString(10);
    }

    /**
     * 到16进制文本
     * @param val
     */
    public static bufferToHex(val: Buffer): string {
        return "0x" + val.toString("hex");
    }

    /**
     * 转为 Buffer格式 的 AccessList
     * @param accessList
     */
    public static toBufferAccessList(accessList: Array<{ address: string, storageKeys: string[] }>): [Buffer, Buffer[]][] {

        let result = [];
        for (let item of accessList) {

            if (false === Util.isValidAddress(item.address)) {
                throw new Error("AccessList address " + item.address + " is invalid");
            }

            let storageKeys = [];
            for (let storageKey of item.storageKeys) {

                if (null === storageKey.match(/^0x[0-9a-fA-F]{64}$/)) {
                    throw new Error("AccessList address " + item.address + " storageKey " + storageKey + " is invalid");
                }

                storageKeys.push(Buffer.from(storageKey.slice(2), "hex"));
            }

            let address = Buffer.from(item.address.slice(2), "hex");
            result.push([address, storageKeys]);
        }

        return result;
    }

    /**
     * 转为 Json格式 的 AccessList
     * @param val
     */
    public static toJsonAccessList = (val: [Buffer, Buffer[]][]): Array<{ address: string, storageKeys: string[] }> => {

        let result = [];
        for (let item of val) {

            let storageKeys = [];
            for (let item2 of item[1]) {
                storageKeys.push(Util.bufferToHex(item2));
            }

            result.push({
                address: Util.bufferToHex(item[0]),
                storageKeys: storageKeys
            });
        }

        return result;
    }
}
