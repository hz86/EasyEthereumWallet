import axios from "axios";

export interface Payload {
    method: string;
    params: Array<any>;
}

export interface TransactionInfo {
    blockHash: string | null;
    blockNumber: number | null;
    from: string;
    gas: number;
    gasPrice: string;
    maxPriorityFeePerGas?: string;
    maxFeePerGas?: string;
    hash: string;
    input: string;
    nonce: number;
    to: string;
    transactionIndex: number | null;
    value: string;
    chainId?: number;
    accessList?: Array<{
        address: string;
        storageKeys: string[];
    }>;
    type: number;
    v?: string;
    r?: string;
    s?: string;
}

export interface TransactionReceipt {
    blockHash: string;
    blockNumber: number;
    contractAddress: string | null;
    cumulativeGasUsed: number;
    effectiveGasPrice: string;
    from: string;
    gasUsed: number;
    logs: Array<{
        address: string;
        data: string;
        topics: string[];
        logIndex: number;
        transactionIndex: number;
        transactionHash: string;
        blockHash: string;
        blockNumber: number;
        removed: boolean;
    }>;
    logsBloom: string;
    status: boolean;
    to: string;
    transactionHash: string;
    transactionIndex: number;
    type: number;
}

export class ChainNode {

    public rpcUrl: string;
    constructor(rpcUrl: string) {
        this.rpcUrl = rpcUrl;
    }

    /**
     * RPC请求
     * @param data
     */
    public async request(data: Payload): Promise<any> {

        let json = JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            method: data.method,
            params: data.params
        });

        let res = await axios.post(this.rpcUrl, json, {
            timeout: 10 * 1000,
            responseType: "json",
            headers: {
                "Content-Type": "application/json"
            }
        });

        if (res.data.error) {
            throw new Error(res.data.error.message);
        }

        return res.data.result;
    }

    /**
     * 取链ID
     */
    public async getChainId(): Promise<number> {

        let chainId = await this.request({
            method: "eth_chainId",
            params: []
        });

        return parseInt(chainId);
    }

    /**
     * 取区块号
     */
    public async getBlockNumber(): Promise<number> {

        let blockNumber = await this.request({
            method: "eth_blockNumber",
            params: []
        });

        return parseInt(blockNumber);
    }

    /**
     * 取交易数量
     * @param address
     */
    public async getTransactionCount(address: string, blockNumber?: string | number): Promise<number> {

        if (("string" !== typeof (blockNumber) && "number" !== typeof (blockNumber)) || "" === blockNumber) blockNumber = "latest";
        blockNumber = typeof (blockNumber) === "number" ? "0x" + blockNumber.toString(16) : blockNumber;

        let count = await this.request({
            method: "eth_getTransactionCount",
            params: [address, blockNumber]
        });

        return parseInt(count);
    }

    /**
     * 取交易结果
     * @param txHash
     */
    public async getTransactionReceipt(txHash: string): Promise<TransactionReceipt> {

        let receipt = await this.request({
            method: "eth_getTransactionReceipt",
            params: [txHash]
        });

        if (null === receipt) {
            return null;
        }

        let result = {
            blockHash: receipt.blockHash,
            blockNumber: parseInt(receipt.blockNumber),
            contractAddress: receipt.contractAddress,
            cumulativeGasUsed: parseInt(receipt.cumulativeGasUsed),
            effectiveGasPrice: BigInt(receipt.effectiveGasPrice).toString(10),
            from: receipt.from,
            gasUsed: parseInt(receipt.gasUsed),
            logs: [],
            logsBloom: receipt.logsBloom,
            status: 0 !== parseInt(receipt.status),
            to: receipt.to,
            transactionHash: receipt.transactionHash,
            transactionIndex: parseInt(receipt.transactionIndex),
            type: typeof (receipt.type) === "string" ? parseInt(receipt.type) : 0
        };

        for (let log of receipt.logs) {
            result.logs.push({
                address: log.address,
                topics: log.topics,
                data: log.data,
                blockNumber: parseInt(log.blockNumber),
                transactionHash: log.transactionHash,
                transactionIndex: parseInt(log.transactionIndex),
                blockHash: log.blockHash,
                logIndex: parseInt(log.logIndex),
                removed: log.removed
            });
        }

        return result;
    }

    /**
     * 获取交易信息
     * @param txHash
     */
    public async getTransaction(txHash: string): Promise<TransactionInfo> {

        let info = await this.request({
            method: "eth_getTransactionByHash",
            params: [txHash]
        });

        if (null === info) {
            return null;
        }

        return {
            blockHash: info.blockHash,
            blockNumber: typeof (info.blockNumber) === "string" ? parseInt(info.blockNumber) : info.blockNumber,
            from: info.from,
            gas: parseInt(info.gas),
            gasPrice: BigInt(info.gasPrice).toString(10),
            maxPriorityFeePerGas: typeof (info.maxPriorityFeePerGas) === "string" ? BigInt(info.maxPriorityFeePerGas).toString(10) : info.maxPriorityFeePerGas,
            maxFeePerGas: typeof (info.maxFeePerGas) === "string" ? BigInt(info.maxFeePerGas).toString(10) : info.maxFeePerGas,
            hash: info.hash,
            input: info.input,
            nonce: parseInt(info.nonce),
            to: info.to,
            transactionIndex: typeof (info.transactionIndex) === "string" ? parseInt(info.transactionIndex) : info.transactionIndex,
            value: info.value,
            type: typeof (info.type) === "string" ? parseInt(info.type) : 0,
            accessList: info.accessList,
            chainId: typeof (info.chainId) === "string" ? parseInt(info.chainId) : info.chainId,
            v: info.v,
            r: info.r,
            s: info.s
        };
    }

    /**
     * 发送交易
     * @param data
     * 返回交易哈希
     */
    public async sendRawTransaction(data: string): Promise<string> {

        let hash = await this.request({
            method: "eth_sendRawTransaction",
            params: [data]
        });

        return hash;
    }

    /**
     * 等待交易完成
     * @param txHash
     * @param maxConfNumber 如果等于0，则直接返回
     * @param callback      maxConfNumber > 0 回调返回当前确认数
     */
    public async waitTransactionReceipt(
        txHash: string,
        maxConfNumber: number = 0,
        callback?: (confNumber, receipt) => void
    ): Promise<TransactionReceipt> {

        let workType = 0;
        let lastBlockNumber = 0;
        let receiptBlockHash = null;
        let receiptBlockNumber = 0;
        let transaction = await this.getTransaction(txHash);

        // 交易不存在
        if (null === transaction) {
            return null;
        }

        while (true) {

            try {

                if (0 === workType) {

                    // 获取交易结果
                    let receipt = await this.getTransactionReceipt(txHash);
                    if (null !== receipt) {

                        // 交易完成
                        lastBlockNumber = receipt.blockNumber;
                        receiptBlockNumber = receipt.blockNumber;
                        receiptBlockHash = receipt.blockHash;
                        if (0 === maxConfNumber) {
                            return receipt;
                        }

                        // 验证交易
                        workType = 1;
                        await this.sleep(1000);
                        continue;
                    }

                    // 判断交易是否被替换
                    let nonce = await this.getTransactionCount(transaction.from);
                    if (nonce > transaction.nonce) {

                        // 有可能是当前交易完成
                        receipt = await this.getTransactionReceipt(txHash);
                        if (null !== receipt) {

                            // 交易完成
                            lastBlockNumber = receipt.blockNumber;
                            receiptBlockNumber = receipt.blockNumber;
                            receiptBlockHash = receipt.blockHash;
                            if (0 === maxConfNumber) {
                                return receipt;
                            }
                        }
                        else {

                            // 被替换了
                            receiptBlockHash = null;
                            receiptBlockNumber = await this.getBlockNumber();
                            lastBlockNumber = receiptBlockNumber;
                            if (0 === maxConfNumber) {
                                return null;
                            }
                        }

                        // 验证交易
                        workType = 1;
                        await this.sleep(1000);
                        continue;
                    }

                    // 判断交易是否存在
                    if (null === await this.getTransaction(txHash)) {
                        return null;
                    }

                    // 请求间隔
                    await this.sleep(1000);
                }
                else if (1 === workType) {

                    // 需要大于上次
                    let blockNumber = await this.getBlockNumber();
                    if (blockNumber > lastBlockNumber) {

                        // 验证结果
                        let receipt = await this.getTransactionReceipt(txHash);
                        if (null !== receipt) {

                            // 有变化则重新开始
                            lastBlockNumber = blockNumber;
                            if (null === receiptBlockHash ||
                                receiptBlockNumber !== receipt.blockNumber ||
                                receiptBlockHash.toLowerCase() !== receipt.blockHash.toLowerCase()) {
                                workType = 0;
                                continue;
                            }
                        }
                        else {

                            // 有变化则重新开始
                            lastBlockNumber = blockNumber;
                            if (null !== receiptBlockHash) {
                                workType = 0;
                                continue;
                            }
                        }

                        // 结果一致
                        let confNumber = blockNumber - receiptBlockNumber;
                        if (null !== receiptBlockHash) {

                            // 确认数
                            if (typeof (callback) === "function") {
                                callback(confNumber, receipt);
                            }
                        }

                        // 到达要求
                        if (confNumber >= maxConfNumber) {
                            return receipt;
                        }
                    }

                    // 请求间隔
                    await this.sleep(1000 * 5);
                }
            }
            catch (err) {
                // 防止连续错误循环太快
                await this.sleep(1000 * 3);
            }
        }
    }

    /**
     * 等待
     * @param ms
     */
    private sleep(ms: number): Promise<void> {
        return new Promise((resolve) => {
            setTimeout(resolve, ms);
        });
    }
}
