*!
 * This file is part of kale-miner.
 * Author: Fred Kyung-jin Rezeau <fred@litemint.com>
 */

const { SorobanRpc, Horizon, xdr, Address, Operation, Asset, Contract, Networks, TransactionBuilder, StrKey, Memo, Keypair, nativeToScVal, scValToNative } = require('@stellar/stellar-sdk');
const fs = require('fs');
const config = require(process.env.CONFIG || './config.json');
const rpc = new SorobanRpc.Server(process.env.RPC_URL || config.stellar?.rpc, { allowHttp: true });
const horizon = new Horizon.Server(config.stellar?.horizon || 'https://horizon.stellar.org', { allowHttp: true });
const contractId = config.stellar?.contract;
const fees = config.stellar?.fees || 10000000;

const signers = config.farmers.reduce((acc, farmer) => {
    const keypair = Keypair.fromSecret(farmer.secret);
    const publicKey = keypair.publicKey();
    acc[publicKey] = {
        secret: farmer.secret,
        stake: farmer.stake || 0,
        difficulty: farmer.difficulty,
        minWorkTime: farmer.minWorkTime || 0,
        harvestOnly: farmer.harvestOnly || false,
        stats: { fees: 0, amount: 0, gaps: 0, workCount: 0, harvestCount: 0, feeCount: 0, diffs: 0 }
    };
    return acc;
}, {});

const blockData = { hash: null, block: 0 };
const balances = {}
const session = { log: [] };

const contractErrors = Object.freeze({
    1: 'HomesteadExists',
    2: 'HomesteadMissing',
    3: 'FarmBlockMissing',
    4: 'FarmPaused',
    5: 'FarmNotPaused',
    6: 'PlantAmountTooLow',
    7: 'ZeroCountTooLow',
    8: 'PailExists',
    9: 'PailMissing',
    10: 'WorkMissing',
    11: 'BlockMissing',
    12: 'BlockInvalid',
    13: 'HashInvalid',
    14: 'HarvestNotReady',
    15: 'GapCountTooLow'
});

const getError = (error) => {
    return contractErrors[parseInt((msg = error instanceof Error
        ? error.message
        : (typeof error === 'object' ? (JSON.stringify(error) || error.toString()) : String(error)))
        .match(/Error\(Contract, #(\d+)\)/)?.[1] || 0, 10)] || msg;
};

const getReturnValue = (resultMetaXdr) => {
    const txMeta = LaunchTube.isValid()
        ? xdr.TransactionMeta.fromXDR(resultMetaXdr, "base64")
        : xdr.TransactionMeta.fromXDR(resultMetaXdr.toXDR().toString("base64"), "base64");
    return txMeta.v3().sorobanMeta().returnValue();
};

async function getInstanceData() {
    const result = {};
    try {
        const { val } = await rpc.getContractData(contractId, xdr.ScVal.scvLedgerKeyContractInstance());
        val.contractData().val().instance().storage()?.forEach((entry) => {
            switch(scValToNative(entry.key())[0]) {
                case 'FarmIndex': result.block = Number(scValToNative(entry.val())); break;
                case 'FarmEntropy': result.hash = Buffer.from(scValToNative(entry.val())).toString('base64'); break;
            }
        });
    } catch (error) {
        console.error(error);
    }
    return result;
}

async function getTemporaryData(key) {
    try {
        const data = xdr.LedgerKey.contractData(
            new xdr.LedgerKeyContractData({
                contract: new Address(contractId).toScAddress(),
                key,
                durability: xdr.ContractDataDurability.temporary(),
            })
        );
        const blockData = await rpc.getLedgerEntries(data);
        const entry = blockData.entries?.[0];
        if (entry) {
            return scValToNative(entry.val?._value.val());
        }
    } catch (error) {
        console.error(error);
    }
}

async function getPail(address, block) {
    const data = await getTemporaryData(xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("Pail"),
        new Address(address).toScVal(),
        nativeToScVal(Number(block), { type: "u32" })]));
    return data;
}

async function setupAsset(farmer) {
    const issuer = config.stellar?.assetIssuer;
    const code = config.stellar?.assetCode;
    if (code?.length && StrKey.isValidEd25519PublicKey(issuer)) {
        const account = await horizon.loadAccount(farmer);
        if (!account.balances.some(balance => balance.asset_code === code && balance.asset_issuer === issuer)) {
            const transaction = new TransactionBuilder(account, {
                fee: fees.toString(),
                networkPassphrase: config.stellar?.networkPassphrase || Networks.PUBLIC
            })
                .addOperation(Operation.changeTrust({ asset: new Asset(code, issuer) }))
                .setTimeout(30)
                .build();
            transaction.sign(Keypair.fromSecret(signers[farmer].secret));
            const response = await getResponse(await rpc.sendTransaction(transaction));
            if (response.status !== 'SUCCESS') throw new Error(`tx Failed: ${response.hash}`);
            console.log(`Trustline set for ${farmer} to ${code}:${issuer}`);
        }
        const native = account.balances.find(balance => balance.asset_type === 'native')?.balance || '0';
        const asset = account.balances.find(balance => balance.asset_code === code && balance.asset_issuer === issuer);
        balances[farmer] = { XLM: native, [code]: asset?.balance || '0' };
        console.log(`Farmer ${farmer} balances: ${asset?.balance || 0} ${code} | ${native} XLM`);
    }
}

async function invoke(method, data) {
    const farmer = signers[data.farmer] || {};
    if (!StrKey.isValidEd25519SecretSeed(farmer.secret)) {
        console.error("Unauthorized:", data.farmer);
        return null;
    }

    let args, source, params;
    const contract = new Contract(data.contract || contractId);
    switch (method) {
        case 'plant':
            args = contract.call('plant', new Address(data.farmer).toScVal(), nativeToScVal(data.amount, { type: 'i128' }));
            params = `with ${(data.amount / 10000000).toFixed(7)} KALE`;
            break;
        case 'work':
            args = contract.call('work', new Address(data.farmer).toScVal(), xdr.ScVal.scvBytes(Buffer.from(data.hash, 'hex')), nativeToScVal(data.nonce, { type: 'u64' }));
            params = `with ${data.hash}/${data.nonce}`;
            break;
        case 'harvest':
        case 'tractor':
            source = StrKey.isValidEd25519SecretSeed(config.harvester?.account) ? Keypair.fromSecret(config.harvester?.account) : null;
            await setupAsset(data.farmer);
            args = contract.call('harvest', new Address(data.farmer).toScVal(), nativeToScVal(method === 'harvest' ? data.block : data.blocks, { type: 'u32' }));
            params = `for block(s) ${method === 'harvest' ? data.block : data.blocks}`;
            break;
    }

    const isLaunchTube = LaunchTube.isValid();
    const account = await rpc.getAccount(source?.publicKey() || data.farmer);

    const simTx = new TransactionBuilder(account, {
        fee: fees.toString(),
        networkPassphrase: config.stellar?.networkPassphrase || Networks.PUBLIC
    }).addOperation(args).setTimeout(30).build();

    const { minResourceFee } = await rpc.simulateTransaction(simTx);
    const inclusionFee = BigInt(minResourceFee) + 201n;

    let transaction = new TransactionBuilder(account, {
        fee: inclusionFee.toString(),
        networkPassphrase: config.stellar?.networkPassphrase || Networks.PUBLIC
    }).addOperation(args).setTimeout(30).build();

    transaction = await rpc.prepareTransaction(transaction);
    transaction.sign(Keypair.fromSecret(source?.secret() || farmer.secret));

    const envelope = transaction.toEnvelope().toXDR();
    const xdrBase64 = envelope.toString('base64');
    const jsonOutput = xdr.FeeBumpTransactionEnvelope.fromXDR(xdrBase64, 'base64').toXDRObject().toJSON();

    fs.writeFileSync(`./logs/tx_${Date.now()}.json`, JSON.stringify({
        tx_fee_bump: jsonOutput,
        xdr: xdrBase64
    }, null, 2));

    if (BigInt(transaction.fee) - BigInt(minResourceFee) > 201n) {
        throw new Error('Inclusion fee too high: exceeds 201 stroops');
    }

    session.log.push({ stamp: Date.now(), msg: `Farmer ${data.farmer.slice(0, 4)}..${data.farmer.slice(-6)} invoked '${method}' ${params}` });
    session.log = session.log.slice(-50);

    return await getResponse(await rpc.sendTransaction(transaction));
}

module.exports = { getInstanceData, getTemporaryData, getPail, getError, getReturnValue, invoke, setupAsset, rpc, horizon, contractId, contractErrors, signers, blockData, balances, session };
