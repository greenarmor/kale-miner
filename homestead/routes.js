/*!
 * This file is part of kale-miner.
 * Author: Fred Kyung-jin Rezeau <fred@litemint.com>
 */

const express = require('express');
const { invoke, hoard, blockData, balances, signers, session } = require('./contract');
const config = require(process.env.CONFIG || './config.json');
const { Harvester, parseRange } = require('./harvester');
const router = express.Router();
const path = require('path');

const convert = (obj) => {
    if (typeof obj === 'bigint') {
        return obj.toString();
    } else if (Array.isArray(obj)) {
        return obj.map(convert);
    } else if (obj && typeof obj === 'object') {
        return Object.fromEntries(
            Object.entries(obj).map(([key, value]) => [key, convert(value)])
        );
    }
    return obj;
}

router.get('/monitor', async (req, res) => {
    try {
        res.json({
            block: convert(blockData),
            session,
            balances,
            farmers: Object.fromEntries(Object.entries(signers).map(([key, value]) => [key, (({ secret, ...rest }) => rest)(value)]))
        });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

router.get('/plant', async (req, res) => {
    const { farmer, amount } = req.query;
    try {
        res.json({ result: await invoke('plant', { farmer, amount }) });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

router.get('/work', async (req, res) => {
    const { farmer, hash, nonce } = req.query;
    try {
        res.json({ result: await invoke('work', { farmer, hash, nonce }) }); 
    } catch (error) {
        res.status(500).send(error.message);
    }
});

router.get('/harvest', async (req, res) => {
    const { farmer, block } = req.query;
    try {
        res.json({ result: await invoke('harvest', { farmer, block }) }); 
    } catch (error) {
        res.status(500).send(error.message);
    }
});

router.post('/tractor', async (req, res) => {
    try {
        if (config.harvester?.range) {
            const { range, count } = parseRange(config.harvester.range);
            for (const key in signers) {
                if (range) {
                    const [start, end] = range;
                    for (let block = end; block >= start; block--) {
                        Harvester.add(key, block, Date.now());
                    }
                    console.log(`Farmer ${key} checking blocks from ${start} to ${end} for harvest`);
                } else if (count) {
                    for (let i = 1; i <= count; i++) {
                        Harvester.add(key, blockData.block - 1 - i, Date.now());
                    }
                    console.log(`Farmer ${key} checking blocks from ${blockData.block - 2} to ${blockData.block - count - 1} for harvest`);
                }
            }
            await Harvester.flush(true);
            return res.json({ result: true });
        }
        return res.status(400).send('Invalid config');
    } catch (error) {
        console.error(error);
        return res.status(500).send(error.message);
    }
});

router.get('/data', async (req, res) => {
    res.json(convert(blockData));
});

router.get('/shader', (req, res) => {
    res.sendFile(path.join(__dirname, '../utils/keccak.wgsl'));
});

router.get('/balances', async (req, res) => {
    res.json(balances);
});

router.post('/hoard', async (req, res) => {
    try {
        res.json({ result: await hoard() }); 
    } catch (error) {
        res.status(500).send(error.message);
    }
});

module.exports = router;