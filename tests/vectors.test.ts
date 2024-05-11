import { ethers } from 'hardhat'
import { TestableP256Verifier } from '../typechain-types';
import { readFile } from 'node:fs/promises';
import { BytesLike, getBytes, hexlify } from 'ethers';
import { expect } from 'chai';

describe('Test Vectors', () => {
    let tv: TestableP256Verifier;
    before(async () => {
        const x = await ethers.getContractFactory('TestableP256Verifier');
        const y = await x.deploy()
        tv = await y.waitForDeployment()
    });

    async function evaluate (hash:BytesLike, r:bigint, s:bigint, x:bigint, y:bigint)
    {
        const raw = ethers.AbiCoder.defaultAbiCoder().encode(
            ['bytes32', 'uint256', 'uint256', 'uint256', 'uint256'],
            [hash, r, s, x, y]);
        const result = await tv.fallback!.staticCall({data: raw});
        return BigInt(result);
    }

    interface TestVectorLine {
        x: string;
        y: string;
        r: string;
        s: string;
        hash: string;
        valid: boolean;
        msg: string;
        comment: string;
    }

    it('Wycheproof', async () => {
        const content = await readFile('test-vectors/vectors_wycheproof.jsonl');
        const lines:TestVectorLine[] = new TextDecoder().decode(content).split(/\n/).map((value) => JSON.parse(value));
        for( const line of lines ) {
            const x = BigInt(hexlify(getBytes(`0x${line.x}`)));
            const y = BigInt(hexlify(getBytes(`0x${line.y}`)));
            const r = BigInt(hexlify(getBytes(`0x${line.r}`)));
            const s = BigInt(hexlify(getBytes(`0x${line.s}`)));
            const hash = getBytes(`0x${line.hash}`);
            const result = await evaluate(hash, r, s, x, y);
            expect(result).to.equal(line.valid ? 1n : 0n);
        }
    });
});
