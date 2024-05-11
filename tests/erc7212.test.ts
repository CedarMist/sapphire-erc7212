import * as asn1js from 'asn1js';
import { ethers } from 'hardhat'
import { hexlify, randomBytes } from 'ethers';
import { TestableP256Verifier } from '../typechain-types';
import { expect } from 'chai';
import { secp256r1 } from '@noble/curves/p256';

describe('ERC-7212', () => {
    let tv: TestableP256Verifier;
    before(async () => {
        const x = await ethers.getContractFactory('TestableP256Verifier');
        const y = await x.deploy()
        tv = await y.waitForDeployment()
    });

    async function testAsnIntegerEncoding(n:bigint) {
        const encodedBySolidity = await tv.test_derEncodeInteger(n);
        const ber = asn1js.Integer.fromBigInt(n).toBER();
        const berHex = hexlify(new Uint8Array(ber));
        expect(encodedBySolidity).to.equal(berHex);
    }

    it('secp256r1', async () => {
        const chainId = (await tv.runner?.provider?.getNetwork())?.chainId;

        for( let i = 0; i < 32; i++ ) {
            const priv = secp256r1.utils.randomPrivateKey();
            const pub = secp256r1.getPublicKey(priv);
            const p = secp256r1.ProjectivePoint.fromPrivateKey(priv).toAffine();
            expect(await tv.test_compressPubkey([p.x, p.y])).to.equal(hexlify(pub));

            const msg = randomBytes(32);
            const sig = secp256r1.sign(msg, priv); // `{prehash: true}` option is available
            const isValid = secp256r1.verify(sig, msg, pub);
            expect(isValid).to.be.true;

            const sigDER = hexlify(sig.toDERRawBytes(true));
            const solidityEncodedSig = await tv.test_derEncodeSignature(sig.r, sig.s);
            expect(solidityEncodedSig).to.equal(sigDER);

            if( chainId !== 1337n ) {
                expect(await tv.test_ecdsa_verify(msg, sig.r, sig.s, [p.x, p.y])).to.be.true;

                const newMsg = randomBytes(32);
                expect(await tv.test_ecdsa_verify(newMsg, sig.r, sig.s, [p.x, p.y])).to.be.false;
            }
        }
    });

    describe('ASN.1', () => {
        it('ASN.1: Integer, single bits shifted', async () => {
            for( let i = 0n; i < 256n; i++ ) {
                const n = 1n << i;
                await testAsnIntegerEncoding(n);
            }
        });

        it('Random Uint256', async () => {
            for( let i = 0; i < 512; i += 1 ) {
                const n = BigInt(hexlify(randomBytes(32)));
                await testAsnIntegerEncoding(n);
            }
        });
    });
});
