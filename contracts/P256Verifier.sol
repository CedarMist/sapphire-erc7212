// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { Sapphire } from '@oasisprotocol/sapphire-contracts/contracts/Sapphire.sol';

contract P256Verifier {
    /**
     * Precompiles don't use a function signature. The first byte of callldata
     * is the first byte of an input argument. In this case:
     *
     * input[  0: 32] = signed data hash
     * input[ 32: 64] = signature r
     * input[ 64: 96] = signature s
     * input[ 96:128] = public key x
     * input[128:160] = public key y
     *
     * result[ 0: 32] = 0x00..00 (invalid) or 0x00..01 (valid)
     *
     * For details, see https://eips.ethereum.org/EIPS/eip-7212
     */
    fallback(bytes calldata input)
        external
        returns (bytes memory)
    {
        if (input.length != 160) {
            return abi.encodePacked(uint256(0));
        }

        bytes32 digest = bytes32(input[0:32]);
        uint256 r = uint256(bytes32(input[32:64]));
        uint256 s = uint256(bytes32(input[64:96]));
        uint256 x = uint256(bytes32(input[96:128]));
        uint256 y = uint256(bytes32(input[128:160]));

        uint256 ret = ecdsa_verify(digest, r, s, [x, y]) ? 1 : 0;

        return abi.encodePacked(ret);
    }

    // See: https://www.secg.org/sec1-v2.pdf section 2.3.3
    function _compressPubkey(uint256[2] memory pubKey)
        internal pure
        returns (bytes memory)
    {
        return abi.encodePacked(0x02 + uint8(pubKey[1] % 2), pubKey[0]);
    }

    function _derEncodeInteger(uint256 x)
        internal pure
        returns (bytes memory)
    {
        uint offset;
        bool extra;
        unchecked {
            // Skip past zero-byte prefix
            for( offset = 0 ; offset < 32; offset++ ) {
                uint high = x & 0xff00000000000000000000000000000000000000000000000000000000000000;
                if( high != 0 ) {
                    // If highest bit is set, we need a zero-byte prefix
                    extra = (high & 0x8000000000000000000000000000000000000000000000000000000000000000) != 0;
                    break;
                }
                x = x << 8;
            }

            // Correct array length, to account for removed zero-byte prefix
            uint len = 32 - offset;
            bytes memory z = abi.encodePacked(x);
            assembly {
                mstore(z, len)
            }

            // If high bit of first byte is non-zero, prefix with a zero-byte
            if( extra ) {
                return abi.encodePacked(uint8(0x02), uint8(len + 1), uint8(0x00), z);
            }
            return abi.encodePacked(uint8(0x02), uint8(len), z);
        }
    }

    function _derEncodeSignature(uint256 r, uint256 s)
        internal pure
        returns (bytes memory)
    {
        bytes memory z = abi.encodePacked(
                            _derEncodeInteger(r),
                            _derEncodeInteger(s));
        return abi.encodePacked(
            uint8(0x30),
            uint8(z.length),
            z
        );
    }

    // Curve order (number of points)
    uint256 internal constant p256r1_order =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

    /**
     * @dev ECDSA verification given signature and public key.
     */
    function ecdsa_verify(
        bytes32 message_hash,
        uint256 r,
        uint256 s,
        uint256[2] memory pubKey
    ) internal view returns (bool) {
        // Check r and s are in the scalar field
        if (r == 0 || r >= p256r1_order || s == 0 || s >= p256r1_order) {
            return false;
        }

        return Sapphire.verify(
            Sapphire.SigningAlg.Secp256r1PrehashedSha256,
            _compressPubkey(pubKey),
            abi.encodePacked(message_hash),
            "",
            _derEncodeSignature(r,s));
    }
}