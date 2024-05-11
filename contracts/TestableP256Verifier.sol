// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { P256Verifier } from "./P256Verifier.sol";

contract TestableP256Verifier is P256Verifier {
    function test_compressPubkey(uint256[2] memory pubKey)
        public pure
        returns (bytes memory)
    {
        return _compressPubkey(pubKey);
    }

    function test_derEncodeInteger(uint256 x)
        public pure
        returns (bytes memory)
    {
        return _derEncodeInteger(x);
    }

    function test_derEncodeSignature(uint256 r, uint256 s)
        public pure
        returns (bytes memory)
    {
        return _derEncodeSignature(r, s);
    }

    function test_ecdsa_verify(
        bytes32 message_hash,
        uint256 r,
        uint256 s,
        uint256[2] memory pubKey
    )
        public view
        returns (bool)
    {
        return ecdsa_verify(message_hash, r, s, pubKey);
    }
}