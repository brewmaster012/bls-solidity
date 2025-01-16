// SPDX-License-Identifier: LGPL 3.0
pragma solidity ^0.8.13;
import {BLS} from "./BLS.sol";
import {BN256G2} from "./BLSG2.sol";

library BLSSign {
    // added by brewmaseter012
    // this does not work because no easy way to do scalar*G2point
    // precompile 0x7 onlydoes scalar*G1point
    function generateKeyPair(
        bytes memory entropy
    ) public view returns (uint256 privateKey, uint256[4] memory publicKey) {
        privateKey = uint256(keccak256(entropy)) % BLS.N;
        require(privateKey != 0, "BLS: zero private key");

        (publicKey[0], publicKey[1], publicKey[2], publicKey[3]) = BN256G2
            .ECTwistMul(privateKey, BLS.G2x0, BLS.G2x1, BLS.G2y0, BLS.G2y1);
    }

    function sign(
        bytes memory message,
        uint256 privateKey
    ) public view returns (uint256[2] memory signature) {
        require(
            privateKey > 0 && privateKey < BLS.N,
            "BLS: invalid private key"
        );

        // Hash message to curve point
        (uint256[2] memory h, ) = BLS.hashToPoint(message);

        // Perform scalar multiplication: signature = privateKey * H(message)
        uint256[4] memory input;
        input[0] = h[0];
        input[1] = h[1];
        input[2] = privateKey;

        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                7, // Call precompile 0x07 for G1 multiplication
                input,
                0x60, // 3 * 32 bytes
                signature,
                0x40 // 2 * 32 bytes
            )
        }
        require(success, "BLS: signing failed");

        // Verify the signature is on the curve
        require(
            BLS.isValidSignature(signature),
            "BLS: invalid signature generated"
        );

        return signature;
    }
}
