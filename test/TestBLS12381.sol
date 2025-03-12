// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
import {Test, console} from "forge-std/Test.sol";

/*
   This test verifies a minimal BLS signature using the pairing precompile.
   The verification equation is:
       e(sig, G2) * e(-H(msg), pk) == 1
   which is equivalent to:
       e(sig, G2) == e(H(msg), pk)

   IMPORTANT:
   - The EIP-2537 precompiles expect *uncompressed* points:
       • G1 points: 128 bytes (64 bytes for X and 64 bytes for Y)
       • G2 points: 256 bytes (each Fp element encoded as 64 bytes, concatenated for the two coefficients)
   - The original SUI test uses compressed values (48 bytes for sig, 96 bytes for pk). You must
     decompress them (and perform hash-to-curve for the message) before calling the pairing precompile.
   - For clarity, this example uses placeholder constants. In a real implementation these constants
     must be the properly decompressed (or precomputed off-chain) values.
*/

// Precompile for pairing check (BLS12_PAIRING_CHECK) is at address 0x0f.
contract BLS12381Verify is Test {
    address constant BLS12_PAIRING_CHECK = address(0x0f);

    // === PLACEHOLDER CONSTANTS (Replace with actual decompressed values) ===

    // Uncompressed signature (G1 point) – 128 bytes.
    bytes constant UNCOMPRESSED_SIG = hex"94138847ea1e9b6723bbdfc689b3f106a36d1630f13a87e5dcb542d84dc95c56b961a6b6a5564c371723c355e1a87e3c";
    /* 128-byte decompressed signature corresponding to the 48-byte compressed sig */";

    // Uncompressed public key (G2 point) – 256 bytes.
    bytes constant UNCOMPRESSED_PK = hex"83bd626a1f81bfe207032acac50127ad0807bd469c24d03fe006bb94a46047705e5f10f5ff7b93077dbeef7c4886c78b0158128021c5e33394166b8458a20bf6883ba90b1bc810343ef8104d1da2a801cae9cf354eb1a3c9c57025dffb971419";
    /* 256-byte decompressed public key corresponding to the 96-byte compressed pk */";

    // Hash-to-curve of the message "Hello BLS" in G1 (uncompressed) – 128 bytes.
    bytes constant HMSG = hex"/* 128-byte output of hash-to-curve for 'Hello BLS' */";

    // Precomputed negation of HMSG (i.e. with y replaced by p - y) – 128 bytes.
    // (This avoids having to perform big integer arithmetic on-chain.)
    bytes constant NEG_HMSG = hex"/* 128-byte negation of HMSG */";

    // Uncompressed G2 generator (H₂ from EIP-2537) – 256 bytes.
    bytes constant G2_GENERATOR = hex"/* 256-byte uncompressed encoding of the G2 generator (H₂) */";
    // =========================================================================

    /// @notice Utility to copy a bytes array `src` into `dest` at byte offset `destOffset`.
    function copyBytes(bytes memory src, bytes memory dest, uint destOffset) internal pure {
        require(destOffset + src.length <= dest.length, "copyBytes: out of bounds");
        for (uint i = 0; i < src.length; i++) {
            dest[destOffset + i] = src[i];
        }
    }

    /// @notice Builds the input for the pairing check precompile.
    /// The expected input is the concatenation of two pairs:
    ///   Pair 1: (UNCOMPRESSED_SIG, G2_GENERATOR)
    ///   Pair 2: (NEG_HMSG, UNCOMPRESSED_PK)
    /// Each pair is: [128-byte G1 point || 256-byte G2 point]
    function pairingInput() internal pure returns (bytes memory) {
        uint256 numPairs = 2;
        uint256 pairSize = 128 + 256; // = 384 bytes per pair
        bytes memory input = new bytes(numPairs * pairSize);
        uint offset = 0;

        // Pair 1: (UNCOMPRESSED_SIG, G2_GENERATOR)
        copyBytes(UNCOMPRESSED_SIG, input, offset);
        offset += 128;
        copyBytes(G2_GENERATOR, input, offset);
        offset += 256;

        // Pair 2: (NEG_HMSG, UNCOMPRESSED_PK)
        copyBytes(NEG_HMSG, input, offset);
        offset += 128;
        copyBytes(UNCOMPRESSED_PK, input, offset);
        // offset += 256; // not needed here

        return input;
    }

    function test_bls12381_min_sig_verify() public {
        // Build pairing input data (768 bytes for 2 pairs).
        bytes memory input = pairingInput();
        uint256 inputLength = input.length;

        uint256 result;
        bool success;
        assembly {
            // Allocate memory for the 32-byte output.
            let outPtr := mload(0x40)
            // Call the pairing precompile.
            // Note: staticcall(gas, addr, in, in_size, out, out_size)
            success := staticcall(gas(), BLS12_PAIRING_CHECK, add(input, 0x20), inputLength, outPtr, 0x20)
            result := mload(outPtr)
        }
        require(success, "Pairing precompile call failed");
        require(result != 0, "BLS signature verification failed");

        emit log_named_uint("BLS signature valid", 1);
    }
}
