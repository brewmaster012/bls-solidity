pragma solidity ^0.8.13;

import {BLS} from "../lib/BLS.sol";
import {BLSSign} from "../lib/BLSSign.sol";
import {Test, console} from "forge-std/Test.sol";

contract TestBLS is Test {
    function verifyMultiple(
        uint256[2] calldata signature,
        uint256[4][] calldata pubkeys,
        uint256[2][] calldata messages
    ) external view returns (bool) {
        return BLS.verifyMultiple(signature, pubkeys, messages);
    }

    function verifyMultipleGasCost(
        uint256[2] calldata signature,
        uint256[4][] calldata pubkeys,
        uint256[2][] calldata messages
    ) external returns (uint256) {
        uint256 g = gasleft();
        require(
            BLS.verifyMultiple(signature, pubkeys, messages),
            "BLSTest: expect succesful verification"
        );
        return g - gasleft();
    }

    function verifySingle(
        uint256[2] calldata signature,
        uint256[4] calldata pubkey,
        uint256[2] calldata message
    ) external view returns (bool) {
        return BLS.verifySingle(signature, pubkey, message);
    }

    function verifySingleeGasCost(
        uint256[2] memory signature,
        uint256[4] memory pubkey,
        uint256[2] memory message
    ) internal returns (uint256) {
        uint256 g = gasleft();
        require(
            BLS.verifySingle(signature, pubkey, message),
            "BLSTest: expect succesful verification"
        );
        return g - gasleft();
    }

    function hashToPointGasCost(
        bytes calldata data
    ) external returns (uint256 p) {
        uint256 g = gasleft();
        BLS.hashToPoint(data);
        return g - gasleft();
    }

    function isOnCurveG1Compressed(uint256 point) external view returns (bool) {
        uint256 FIELD_MASK = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
        return BLS.isOnCurveG1(point & FIELD_MASK);
    }

    function isOnCurveG1(
        uint256[2] calldata point
    ) external pure returns (bool) {
        return BLS.isOnCurveG1(point);
    }

    function isOnCurveG1CompressedGasCost(
        uint256 point
    ) external returns (uint256) {
        uint256 g = gasleft();
        BLS.isOnCurveG1(point);
        return g - gasleft();
    }

    function isOnCurveG1GasCost(
        uint256[2] calldata point
    ) external returns (uint256) {
        uint256 g = gasleft();
        BLS.isOnCurveG1(point);
        return g - gasleft();
    }

    function isOnCurveG2Compressed(
        uint256[2] calldata point
    ) external view returns (bool) {
        uint256 FIELD_MASK = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
        uint256 x0 = point[0] & FIELD_MASK;
        uint256 x1 = point[1];
        return BLS.isOnCurveG2([x0, x1]);
    }

    function isOnCurveG2(
        uint256[4] calldata point
    ) external pure returns (bool) {
        return BLS.isOnCurveG2(point);
    }

    function isOnCurveG2CompressedGasCost(
        uint256[2] calldata point
    ) external returns (uint256) {
        uint256 g = gasleft();
        BLS.isOnCurveG2(point);
        return g - gasleft();
    }

    function isOnCurveG2GasCost(
        uint256[4] calldata point
    ) external returns (uint256) {
        uint256 g = gasleft();
        BLS.isOnCurveG2(point);
        return g - gasleft();
    }

    function isNonResidueFP(uint256 e) external view returns (bool) {
        return BLS.isNonResidueFP(e);
    }

    function isNonResidueFPGasCost(uint256 e) external returns (uint256) {
        uint256 g = gasleft();
        BLS.isNonResidueFP(e);
        return g - gasleft();
    }

    function isNonResidueFP2(
        uint256[2] calldata e
    ) external view returns (bool) {
        return BLS.isNonResidueFP2(e);
    }

    function isNonResidueFP2GasCost(
        uint256[2] calldata e
    ) external returns (uint256) {
        uint256 g = gasleft();
        BLS.isNonResidueFP2(e);
        return g - gasleft();
    }

    function pubkeyToUncompresed(
        uint256[2] calldata compressed,
        uint256[2] calldata y
    ) external pure returns (uint256[4] memory uncompressed) {
        return BLS.pubkeyToUncompresed(compressed, y);
    }

    function signatureToUncompresed(
        uint256 compressed,
        uint256 y
    ) external pure returns (uint256[2] memory uncompressed) {
        return BLS.signatureToUncompresed(compressed, y);
    }

    function isValidCompressedPublicKey(
        uint256[2] calldata compressed
    ) external view returns (bool) {
        return BLS.isValidCompressedPublicKey(compressed);
    }

    function isValidCompressedSignature(
        uint256 compressed
    ) external view returns (bool) {
        return BLS.isValidCompressedSignature(compressed);
    }

    // tests
    //
    function test_ex1() public {
        // Test hash to point with some predefined test vectors since we can't easily generate random hex in Solidity
        bytes[] memory testVectors = new bytes[](5);
        testVectors[0] = hex"123456789abc"; // 12 bytes of data
        testVectors[1] = hex"deadbeef1234";
        testVectors[2] = hex"abcdef123456";
        testVectors[3] = hex"111111222222";
        testVectors[4] = hex"aaaaabbbbbcc";

        for (uint i = 0; i < testVectors.length; i++) {
            // Get point coordinates
            (uint256[2] memory point, ) = BLS.hashToPoint(testVectors[i]);

            // Verify the point is on curve
            bool isOnCurve = BLS.isOnCurveG1([point[0], point[1]]);
            assertTrue(isOnCurve, "Point must be on curve G1");

            // Verify coordinates are within valid field range
            assertTrue(point[0] < BLS.N, "X coordinate must be less than N");
            assertTrue(point[1] < BLS.N, "Y coordinate must be less than N");

            // Log results for verification
            emit log_named_uint("x coordinate", point[0]);
            emit log_named_uint("y coordinate", point[1]);
        }
    }

    function test_hashToPointGas() public {
        uint256 N = 10000;
        uint256 totalGas = 0;
        uint256 maxGas = 0;
        uint256 totalRep = 0;
        uint256 maxRep = 0;
        for (uint i = 0; i < N; i++) {
            uint256 g = gasleft();
            bytes memory vector = abi.encodePacked(vm.unixTime(), i);
            (, uint256 rep) = BLS.hashToPoint(vector);
            uint256 cost = g - gasleft();
            totalGas += cost;
            maxGas = cost > maxGas ? cost : maxGas;
            totalRep += rep;
            maxRep = rep > maxRep ? rep : maxRep;
            // emit log_named_uint("hashToPoint gas cost", cost);
            // emit log_named_uint("repetition in sqrt", rep);
        }
        emit log_named_uint("hashToPoint average gas cost", totalGas / N);
        emit log_named_uint("hashToPoint max gas cost", maxGas);
        emit log_named_uint(
            "hashToPoint average repetition in sqrt; scaled by 100x",
            (totalRep * 100) / N
        );
        emit log_named_uint("hashToPoint max repetition in sqrt", maxRep);
    }

    function test_signAndVerify() public {
        // Generate a key pair using some random entropy
        bytes memory entropy = abi.encodePacked(
            blockhash(block.number - 1),
            block.timestamp
        );
        (uint256 privateKey, uint256[4] memory publicKey) = BLSSign
            .generateKeyPair(entropy);

        // Log the generated keys
        emit log_named_uint("Private Key", privateKey);
        emit log_named_uint("Public Key x0", publicKey[0]);
        emit log_named_uint("Public Key x1", publicKey[1]);
        emit log_named_uint("Public Key y0", publicKey[2]);
        emit log_named_uint("Public Key y1", publicKey[3]);

        // Verify the public key is valid
        assertTrue(
            BLS.isValidPublicKey(publicKey),
            "Public key should be valid"
        );

        // Create a test message
        bytes memory message = "Hello BLS"; // the same as go test case
        emit log_named_bytes("Message", message);
        // Sign the message
        uint256[2] memory signature = BLSSign.sign(message, privateKey);

        // Log the signature
        emit log_named_uint("Signature[0]", signature[0]);
        emit log_named_uint("Signature[1]", signature[1]);

        // Verify the signature is valid
        assertTrue(
            BLS.isValidSignature(signature),
            "Signature should be valid"
        );

        // Hash message to point for verification
        (uint256[2] memory messagePoint, ) = BLS.hashToPoint(message);
        emit log_named_uint("hash x", messagePoint[0]);
        emit log_named_uint("hash y", messagePoint[1]);

        // Verify the signature using verifySingle
        bool isValid = BLS.verifySingle(signature, publicKey, messagePoint);
        assertTrue(isValid, "Signature verification should succeed");

        uint256 gas = verifySingleeGasCost(signature, publicKey, messagePoint);
        emit log_named_uint("verifySingle gas cost", gas);

        // Test with wrong message
        bytes memory wrongMessage = "Wrong message";
        (uint256[2] memory wrongMessagePoint, ) = BLS.hashToPoint(wrongMessage);

        bool shouldFail = BLS.verifySingle(
            signature,
            publicKey,
            wrongMessagePoint
        );

        assertFalse(shouldFail, "Verification with wrong message should fail");

        // test with wrong signature and correct message
        bytes memory wrong_message = "Hello, BLS!I'm wrong";
        uint256[2] memory wrongSignature = BLSSign.sign(message, privateKey);
        shouldFail = BLS.verifySingle(wrongSignature, publicKey, messagePoint);
    }
}
