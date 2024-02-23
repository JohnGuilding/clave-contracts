// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;
pragma abicoder v2;

import {IGroth16Verifier} from "../interfaces/IGroth16Verifier.sol";

// Mock/stub of snarkjs Groth16 Solidity verifier.
// We can't allow the result to change via a flag in storage as
// that would break ERC-4337 validation storage rules.
//
// This will eventually be removed in favor of real ZKP verfication contract.
// https://github.com/getwax/wax/issues/143
contract MockGroth16Verifier is IGroth16Verifier {
    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[5] memory publicSignals
    ) external pure returns (bool r) {
        a;
        b;
        c;
        publicSignals;

        r = true;
    }
}
