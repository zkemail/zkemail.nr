// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import "./Verifier.sol";

contract VerifierTest {

    HonkVerifier public verifier = new HonkVerifier();

    function verify(bytes calldata _proof, uint256 _pubkey, uint256 _nullifier) external view returns (bool) {
        bytes32[] memory publicInputs = new bytes32[](2);
        publicInputs[0] = bytes32(_pubkey);
        publicInputs[1] = bytes32(_nullifier);
        return verifier.verify(_proof, publicInputs);
    }
}
