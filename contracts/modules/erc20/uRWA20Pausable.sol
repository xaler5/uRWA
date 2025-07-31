// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {uRWA20} from "../../uRWA20.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

contract uRWA20Pausable is uRWA20, Pausable {

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant UNPAUSER_ROLE = keccak256("UNPAUSER_ROLE");

    constructor(string memory name, string memory symbol, address initialAdmin)
        uRWA20(name, symbol, initialAdmin)
    {
        _grantRole(PAUSER_ROLE, initialAdmin);
        _grantRole(UNPAUSER_ROLE, initialAdmin);
    }

    function _update(address from, address to, uint256 amount) internal virtual override whenNotPaused() {
        super._update(from, to, amount);
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(UNPAUSER_ROLE) {
        _unpause();
    }
}