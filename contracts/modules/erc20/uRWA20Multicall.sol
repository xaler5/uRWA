// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {uRWA20} from "../../uRWA20.sol";
import {Multicall} from "@openzeppelin/contracts/utils/Multicall.sol";

contract uRWA20Multicall is uRWA20, Multicall {

    constructor(string memory name, string memory symbol, address initialAdmin)
        uRWA20(name, symbol, initialAdmin)
    {}
}