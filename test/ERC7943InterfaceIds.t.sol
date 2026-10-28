// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {
    IERC7943Fungible,
    IERC7943NonFungible,
    IERC7943MultiToken
} from "../contracts/interfaces/IERC7943.sol";

/// @notice Pins the locally compiled interfaces to the ERC-165 identifiers
/// mandated by Final ERC-7943. The implementation test suites assert
/// `supportsInterface(type(IERC7943...).interfaceId)`, which only establishes
/// agreement between each contract and the interface compiled beside it; this
/// test anchors that interface to the normative external values so any future
/// signature drift fails loudly instead of passing green.
contract ERC7943InterfaceIdsTest is Test {
    function test_FinalInterfaceIds() public pure {
        assertTrue(type(IERC7943Fungible).interfaceId == bytes4(0x3edbb4c4));
        assertTrue(type(IERC7943NonFungible).interfaceId == bytes4(0xbf1ef5fe));
        assertTrue(type(IERC7943MultiToken).interfaceId == bytes4(0x41c4fbad));
    }
}
