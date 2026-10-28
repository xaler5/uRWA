// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {uRWA20Pausable} from "../contracts/modules/erc20/uRWA20Pausable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/// @notice Final ERC-7943 requires `canTransfer` to return false (not revert)
/// whenever a permissioned rule would prevent the transfer, naming pausing as
/// an example. These tests pin that behavior for the pausable extension.
contract URWA20PausableTest is Test {
    uRWA20Pausable internal token;
    address internal admin = makeAddr("admin");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    function setUp() public {
        token = new uRWA20Pausable("Pausable RWA", "PRWA", admin);
        vm.startPrank(admin);
        token.changeSendWhitelist(alice, true);
        token.changeReceiveWhitelist(alice, true);
        token.changeSendWhitelist(bob, true);
        token.changeReceiveWhitelist(bob, true);
        token.mint(alice, 100);
        vm.stopPrank();
    }

    function test_CanTransferTrueBeforePause() public view {
        assertTrue(token.canTransfer(alice, bob, 10));
    }

    function test_CanTransferFalseWhilePausedWithoutReverting() public {
        vm.prank(admin);
        token.pause();

        // Must not revert and must report the transfer as not allowed.
        (bool success, bytes memory data) = address(token).staticcall(
            abi.encodeWithSelector(token.canTransfer.selector, alice, bob, uint256(10))
        );
        assertTrue(success);
        assertFalse(abi.decode(data, (bool)));

        // And the transfer itself is indeed blocked.
        vm.prank(alice);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        token.transfer(bob, 10);
    }

    function test_CanTransferTrueAgainAfterUnpause() public {
        vm.startPrank(admin);
        token.pause();
        token.unpause();
        vm.stopPrank();
        assertTrue(token.canTransfer(alice, bob, 10));
    }
}
