// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {uRWA1155} from "../../contracts/uRWA1155.sol";
import {IERC7943MultiToken} from "../../contracts/interfaces/IERC7943.sol";
import {IERC1155Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

/// @notice Conformance cases for the multi-token ERC-7943 interface.
/// @dev Same rules as the fungible suite (see uRWA20Conformance.t.sol), per token id, plus batch cases.
contract uRWA1155ConformanceTest is Test {
    uRWA1155 internal token;

    address internal admin = makeAddr("admin");
    address internal alice = makeAddr("alice"); // can send and receive, holds 100 of ID
    address internal bob = makeAddr("bob"); // can send and receive
    address internal carol = makeAddr("carol"); // not whitelisted at all
    address internal operator = makeAddr("operator"); // not whitelisted, approved by alice

    uint256 internal constant ID = 1;

    function setUp() public {
        token = new uRWA1155("uri", admin);
        vm.startPrank(admin);
        token.changeSendWhitelist(alice, true);
        token.changeReceiveWhitelist(alice, true);
        token.changeSendWhitelist(bob, true);
        token.changeReceiveWhitelist(bob, true);
        token.mint(alice, ID, 100);
        token.grantRole(token.BURNER_ROLE(), alice);
        vm.stopPrank();
    }

    function _pair(uint256 a, uint256 b) internal pure returns (uint256[] memory arr) {
        arr = new uint256[](2);
        arr[0] = a;
        arr[1] = b;
    }

    function test_Transfer_Allowed() public {
        assertTrue(token.canTransfer(alice, bob, ID, 10));
        vm.prank(alice);
        token.safeTransferFrom(alice, bob, ID, 10, "");
        assertEq(token.balanceOf(bob, ID), 10);
    }

    function test_Transfer_ReceiverCannotReceive() public {
        assertFalse(token.canTransfer(alice, carol, ID, 10));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC7943MultiToken.ERC7943CannotReceive.selector, carol));
        token.safeTransferFrom(alice, carol, ID, 10, "");
    }

    function test_Operator_NotWhitelistedOperatorCanMoveAllowedFunds() public {
        vm.prank(alice);
        token.setApprovalForAll(operator, true);
        assertTrue(token.canTransfer(alice, bob, ID, 10));
        vm.prank(operator);
        token.safeTransferFrom(alice, bob, ID, 10, "");
        assertEq(token.balanceOf(bob, ID), 10);
    }

    function test_Frozen_AboveUnfrozenBlocked() public {
        vm.prank(admin);
        token.setFrozenTokens(alice, ID, 60);
        assertFalse(token.canTransfer(alice, bob, ID, 41));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC7943MultiToken.ERC7943InsufficientUnfrozenBalance.selector, alice, ID, 41, 40));
        token.safeTransferFrom(alice, bob, ID, 41, "");
    }

    function test_Shortfall_NothingFrozen_LeftToBaseStandard() public {
        assertTrue(token.canTransfer(alice, bob, ID, 101));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC1155Errors.ERC1155InsufficientBalance.selector, alice, 100, 101, ID));
        token.safeTransferFrom(alice, bob, ID, 101, "");
    }

    /// @dev Regression for ethereum/ERCs#1814: repeating an id in a batch must not let each entry pass
    /// against the same unfrozen amount. 40 + 40 of id 1 with 40 unfrozen is 80, which is blocked.
    function test_Batch_DuplicateIdCannotBypassFreeze() public {
        vm.prank(admin);
        token.setFrozenTokens(alice, ID, 60);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC7943MultiToken.ERC7943InsufficientUnfrozenBalance.selector, alice, ID, 80, 40));
        token.safeBatchTransferFrom(alice, bob, _pair(ID, ID), _pair(40, 40), "");
    }

    function test_Batch_DuplicateIdWithinUnfrozenAllowed() public {
        vm.prank(admin);
        token.setFrozenTokens(alice, ID, 60);
        vm.prank(alice);
        token.safeBatchTransferFrom(alice, bob, _pair(ID, ID), _pair(20, 20), "");
        assertEq(token.balanceOf(bob, ID), 40);
    }

    /// @dev A self-transfer credits each entry back before the next, so a repeated id is checked
    /// per entry, as in the base standard.
    function test_Batch_SelfTransferDuplicateIdNothingFrozen() public {
        vm.prank(alice);
        token.safeBatchTransferFrom(alice, alice, _pair(ID, ID), _pair(100, 100), "");
        assertEq(token.balanceOf(alice, ID), 100);
    }

    function test_Batch_SelfTransferDuplicateIdWithinUnfrozen() public {
        vm.prank(admin);
        token.setFrozenTokens(alice, ID, 60);
        vm.prank(alice);
        token.safeBatchTransferFrom(alice, alice, _pair(ID, ID), _pair(40, 40), "");
        assertEq(token.balanceOf(alice, ID), 100);
        assertEq(token.getFrozenTokens(alice, ID), 60);
    }

    /// @dev A permissioned batch burn with a repeated id reduces the frozen amount by the total excess,
    /// leaving frozen equal to what is left (100 frozen, 60 burned -> 40 balance, 40 frozen).
    function test_Batch_DuplicateIdBurnAdjustsFrozenOnce() public {
        vm.prank(admin);
        token.setFrozenTokens(alice, ID, 100);
        vm.prank(alice);
        token.burnBatch(_pair(ID, ID), _pair(30, 30));
        assertEq(token.balanceOf(alice, ID), 40);
        assertEq(token.getFrozenTokens(alice, ID), 40);
    }

    function test_Mint_Preflight_AllowedReceiver() public {
        assertTrue(token.canTransfer(address(0), bob, ID, 10));
        vm.prank(admin);
        token.mint(bob, ID, 10);
    }

    function test_Mint_Preflight_BlockedReceiver() public {
        assertFalse(token.canTransfer(address(0), carol, ID, 10));
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(IERC7943MultiToken.ERC7943CannotReceive.selector, carol));
        token.mint(carol, ID, 10);
    }

    function test_Burn_Preflight_AllowedSender() public {
        assertTrue(token.canTransfer(alice, address(0), ID, 10));
        vm.prank(alice);
        token.burn(ID, 10);
    }

    function test_Burn_Preflight_BlockedSender() public {
        vm.prank(admin);
        token.changeSendWhitelist(alice, false);
        assertFalse(token.canTransfer(alice, address(0), ID, 10));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC7943MultiToken.ERC7943CannotSend.selector, alice));
        token.burn(ID, 10);
    }

    /// @dev The zero address is the mint source and burn sink, so it always passes the account checks.
    /// That is what makes mint/burn pre-flights depend only on the non-zero side. It does not make a plain
    /// transfer to the zero address possible: the base standard still rejects it.
    function test_ZeroAddress_AlwaysPassesAccountChecks() public {
        assertTrue(token.canSend(address(0)));
        assertTrue(token.canReceive(address(0)));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC1155Errors.ERC1155InvalidReceiver.selector, address(0)));
        token.safeTransferFrom(alice, address(0), ID, 10, "");
    }

    function test_Forced_BypassesSenderEligibility() public {
        vm.prank(admin);
        token.changeSendWhitelist(alice, false);
        assertFalse(token.canTransfer(alice, bob, ID, 10));
        vm.prank(admin);
        token.forcedTransfer(alice, bob, ID, 10);
        assertEq(token.balanceOf(bob, ID), 10);
    }

    function test_Forced_StillChecksReceiver() public {
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(IERC7943MultiToken.ERC7943CannotReceive.selector, carol));
        token.forcedTransfer(alice, carol, ID, 10);
    }

    function testFuzz_Parity_Transfer(bool fromSend, bool toReceive, uint256 frozen, uint256 amount) public {
        amount = bound(amount, 0, 100);
        frozen = bound(frozen, 0, 200);
        vm.startPrank(admin);
        token.changeSendWhitelist(alice, fromSend);
        token.changeReceiveWhitelist(bob, toReceive);
        token.setFrozenTokens(alice, ID, frozen);
        vm.stopPrank();

        bool predicted = token.canTransfer(alice, bob, ID, amount);
        vm.prank(alice);
        (bool ok, ) = address(token).call(abi.encodeCall(token.safeTransferFrom, (alice, bob, ID, amount, "")));
        assertEq(ok, predicted);
    }

    function testFuzz_Parity_Mint(bool toReceive, uint256 amount) public {
        amount = bound(amount, 0, type(uint128).max);
        vm.prank(admin);
        token.changeReceiveWhitelist(bob, toReceive);

        bool predicted = token.canTransfer(address(0), bob, ID, amount);
        vm.prank(admin);
        (bool ok, ) = address(token).call(abi.encodeCall(token.mint, (bob, ID, amount)));
        assertEq(ok, predicted);
    }
}
