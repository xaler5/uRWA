// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {uRWA20} from "../../contracts/uRWA20.sol";
import {IERC7943Fungible} from "../../contracts/interfaces/IERC7943.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

/// @notice Conformance cases for the fungible ERC-7943 interface.
/// @dev Each case states what `canTransfer` predicts and what the real movement does, so another
/// implementation can be checked against the same expectations. The rule being exercised:
/// - Public transfers (including operator transfers) and permissionless mints/burns MUST NOT succeed
///   when `canTransfer` is false.
/// - `canTransfer` MUST NOT return false for balance shortfalls; those are left to the base standard.
/// - A zero `from` / `to` is the mint / burn pre-flight, with no account check on the zero side.
/// - Permissioned mints, burns and forced transfers MAY bypass parts of `canTransfer`.
contract uRWA20ConformanceTest is Test {
    uRWA20 internal token;

    address internal admin = makeAddr("admin");
    address internal alice = makeAddr("alice"); // can send and receive, holds 100
    address internal bob = makeAddr("bob"); // can send and receive
    address internal carol = makeAddr("carol"); // not whitelisted at all
    address internal operator = makeAddr("operator"); // not whitelisted, only approved by alice

    function setUp() public {
        token = new uRWA20("Conformance RWA", "CRWA", admin);
        vm.startPrank(admin);
        _allow(alice, true, true);
        _allow(bob, true, true);
        token.mint(alice, 100);
        token.grantRole(token.BURNER_ROLE(), alice);
        vm.stopPrank();
    }

    function _allow(address account, bool send, bool receive_) internal {
        token.changeSendWhitelist(account, send);
        token.changeReceiveWhitelist(account, receive_);
    }

    // ---------------------------------------------------------------------
    // Ordinary transfers
    // ---------------------------------------------------------------------

    function test_Transfer_Allowed() public {
        assertTrue(token.canTransfer(alice, bob, 10));
        vm.prank(alice);
        token.transfer(bob, 10);
        assertEq(token.balanceOf(bob), 10);
    }

    function test_Transfer_SenderCannotSend() public {
        vm.prank(admin);
        token.changeSendWhitelist(alice, false);
        assertFalse(token.canTransfer(alice, bob, 10));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC7943Fungible.ERC7943CannotSend.selector, alice));
        token.transfer(bob, 10);
    }

    function test_Transfer_ReceiverCannotReceive() public {
        assertFalse(token.canTransfer(alice, carol, 10));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC7943Fungible.ERC7943CannotReceive.selector, carol));
        token.transfer(carol, 10);
    }

    /// @dev Send and receive eligibility are independent: an account can be allowed to exit but not to enter.
    function test_Transfer_OneWayRestriction() public {
        vm.startPrank(admin);
        token.mint(bob, 10);
        token.changeReceiveWhitelist(bob, false);
        vm.stopPrank();

        assertTrue(token.canTransfer(bob, alice, 10));
        vm.prank(bob);
        token.transfer(alice, 10);

        assertFalse(token.canTransfer(alice, bob, 10));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC7943Fungible.ERC7943CannotReceive.selector, bob));
        token.transfer(bob, 10);
    }

    // ---------------------------------------------------------------------
    // Operator transfers: the operator is not part of the decision
    // ---------------------------------------------------------------------

    function test_Operator_NotWhitelistedOperatorCanMoveAllowedFunds() public {
        vm.prank(alice);
        token.approve(operator, 10);
        assertTrue(token.canTransfer(alice, bob, 10));
        vm.prank(operator);
        token.transferFrom(alice, bob, 10);
        assertEq(token.balanceOf(bob), 10);
    }

    function test_Operator_BlockedReceiverStillBlocked() public {
        vm.prank(alice);
        token.approve(operator, 10);
        assertFalse(token.canTransfer(alice, carol, 10));
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(IERC7943Fungible.ERC7943CannotReceive.selector, carol));
        token.transferFrom(alice, carol, 10);
    }

    // ---------------------------------------------------------------------
    // Frozen amounts and balance shortfalls
    // ---------------------------------------------------------------------

    function test_Frozen_WithinUnfrozenAllowed() public {
        vm.prank(admin);
        token.setFrozenTokens(alice, 60);
        assertTrue(token.canTransfer(alice, bob, 40));
        vm.prank(alice);
        token.transfer(bob, 40);
    }

    function test_Frozen_AboveUnfrozenBlocked() public {
        vm.prank(admin);
        token.setFrozenTokens(alice, 60);
        assertFalse(token.canTransfer(alice, bob, 41));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC7943Fungible.ERC7943InsufficientUnfrozenBalance.selector, alice, 41, 40));
        token.transfer(bob, 41);
    }

    /// @dev The frozen amount may exceed the balance; nothing is then transferable.
    function test_Frozen_AboveBalanceBlocksEverything() public {
        vm.prank(admin);
        token.setFrozenTokens(alice, 200);
        assertFalse(token.canTransfer(alice, bob, 1));
    }

    /// @dev With nothing frozen, a shortfall is a base-standard concern: `canTransfer` stays true and the
    /// transfer reverts with the ERC-20 error, not an ERC-7943 one.
    function test_Shortfall_NothingFrozen_LeftToBaseStandard() public {
        assertTrue(token.canTransfer(alice, bob, 101));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InsufficientBalance.selector, alice, 100, 101));
        token.transfer(bob, 101);
    }

    // ---------------------------------------------------------------------
    // Mint and burn pre-flights (zero `from` / `to`)
    // ---------------------------------------------------------------------

    function test_Mint_Preflight_AllowedReceiver() public {
        assertTrue(token.canTransfer(address(0), bob, 10));
        vm.prank(admin);
        token.mint(bob, 10);
    }

    function test_Mint_Preflight_BlockedReceiver() public {
        assertFalse(token.canTransfer(address(0), carol, 10));
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(IERC7943Fungible.ERC7943CannotReceive.selector, carol));
        token.mint(carol, 10);
    }

    function test_Burn_Preflight_AllowedSender() public {
        assertTrue(token.canTransfer(alice, address(0), 10));
        vm.prank(alice);
        token.burn(10);
        assertEq(token.balanceOf(alice), 90);
    }

    function test_Burn_Preflight_BlockedSender() public {
        vm.prank(admin);
        token.changeSendWhitelist(alice, false);
        assertFalse(token.canTransfer(alice, address(0), 10));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC7943Fungible.ERC7943CannotSend.selector, alice));
        token.burn(10);
    }

    /// @dev A permissionless burn would have to respect the unfrozen amount, so the pre-flight says no.
    /// The reference `burn` is permissioned (BURNER_ROLE) and uses the exception the spec allows: it
    /// goes through and reduces the frozen amount instead.
    function test_Burn_PermissionedMayBypassFrozen() public {
        vm.prank(admin);
        token.setFrozenTokens(alice, 100);
        assertFalse(token.canTransfer(alice, address(0), 10));
        vm.prank(alice);
        token.burn(10);
        assertEq(token.balanceOf(alice), 90);
        assertEq(token.getFrozenTokens(alice), 90);
    }

    /// @dev The zero address is the mint source and burn sink, so it always passes the account checks.
    /// That is what makes mint/burn pre-flights depend only on the non-zero side. It does not make a plain
    /// transfer to the zero address possible: the base standard still rejects it.
    function test_ZeroAddress_AlwaysPassesAccountChecks() public {
        assertTrue(token.canSend(address(0)));
        assertTrue(token.canReceive(address(0)));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InvalidReceiver.selector, address(0)));
        token.transfer(address(0), 10);
    }

    // ---------------------------------------------------------------------
    // Forced transfers: restricted path, not predicted by canTransfer
    // ---------------------------------------------------------------------

    function test_Forced_BypassesSenderEligibility() public {
        vm.prank(admin);
        token.changeSendWhitelist(alice, false);
        assertFalse(token.canTransfer(alice, bob, 10));
        vm.prank(admin);
        token.forcedTransfer(alice, bob, 10);
        assertEq(token.balanceOf(bob), 10);
    }

    function test_Forced_StillChecksReceiver() public {
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(IERC7943Fungible.ERC7943CannotReceive.selector, carol));
        token.forcedTransfer(alice, carol, 10);
    }

    function test_Forced_MovesFrozenAndReducesFrozenAmount() public {
        vm.startPrank(admin);
        token.setFrozenTokens(alice, 100);
        token.forcedTransfer(alice, bob, 30);
        vm.stopPrank();
        assertEq(token.balanceOf(alice), 70);
        assertEq(token.getFrozenTokens(alice), 70);
    }

    // ---------------------------------------------------------------------
    // Parity: for ordinary transfers within the balance, the pre-flight matches the real outcome
    // ---------------------------------------------------------------------

    function testFuzz_Parity_Transfer(bool fromSend, bool toReceive, uint256 frozen, uint256 amount) public {
        amount = bound(amount, 0, 100);
        frozen = bound(frozen, 0, 200);
        vm.startPrank(admin);
        token.changeSendWhitelist(alice, fromSend);
        token.changeReceiveWhitelist(bob, toReceive);
        token.setFrozenTokens(alice, frozen);
        vm.stopPrank();

        bool predicted = token.canTransfer(alice, bob, amount);
        vm.prank(alice);
        (bool ok, ) = address(token).call(abi.encodeCall(token.transfer, (bob, amount)));
        assertEq(ok, predicted);
    }

    function testFuzz_Parity_Mint(bool toReceive, uint256 amount) public {
        amount = bound(amount, 0, type(uint128).max);
        vm.prank(admin);
        token.changeReceiveWhitelist(bob, toReceive);

        bool predicted = token.canTransfer(address(0), bob, amount);
        vm.prank(admin);
        (bool ok, ) = address(token).call(abi.encodeCall(token.mint, (bob, amount)));
        assertEq(ok, predicted);
    }
}
