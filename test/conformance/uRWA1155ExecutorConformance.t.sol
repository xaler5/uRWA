// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {uRWA1155} from "../../contracts/uRWA1155.sol";
import {IERC7943MultiToken} from "../../contracts/interfaces/IERC7943.sol";
import {IERC1155Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {ForwardingExecutor} from "./uRWA20ExecutorConformance.t.sol";

/// @notice Conformance cases for a transfer settled by an executor the holder has approved.
/// @dev Same rules as the fungible executor suite, per token id, plus batches:
/// - The executor is not part of the decision: it needs no eligibility of its own and cannot get past a check.
/// - `canTransfer` decides at the state of settlement, not the state when the holder authorised the transfer.
/// - A missing approval is left to the base standard.
/// - A repeated id in a batch is checked against its running total, except in a self-transfer, which credits each
///   entry back before the next and is checked per entry.
contract uRWA1155ExecutorConformanceTest is Test {
    uRWA1155 internal token;
    ForwardingExecutor internal executor;

    address internal admin = makeAddr("admin");
    address internal alice = makeAddr("alice"); // can send and receive, holds 100 of ID, approves the executor
    address internal bob = makeAddr("bob"); // can send and receive
    address internal carol = makeAddr("carol"); // not whitelisted at all

    uint256 internal constant ID = 1;

    function setUp() public {
        token = new uRWA1155("uri", admin);
        executor = new ForwardingExecutor();
        vm.startPrank(admin);
        token.changeSendWhitelist(alice, true);
        token.changeReceiveWhitelist(alice, true);
        token.changeSendWhitelist(bob, true);
        token.changeReceiveWhitelist(bob, true);
        token.mint(alice, ID, 100);
        vm.stopPrank();
        vm.prank(alice);
        token.setApprovalForAll(address(executor), true);
    }

    function _pair(uint256 a, uint256 b) internal pure returns (uint256[] memory arr) {
        arr = new uint256[](2);
        arr[0] = a;
        arr[1] = b;
    }

    function _settle(address from, address to, uint256 amount) internal {
        executor.execute(address(token), abi.encodeCall(token.safeTransferFrom, (from, to, ID, amount, "")));
    }

    function _settleBatch(address from, address to, uint256 first, uint256 second) internal {
        executor.execute(
            address(token),
            abi.encodeCall(token.safeBatchTransferFrom, (from, to, _pair(ID, ID), _pair(first, second), ""))
        );
    }

    // ---------------------------------------------------------------------
    // The executor is not part of the decision
    // ---------------------------------------------------------------------

    function test_Executor_NotWhitelistedExecutorCanSettleAllowedFunds() public {
        assertFalse(token.canSend(address(executor)));
        assertFalse(token.canReceive(address(executor)));
        assertTrue(token.canTransfer(alice, bob, ID, 10));
        _settle(alice, bob, 10);
        assertEq(token.balanceOf(bob, ID), 10);
    }

    function test_Executor_SenderCannotSend() public {
        vm.prank(admin);
        token.changeSendWhitelist(alice, false);
        assertFalse(token.canTransfer(alice, bob, ID, 10));
        vm.expectRevert(abi.encodeWithSelector(IERC7943MultiToken.ERC7943CannotSend.selector, alice));
        _settle(alice, bob, 10);
    }

    function test_Executor_ReceiverCannotReceive() public {
        assertFalse(token.canTransfer(alice, carol, ID, 10));
        vm.expectRevert(abi.encodeWithSelector(IERC7943MultiToken.ERC7943CannotReceive.selector, carol));
        _settle(alice, carol, 10);
    }

    function test_Executor_AboveUnfrozenBlocked() public {
        vm.prank(admin);
        token.setFrozenTokens(alice, ID, 60);
        assertFalse(token.canTransfer(alice, bob, ID, 41));
        vm.expectRevert(
            abi.encodeWithSelector(IERC7943MultiToken.ERC7943InsufficientUnfrozenBalance.selector, alice, ID, 41, 40)
        );
        _settle(alice, bob, 41);
    }

    // ---------------------------------------------------------------------
    // The state at settlement decides
    // ---------------------------------------------------------------------

    /// @dev A holder can authorise a transfer long before it settles. Eligibility can change in between.
    function test_Executor_EligibilityLostBeforeSettlementBlocks() public {
        assertTrue(token.canTransfer(alice, bob, ID, 10));
        vm.prank(admin);
        token.changeReceiveWhitelist(bob, false);
        assertFalse(token.canTransfer(alice, bob, ID, 10));
        vm.expectRevert(abi.encodeWithSelector(IERC7943MultiToken.ERC7943CannotReceive.selector, bob));
        _settle(alice, bob, 10);
    }

    /// @dev Each settlement spends the unfrozen amount, so the next prediction has to be read at the new state.
    function test_Executor_EarlierSettlementChangesTheNextPrediction() public {
        vm.prank(admin);
        token.setFrozenTokens(alice, ID, 60);
        assertTrue(token.canTransfer(alice, bob, ID, 30));
        _settle(alice, bob, 30);

        assertFalse(token.canTransfer(alice, bob, ID, 30));
        vm.expectRevert(
            abi.encodeWithSelector(IERC7943MultiToken.ERC7943InsufficientUnfrozenBalance.selector, alice, ID, 30, 10)
        );
        _settle(alice, bob, 30);

        assertTrue(token.canTransfer(alice, bob, ID, 10));
        _settle(alice, bob, 10);
        assertEq(token.balanceOf(bob, ID), 40);
    }

    // ---------------------------------------------------------------------
    // A missing approval is left to the base standard
    // ---------------------------------------------------------------------

    function test_Executor_MissingApproval_LeftToBaseStandard() public {
        vm.prank(alice);
        token.setApprovalForAll(address(executor), false);
        assertTrue(token.canTransfer(alice, bob, ID, 10));
        vm.expectRevert(
            abi.encodeWithSelector(IERC1155Errors.ERC1155MissingApprovalForAll.selector, address(executor), alice)
        );
        _settle(alice, bob, 10);
    }

    // ---------------------------------------------------------------------
    // Batches with a repeated id, between two accounts: the running total is checked
    // ---------------------------------------------------------------------

    function test_Executor_Batch_DuplicateIdCannotBypassFreeze() public {
        vm.prank(admin);
        token.setFrozenTokens(alice, ID, 60);
        vm.expectRevert(
            abi.encodeWithSelector(IERC7943MultiToken.ERC7943InsufficientUnfrozenBalance.selector, alice, ID, 80, 40)
        );
        _settleBatch(alice, bob, 40, 40);
    }

    function test_Executor_Batch_DuplicateIdWithinUnfrozenAllowed() public {
        vm.prank(admin);
        token.setFrozenTokens(alice, ID, 60);
        _settleBatch(alice, bob, 20, 20);
        assertEq(token.balanceOf(bob, ID), 40);
    }

    function test_Executor_Batch_DuplicateIdAboveBalanceBlocked() public {
        vm.expectRevert(abi.encodeWithSelector(IERC1155Errors.ERC1155InsufficientBalance.selector, alice, 100, 200, ID));
        _settleBatch(alice, bob, 100, 100);
    }

    // ---------------------------------------------------------------------
    // Batches with a repeated id, in a self-transfer: each entry is checked on its own
    // ---------------------------------------------------------------------

    /// @dev The same amounts that fail between two accounts above succeed here: each entry is credited back.
    function test_Executor_Batch_SelfTransferDuplicateIdNothingFrozen() public {
        _settleBatch(alice, alice, 100, 100);
        assertEq(token.balanceOf(alice, ID), 100);
    }

    function test_Executor_Batch_SelfTransferDuplicateIdWithinUnfrozen() public {
        vm.prank(admin);
        token.setFrozenTokens(alice, ID, 60);
        _settleBatch(alice, alice, 40, 40);
        assertEq(token.balanceOf(alice, ID), 100);
        assertEq(token.getFrozenTokens(alice, ID), 60);
    }

    /// @dev A self-transfer is not an exemption: an entry above the unfrozen amount is still blocked.
    function test_Executor_Batch_SelfTransferEntryAboveUnfrozenBlocked() public {
        vm.prank(admin);
        token.setFrozenTokens(alice, ID, 60);
        vm.expectRevert(
            abi.encodeWithSelector(IERC7943MultiToken.ERC7943InsufficientUnfrozenBalance.selector, alice, ID, 41, 40)
        );
        _settleBatch(alice, alice, 40, 41);
    }

    // ---------------------------------------------------------------------
    // Parity: settling through the executor matches the pre-flight and a direct transfer
    // ---------------------------------------------------------------------

    function testFuzz_Parity_ExecutorMatchesDirectTransfer(
        bool fromSend,
        bool toReceive,
        uint256 frozen,
        uint256 amount
    ) public {
        amount = bound(amount, 0, 100);
        frozen = bound(frozen, 0, 200);
        vm.startPrank(admin);
        token.changeSendWhitelist(alice, fromSend);
        token.changeReceiveWhitelist(bob, toReceive);
        token.setFrozenTokens(alice, ID, frozen);
        vm.stopPrank();

        bytes memory transferCall = abi.encodeCall(token.safeTransferFrom, (alice, bob, ID, amount, ""));
        bool predicted = token.canTransfer(alice, bob, ID, amount);
        uint256 snapshot = vm.snapshotState();
        vm.prank(alice);
        (bool directOk, ) = address(token).call(transferCall);
        vm.revertToState(snapshot);
        (bool executorOk, ) = address(executor).call(abi.encodeCall(executor.execute, (address(token), transferCall)));
        assertEq(directOk, predicted);
        assertEq(executorOk, predicted);
    }
}
