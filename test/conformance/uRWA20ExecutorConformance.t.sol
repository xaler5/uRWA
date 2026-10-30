// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {uRWA20} from "../../contracts/uRWA20.sol";
import {IERC7943Fungible} from "../../contracts/interfaces/IERC7943.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

/// @notice Forwards a call to the token, in the shape of ERC-8226's `IAgentExecutor.execute`.
/// @dev The mandate check ERC-8226 puts here is left out: it is the executor's gate, and the token does not see it.
contract ForwardingExecutor {
    function execute(address target, bytes calldata data) external returns (bytes memory result) {
        bool ok;
        (ok, result) = target.call(data);
        if (!ok) {
            assembly {
                revert(add(result, 0x20), mload(result))
            }
        }
    }
}

/// @notice Conformance cases for a transfer settled by an executor the holder has approved.
/// @dev ERC-7943 does not define executors. To the token, an executor that forwards to `transferFrom` is a contract
/// operator, so these cases follow from the public-transfer rules:
/// - The executor is not part of the decision: it needs no eligibility of its own and cannot get past a check.
/// - `canTransfer` decides at the state of settlement, not the state when the holder authorised the transfer.
/// - An allowance shortfall is left to the base standard, as a balance shortfall is.
contract uRWA20ExecutorConformanceTest is Test {
    uRWA20 internal token;
    ForwardingExecutor internal executor;

    address internal admin = makeAddr("admin");
    address internal alice = makeAddr("alice"); // can send and receive, holds 100, approves the executor
    address internal bob = makeAddr("bob"); // can send and receive
    address internal carol = makeAddr("carol"); // not whitelisted at all

    function setUp() public {
        token = new uRWA20("Conformance RWA", "CRWA", admin);
        executor = new ForwardingExecutor();
        vm.startPrank(admin);
        token.changeSendWhitelist(alice, true);
        token.changeReceiveWhitelist(alice, true);
        token.changeSendWhitelist(bob, true);
        token.changeReceiveWhitelist(bob, true);
        token.mint(alice, 100);
        vm.stopPrank();
        vm.prank(alice);
        token.approve(address(executor), type(uint256).max);
    }

    function _settle(address from, address to, uint256 amount) internal {
        executor.execute(address(token), abi.encodeCall(token.transferFrom, (from, to, amount)));
    }

    // ---------------------------------------------------------------------
    // The executor is not part of the decision
    // ---------------------------------------------------------------------

    function test_Executor_NotWhitelistedExecutorCanSettleAllowedFunds() public {
        assertFalse(token.canSend(address(executor)));
        assertFalse(token.canReceive(address(executor)));
        assertTrue(token.canTransfer(alice, bob, 10));
        _settle(alice, bob, 10);
        assertEq(token.balanceOf(bob), 10);
    }

    function test_Executor_SenderCannotSend() public {
        vm.prank(admin);
        token.changeSendWhitelist(alice, false);
        assertFalse(token.canTransfer(alice, bob, 10));
        vm.expectRevert(abi.encodeWithSelector(IERC7943Fungible.ERC7943CannotSend.selector, alice));
        _settle(alice, bob, 10);
    }

    function test_Executor_ReceiverCannotReceive() public {
        assertFalse(token.canTransfer(alice, carol, 10));
        vm.expectRevert(abi.encodeWithSelector(IERC7943Fungible.ERC7943CannotReceive.selector, carol));
        _settle(alice, carol, 10);
    }

    function test_Executor_AboveUnfrozenBlocked() public {
        vm.prank(admin);
        token.setFrozenTokens(alice, 60);
        assertFalse(token.canTransfer(alice, bob, 41));
        vm.expectRevert(
            abi.encodeWithSelector(IERC7943Fungible.ERC7943InsufficientUnfrozenBalance.selector, alice, 41, 40)
        );
        _settle(alice, bob, 41);
    }

    // ---------------------------------------------------------------------
    // The state at settlement decides
    // ---------------------------------------------------------------------

    /// @dev A holder can authorise a transfer long before it settles. Eligibility can change in between.
    function test_Executor_EligibilityLostBeforeSettlementBlocks() public {
        assertTrue(token.canTransfer(alice, bob, 10));
        vm.prank(admin);
        token.changeReceiveWhitelist(bob, false);
        assertFalse(token.canTransfer(alice, bob, 10));
        vm.expectRevert(abi.encodeWithSelector(IERC7943Fungible.ERC7943CannotReceive.selector, bob));
        _settle(alice, bob, 10);
    }

    /// @dev Each settlement spends the unfrozen amount, so the next prediction has to be read at the new state.
    function test_Executor_EarlierSettlementChangesTheNextPrediction() public {
        vm.prank(admin);
        token.setFrozenTokens(alice, 60);
        assertTrue(token.canTransfer(alice, bob, 30));
        _settle(alice, bob, 30);

        assertFalse(token.canTransfer(alice, bob, 30));
        vm.expectRevert(
            abi.encodeWithSelector(IERC7943Fungible.ERC7943InsufficientUnfrozenBalance.selector, alice, 30, 10)
        );
        _settle(alice, bob, 30);

        assertTrue(token.canTransfer(alice, bob, 10));
        _settle(alice, bob, 10);
        assertEq(token.balanceOf(bob), 40);
    }

    // ---------------------------------------------------------------------
    // Shortfalls are left to the base standard
    // ---------------------------------------------------------------------

    function test_Executor_AllowanceShortfall_LeftToBaseStandard() public {
        vm.prank(alice);
        token.approve(address(executor), 5);
        assertTrue(token.canTransfer(alice, bob, 10));
        vm.expectRevert(
            abi.encodeWithSelector(IERC20Errors.ERC20InsufficientAllowance.selector, address(executor), 5, 10)
        );
        _settle(alice, bob, 10);
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
        token.setFrozenTokens(alice, frozen);
        vm.stopPrank();

        bool predicted = token.canTransfer(alice, bob, amount);
        uint256 snapshot = vm.snapshotState();
        vm.prank(alice);
        (bool directOk, ) = address(token).call(abi.encodeCall(token.transfer, (bob, amount)));
        vm.revertToState(snapshot);
        (bool executorOk, ) = address(executor).call(
            abi.encodeCall(executor.execute, (address(token), abi.encodeCall(token.transferFrom, (alice, bob, amount))))
        );
        assertEq(directOk, predicted);
        assertEq(executorOk, predicted);
    }
}
