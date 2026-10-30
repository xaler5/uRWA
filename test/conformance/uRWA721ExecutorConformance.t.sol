// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {uRWA721} from "../../contracts/uRWA721.sol";
import {IERC7943NonFungible} from "../../contracts/interfaces/IERC7943.sol";
import {IERC721Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {ForwardingExecutor} from "./uRWA20ExecutorConformance.t.sol";

/// @notice Conformance cases for a transfer settled by an executor the holder has approved.
/// @dev Same rules as the fungible executor suite, per token id:
/// - The executor is not part of the decision: it needs no eligibility of its own and cannot get past a check.
/// - `canTransfer` decides at the state of settlement, not the state when the holder authorised the transfer.
/// - A missing approval is left to the base standard.
contract uRWA721ExecutorConformanceTest is Test {
    uRWA721 internal token;
    ForwardingExecutor internal executor;

    address internal admin = makeAddr("admin");
    address internal alice = makeAddr("alice"); // can send and receive, owns token 1, approves the executor
    address internal bob = makeAddr("bob"); // can send and receive
    address internal carol = makeAddr("carol"); // not whitelisted at all

    uint256 internal constant ID = 1;

    function setUp() public {
        token = new uRWA721("Conformance RWA", "CRWA", admin);
        executor = new ForwardingExecutor();
        vm.startPrank(admin);
        token.changeSendWhitelist(alice, true);
        token.changeReceiveWhitelist(alice, true);
        token.changeSendWhitelist(bob, true);
        token.changeReceiveWhitelist(bob, true);
        token.safeMint(alice, ID);
        vm.stopPrank();
        vm.prank(alice);
        token.setApprovalForAll(address(executor), true);
    }

    function _settle(address from, address to, uint256 id) internal {
        executor.execute(address(token), abi.encodeCall(token.transferFrom, (from, to, id)));
    }

    // ---------------------------------------------------------------------
    // The executor is not part of the decision
    // ---------------------------------------------------------------------

    function test_Executor_NotWhitelistedExecutorCanSettleAllowedToken() public {
        assertFalse(token.canSend(address(executor)));
        assertFalse(token.canReceive(address(executor)));
        assertTrue(token.canTransfer(alice, bob, ID));
        _settle(alice, bob, ID);
        assertEq(token.ownerOf(ID), bob);
    }

    function test_Executor_SenderCannotSend() public {
        vm.prank(admin);
        token.changeSendWhitelist(alice, false);
        assertFalse(token.canTransfer(alice, bob, ID));
        vm.expectRevert(abi.encodeWithSelector(IERC7943NonFungible.ERC7943CannotSend.selector, alice));
        _settle(alice, bob, ID);
    }

    function test_Executor_ReceiverCannotReceive() public {
        assertFalse(token.canTransfer(alice, carol, ID));
        vm.expectRevert(abi.encodeWithSelector(IERC7943NonFungible.ERC7943CannotReceive.selector, carol));
        _settle(alice, carol, ID);
    }

    function test_Executor_FrozenTokenBlocked() public {
        vm.prank(admin);
        token.setFrozenTokens(alice, ID, true);
        assertFalse(token.canTransfer(alice, bob, ID));
        vm.expectRevert(abi.encodeWithSelector(IERC7943NonFungible.ERC7943InsufficientUnfrozenBalance.selector, alice, ID));
        _settle(alice, bob, ID);
    }

    // ---------------------------------------------------------------------
    // The state at settlement decides
    // ---------------------------------------------------------------------

    /// @dev A holder can authorise a transfer long before it settles. Eligibility can change in between.
    function test_Executor_EligibilityLostBeforeSettlementBlocks() public {
        assertTrue(token.canTransfer(alice, bob, ID));
        vm.prank(admin);
        token.changeReceiveWhitelist(bob, false);
        assertFalse(token.canTransfer(alice, bob, ID));
        vm.expectRevert(abi.encodeWithSelector(IERC7943NonFungible.ERC7943CannotReceive.selector, bob));
        _settle(alice, bob, ID);
    }

    /// @dev Once a settlement moves the token, the approval the previous owner gave no longer reaches it.
    function test_Executor_TokenAlreadyMovedBlocks() public {
        _settle(alice, bob, ID);
        assertFalse(token.canTransfer(alice, bob, ID));
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721InsufficientApproval.selector, address(executor), ID));
        _settle(alice, bob, ID);
    }

    // ---------------------------------------------------------------------
    // A missing approval is left to the base standard
    // ---------------------------------------------------------------------

    function test_Executor_MissingApproval_LeftToBaseStandard() public {
        vm.prank(alice);
        token.setApprovalForAll(address(executor), false);
        assertTrue(token.canTransfer(alice, bob, ID));
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721InsufficientApproval.selector, address(executor), ID));
        _settle(alice, bob, ID);
    }

    // ---------------------------------------------------------------------
    // Parity: settling through the executor matches the pre-flight and a direct transfer
    // ---------------------------------------------------------------------

    function testFuzz_Parity_ExecutorMatchesDirectTransfer(bool fromSend, bool toReceive, bool frozen) public {
        vm.startPrank(admin);
        token.changeSendWhitelist(alice, fromSend);
        token.changeReceiveWhitelist(bob, toReceive);
        token.setFrozenTokens(alice, ID, frozen);
        vm.stopPrank();

        bool predicted = token.canTransfer(alice, bob, ID);
        uint256 snapshot = vm.snapshotState();
        vm.prank(alice);
        (bool directOk, ) = address(token).call(abi.encodeCall(token.transferFrom, (alice, bob, ID)));
        vm.revertToState(snapshot);
        (bool executorOk, ) = address(executor).call(
            abi.encodeCall(executor.execute, (address(token), abi.encodeCall(token.transferFrom, (alice, bob, ID))))
        );
        assertEq(directOk, predicted);
        assertEq(executorOk, predicted);
    }
}
