// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {uRWA721} from "../../contracts/uRWA721.sol";
import {IERC7943NonFungible} from "../../contracts/interfaces/IERC7943.sol";
import {IERC721Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

/// @notice Conformance cases for the non-fungible ERC-7943 interface.
/// @dev Same rules as the fungible suite (see uRWA20Conformance.t.sol); the frozen check is per token id.
contract uRWA721ConformanceTest is Test {
    uRWA721 internal token;

    address internal admin = makeAddr("admin");
    address internal alice = makeAddr("alice"); // can send and receive, owns token 1
    address internal bob = makeAddr("bob"); // can send and receive
    address internal carol = makeAddr("carol"); // not whitelisted at all
    address internal operator = makeAddr("operator"); // not whitelisted, approved by alice

    uint256 internal constant ID = 1;
    uint256 internal constant NEW_ID = 2;

    function setUp() public {
        token = new uRWA721("Conformance RWA", "CRWA", admin);
        vm.startPrank(admin);
        token.changeSendWhitelist(alice, true);
        token.changeReceiveWhitelist(alice, true);
        token.changeSendWhitelist(bob, true);
        token.changeReceiveWhitelist(bob, true);
        token.safeMint(alice, ID);
        token.grantRole(token.BURNER_ROLE(), alice);
        vm.stopPrank();
    }

    function test_Transfer_Allowed() public {
        assertTrue(token.canTransfer(alice, bob, ID));
        vm.prank(alice);
        token.transferFrom(alice, bob, ID);
        assertEq(token.ownerOf(ID), bob);
    }

    function test_Transfer_SenderCannotSend() public {
        vm.prank(admin);
        token.changeSendWhitelist(alice, false);
        assertFalse(token.canTransfer(alice, bob, ID));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC7943NonFungible.ERC7943CannotSend.selector, alice));
        token.transferFrom(alice, bob, ID);
    }

    function test_Transfer_ReceiverCannotReceive() public {
        assertFalse(token.canTransfer(alice, carol, ID));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC7943NonFungible.ERC7943CannotReceive.selector, carol));
        token.transferFrom(alice, carol, ID);
    }

    function test_Operator_NotWhitelistedOperatorCanMoveAllowedToken() public {
        vm.prank(alice);
        token.approve(operator, ID);
        assertTrue(token.canTransfer(alice, bob, ID));
        vm.prank(operator);
        token.safeTransferFrom(alice, bob, ID);
        assertEq(token.ownerOf(ID), bob);
    }

    function test_Frozen_TokenBlocked() public {
        vm.prank(admin);
        token.setFrozenTokens(alice, ID, true);
        assertFalse(token.canTransfer(alice, bob, ID));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC7943NonFungible.ERC7943InsufficientUnfrozenBalance.selector, alice, ID));
        token.transferFrom(alice, bob, ID);
    }

    function test_Mint_Preflight_AllowedReceiver() public {
        assertTrue(token.canTransfer(address(0), bob, NEW_ID));
        vm.prank(admin);
        token.safeMint(bob, NEW_ID);
    }

    function test_Mint_Preflight_BlockedReceiver() public {
        assertFalse(token.canTransfer(address(0), carol, NEW_ID));
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(IERC7943NonFungible.ERC7943CannotReceive.selector, carol));
        token.safeMint(carol, NEW_ID);
    }

    /// @dev A mint pre-flight for an id that already exists predicts nothing that can happen.
    function test_Mint_Preflight_ExistingIdFalse() public view {
        assertFalse(token.canTransfer(address(0), bob, ID));
    }

    function test_Burn_Preflight_AllowedSender() public {
        assertTrue(token.canTransfer(alice, address(0), ID));
        vm.prank(alice);
        token.burn(ID);
    }

    function test_Burn_Preflight_BlockedSender() public {
        vm.prank(admin);
        token.changeSendWhitelist(alice, false);
        assertFalse(token.canTransfer(alice, address(0), ID));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC7943NonFungible.ERC7943CannotSend.selector, alice));
        token.burn(ID);
    }

    /// @dev Permissioned burn of a frozen token is allowed and clears the freeze; the pre-flight
    /// (which describes the permissionless case) says no.
    function test_Burn_PermissionedMayBypassFrozen() public {
        vm.prank(admin);
        token.setFrozenTokens(alice, ID, true);
        assertFalse(token.canTransfer(alice, address(0), ID));
        vm.prank(alice);
        token.burn(ID);
        assertFalse(token.getFrozenTokens(alice, ID));
    }

    /// @dev The zero address is the mint source and burn sink, so it always passes the account checks.
    /// That is what makes mint/burn pre-flights depend only on the non-zero side. It does not make a plain
    /// transfer to the zero address possible: the base standard still rejects it.
    function test_ZeroAddress_AlwaysPassesAccountChecks() public {
        assertTrue(token.canSend(address(0)));
        assertTrue(token.canReceive(address(0)));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721InvalidReceiver.selector, address(0)));
        token.transferFrom(alice, address(0), ID);
    }

    function test_Forced_BypassesFrozenAndSenderEligibility() public {
        vm.startPrank(admin);
        token.changeSendWhitelist(alice, false);
        token.setFrozenTokens(alice, ID, true);
        vm.stopPrank();
        assertFalse(token.canTransfer(alice, bob, ID));
        vm.prank(admin);
        token.forcedTransfer(alice, bob, ID);
        assertEq(token.ownerOf(ID), bob);
        assertFalse(token.getFrozenTokens(alice, ID));
    }

    function test_Forced_StillChecksReceiver() public {
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(IERC7943NonFungible.ERC7943CannotReceive.selector, carol));
        token.forcedTransfer(alice, carol, ID);
    }

    function testFuzz_Parity_Transfer(bool fromSend, bool toReceive, bool frozen) public {
        vm.startPrank(admin);
        token.changeSendWhitelist(alice, fromSend);
        token.changeReceiveWhitelist(bob, toReceive);
        token.setFrozenTokens(alice, ID, frozen);
        vm.stopPrank();

        bool predicted = token.canTransfer(alice, bob, ID);
        vm.prank(alice);
        (bool ok, ) = address(token).call(abi.encodeCall(token.transferFrom, (alice, bob, ID)));
        assertEq(ok, predicted);
    }

    function testFuzz_Parity_Mint(bool toReceive, uint256 id) public {
        vm.prank(admin);
        token.changeReceiveWhitelist(bob, toReceive);

        bool predicted = token.canTransfer(address(0), bob, id);
        vm.prank(admin);
        (bool ok, ) = address(token).call(abi.encodeCall(token.safeMint, (bob, id)));
        assertEq(ok, predicted);
    }
}
