// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test, console} from "forge-std/Test.sol";
import {uRWA20} from "../contracts/uRWA20.sol";
import {IERC7943} from "../contracts/interfaces/IERC7943.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {AccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {IAccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/IAccessControlEnumerable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

contract uRWA20Test is Test {
    uRWA20 public token;

    // Roles
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    bytes32 public constant ENFORCER_ROLE = keccak256("ENFORCER_ROLE");
    bytes32 public constant WHITELIST_ROLE = keccak256("WHITELIST_ROLE");
    bytes32 public constant ADMIN_ROLE = 0x00;

    // Users
    address public admin = address(1);
    address public user1 = address(2);
    address public user2 = address(3);
    address public minter = address(4);
    address public burner = address(5);
    address public enforcer = address(6);
    address public whitelister = address(7);
    address public nonWhitelistedUser = address(8);
    address public otherUser = address(9);

    // Amounts
    uint256 public constant INITIAL_MINT_AMOUNT = 1000 * 1e18;
    uint256 public constant TRANSFER_AMOUNT = 100 * 1e18;
    uint256 public constant APPROVE_AMOUNT = 50 * 1e18;
    uint256 public constant BURN_AMOUNT = 10 * 1e18;
    uint256 public constant FORCE_TRANSFER_AMOUNT = 20 * 1e18;
    uint256 public constant FREEZE_AMOUNT = 30 * 1e18;

    function setUp() public {
        vm.startPrank(admin);
        token = new uRWA20("uRWA Token", "uTKN", admin);

        // Grant roles
        token.grantRole(MINTER_ROLE, minter);
        token.grantRole(BURNER_ROLE, burner);
        token.grantRole(ENFORCER_ROLE, enforcer);
        token.grantRole(WHITELIST_ROLE, whitelister);

        // Whitelist initial users
        token.changeWhitelist(admin, true);
        token.changeWhitelist(user1, true);
        token.changeWhitelist(user2, true);
        token.changeWhitelist(minter, true);
        token.changeWhitelist(burner, true);
        token.changeWhitelist(enforcer, true);
        token.changeWhitelist(whitelister, true);
        vm.stopPrank();

        // Mint initial tokens for tests
        vm.prank(minter);
        token.mint(user1, INITIAL_MINT_AMOUNT);
    }

    // --- Constructor Tests ---

    function test_Constructor_SetsNameAndSymbol() public view {
        assertEq(token.name(), "uRWA Token");
        assertEq(token.symbol(), "uTKN");
        assertEq(token.decimals(), 18);
    }

    function test_Constructor_GrantsInitialRoles() public view {
        assertTrue(token.hasRole(ADMIN_ROLE, admin));
        assertTrue(token.hasRole(MINTER_ROLE, admin));
        assertTrue(token.hasRole(BURNER_ROLE, admin));
        assertTrue(token.hasRole(ENFORCER_ROLE, admin));
        assertTrue(token.hasRole(WHITELIST_ROLE, admin));
    }

    function test_Revert_Constructor_ZeroAdminAddress() public {
        vm.expectRevert(uRWA20.NotZeroAddress.selector);
        new uRWA20("Fail", "FAIL", address(0));
    }

    // --- Whitelist Tests ---

    function test_Whitelist_ChangeStatus() public {
        assertFalse(token.isUserAllowed(otherUser));
        vm.prank(whitelister);
        vm.expectEmit(true, false, false, true);
        emit uRWA20.Whitelisted(otherUser, true);
        token.changeWhitelist(otherUser, true);
        assertTrue(token.isUserAllowed(otherUser));

        vm.prank(whitelister);
        vm.expectEmit(true, false, false, true);
        emit uRWA20.Whitelisted(otherUser, false);
        token.changeWhitelist(otherUser, false);
        assertFalse(token.isUserAllowed(otherUser));
    }

    function test_Revert_Whitelist_ChangeStatus_NotWhitelister() public {
        vm.prank(otherUser); // Not a whitelister
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, otherUser, WHITELIST_ROLE));
        token.changeWhitelist(nonWhitelistedUser, true);
    }

    function test_Revert_Whitelist_ChangeStatus_ZeroAddress() public {
        vm.prank(whitelister);
        vm.expectRevert(uRWA20.NotZeroAddress.selector);
        token.changeWhitelist(address(0), true);
    }

    function test_Whitelist_IsUserAllowed() public view {
        assertTrue(token.isUserAllowed(user1));
        assertFalse(token.isUserAllowed(nonWhitelistedUser));
    }

    // --- Minting Tests ---

    function test_Mint_Success() public {
        uint256 mintAmount = 500 * 1e18;
        vm.prank(minter);
        vm.expectEmit(true, true, true, true);
        emit IERC20.Transfer(address(0), user2, mintAmount);
        token.mint(user2, mintAmount);
        assertEq(token.balanceOf(user2), mintAmount);
        assertEq(token.totalSupply(), INITIAL_MINT_AMOUNT + mintAmount);
    }

    function test_Revert_Mint_NotMinter() public {
        vm.prank(user1); // Not a minter
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user1, MINTER_ROLE));
        token.mint(user2, TRANSFER_AMOUNT);
    }

    function test_Revert_Mint_ToNonWhitelisted() public {
        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedUser.selector, nonWhitelistedUser));
        token.mint(nonWhitelistedUser, TRANSFER_AMOUNT);
    }

    function test_Revert_Mint_ToZeroAddress() public {
        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InvalidReceiver.selector, address(0)));
        token.mint(address(0), TRANSFER_AMOUNT);
    }

    // --- Burning Tests ---

    function test_Burn_Success() public {
        // Grant burner role to user1 for this test
        vm.prank(admin);
        token.grantRole(BURNER_ROLE, user1);

        uint256 initialBalance = token.balanceOf(user1);
        uint256 initialSupply = token.totalSupply();
        vm.prank(user1); // User1 (owner and burner) burns tokens
        vm.expectEmit(true, true, true, true);
        emit IERC20.Transfer(user1, address(0), BURN_AMOUNT);
        token.burn(BURN_AMOUNT);
        assertEq(token.balanceOf(user1), initialBalance - BURN_AMOUNT);
        assertEq(token.totalSupply(), initialSupply - BURN_AMOUNT);
    }

    function test_Revert_Burn_NotBurnerRole() public {
        vm.prank(user1); // Owner does not have burner role by default
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user1, BURNER_ROLE));
        token.burn(BURN_AMOUNT);
    }

    function test_Revert_Burn_BurnerNotWhitelisted() public {
        // Mint some tokens to burner to attempt burn
        vm.prank(minter);
        token.mint(burner, BURN_AMOUNT * 2);

        // Remove burner from whitelist
        vm.prank(whitelister);
        token.changeWhitelist(burner, false);

        vm.prank(burner); // Burner (not whitelisted) tries to burn
        token.burn(BURN_AMOUNT);
    }

    function test_Revert_Burn_InsufficientBalance() public {
        // Grant burner role to user1
        uint256 available = token.balanceOf(user1) - token.getFrozen(user1, 0);
        vm.prank(admin);
        token.grantRole(BURNER_ROLE, user1);

        vm.prank(user1);
        uint256 burnAmount = available + 1; // More than available balance
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943InsufficientUnfrozenBalance.selector, user1, 0, burnAmount, available));
        token.burn(burnAmount);
    }

    // --- Transfer Tests ---

    function test_Transfer_Success_WhitelistedToWhitelisted() public {
        uint256 user1InitialBalance = token.balanceOf(user1);
        uint256 user2InitialBalance = token.balanceOf(user2);
        vm.prank(user1); // Owner
        vm.expectEmit(true, true, true, true);
        emit IERC20.Transfer(user1, user2, TRANSFER_AMOUNT);
        assertTrue(token.transfer(user2, TRANSFER_AMOUNT));
        assertEq(token.balanceOf(user1), user1InitialBalance - TRANSFER_AMOUNT);
        assertEq(token.balanceOf(user2), user2InitialBalance + TRANSFER_AMOUNT);
    }

    function test_Revert_Transfer_FromNotWhitelisted() public {
        // Remove user1 from whitelist
        vm.prank(whitelister);
        token.changeWhitelist(user1, false);

        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedTransfer.selector, user1, user2, 0, TRANSFER_AMOUNT));
        token.transfer(user2, TRANSFER_AMOUNT);
    }

    function test_Revert_Transfer_ToNotWhitelisted() public {
        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedTransfer.selector, user1, nonWhitelistedUser, 0, TRANSFER_AMOUNT));
        token.transfer(nonWhitelistedUser, TRANSFER_AMOUNT);
    }

    function test_Revert_Transfer_NotAllowedTransfer() public {
        uint256 transferAmount = INITIAL_MINT_AMOUNT + 1;
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedTransfer.selector, user1, user2, 0, transferAmount));
        vm.prank(user1);
        token.transfer(user2, transferAmount);
    }

    function test_Revert_Transfer_ToZeroAddress() public {
        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InvalidReceiver.selector, address(0)));
        token.transfer(address(0), TRANSFER_AMOUNT);
    }

    // --- Approve and TransferFrom Tests ---

    function test_Approve_Success() public {
        vm.prank(user1);
        vm.expectEmit(true, true, true, true);
        emit IERC20.Approval(user1, user2, APPROVE_AMOUNT);
        assertTrue(token.approve(user2, APPROVE_AMOUNT));
        assertEq(token.allowance(user1, user2), APPROVE_AMOUNT);
    }

    function test_TransferFrom_Success() public {
        // user1 approves user2
        vm.prank(user1);
        token.approve(user2, APPROVE_AMOUNT);

        // user2 transfers from user1 to otherUser (whitelisted)
        vm.prank(admin); // Whitelist otherUser
        token.changeWhitelist(otherUser, true);

        uint256 user1InitialBalance = token.balanceOf(user1);
        uint256 otherUserInitialBalance = token.balanceOf(otherUser);
        uint256 initialAllowance = token.allowance(user1, user2);

        vm.prank(user2);
        vm.expectEmit(true, true, true, true); // Transfer event
        emit IERC20.Transfer(user1, otherUser, APPROVE_AMOUNT);

        assertTrue(token.transferFrom(user1, otherUser, APPROVE_AMOUNT));
        assertEq(token.balanceOf(user1), user1InitialBalance - APPROVE_AMOUNT);
        assertEq(token.balanceOf(otherUser), otherUserInitialBalance + APPROVE_AMOUNT);
        assertEq(token.allowance(user1, user2), initialAllowance - APPROVE_AMOUNT);
    }

    function test_Revert_TransferFrom_FromNotWhitelisted() public {
        vm.prank(user1);
        token.approve(user2, APPROVE_AMOUNT);

        // Remove user1 from whitelist
        vm.prank(whitelister);
        token.changeWhitelist(user1, false);

        vm.prank(user2);
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedTransfer.selector, user1, user2, 0, APPROVE_AMOUNT));
        token.transferFrom(user1, user2, APPROVE_AMOUNT);
    }

    function test_Revert_TransferFrom_ToNotWhitelisted() public {
        vm.prank(user1);
        token.approve(user2, APPROVE_AMOUNT);

        vm.prank(user2);
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedTransfer.selector, user1, nonWhitelistedUser, 0, APPROVE_AMOUNT));
        token.transferFrom(user1, nonWhitelistedUser, APPROVE_AMOUNT);
    }

     function test_Revert_TransferFrom_SpenderNotWhitelisted() public {
        vm.prank(user1);
        token.approve(nonWhitelistedUser, APPROVE_AMOUNT);
        vm.prank(admin);
        token.changeWhitelist(otherUser, true);

        vm.prank(nonWhitelistedUser);
        assertTrue(token.transferFrom(user1, otherUser, APPROVE_AMOUNT));
        assertEq(token.balanceOf(user1), INITIAL_MINT_AMOUNT - APPROVE_AMOUNT);
        assertEq(token.balanceOf(otherUser), APPROVE_AMOUNT);

        vm.prank(user1);
        token.approve(nonWhitelistedUser, APPROVE_AMOUNT);
        vm.prank(nonWhitelistedUser);
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedTransfer.selector, user1, nonWhitelistedUser, 0, APPROVE_AMOUNT));
        token.transferFrom(user1, nonWhitelistedUser, APPROVE_AMOUNT);
    }

    function test_Revert_TransferFrom_InsufficientAllowance() public {
        vm.prank(user1);
        token.approve(user2, APPROVE_AMOUNT - 1); // Approve less than needed

        vm.prank(user2);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InsufficientAllowance.selector, user2, APPROVE_AMOUNT - 1, APPROVE_AMOUNT));
        token.transferFrom(user1, otherUser, APPROVE_AMOUNT);
    }

    function test_Revert_TransferFrom_NotAllowedTransfer() public {
        uint256 transferAmount = INITIAL_MINT_AMOUNT + 1;
        vm.prank(user1);
        token.approve(user2, transferAmount); // Approve more than balance

        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedTransfer.selector, user1, otherUser, 0, transferAmount ));
        vm.prank(user2);
        token.transferFrom(user1, otherUser, transferAmount);
    }

    function test_Revert_TransferFrom_ToZeroAddress() public { 
        vm.prank(user1);
        token.approve(user2, APPROVE_AMOUNT);

        vm.prank(user2);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InvalidReceiver.selector, address(0)));
        token.transferFrom(user1, address(0), APPROVE_AMOUNT);
    }


    // --- ForceTransfer Tests ---

    function test_ForceTransfer_Success_WhitelistedToWhitelisted() public {
        uint256 user1InitialBalance = token.balanceOf(user1);
        uint256 user2InitialBalance = token.balanceOf(user2);

        vm.prank(enforcer);
        vm.expectEmit(true, true, true, true); // Transfer event from super._update
        emit IERC20.Transfer(user1, user2, FORCE_TRANSFER_AMOUNT);
        vm.expectEmit(true, true, true, true); // ForcedTransfer event
        emit IERC7943.ForcedTransfer(user1, user2, 0, FORCE_TRANSFER_AMOUNT);

        token.forceTransfer(user1, user2, 0, FORCE_TRANSFER_AMOUNT);
        assertEq(token.balanceOf(user1), user1InitialBalance - FORCE_TRANSFER_AMOUNT);
        assertEq(token.balanceOf(user2), user2InitialBalance + FORCE_TRANSFER_AMOUNT);
    }

    function test_ForceTransfer_Success_FromNonWhitelistedToWhitelisted() public {
        // Remove user1 from whitelist
        vm.prank(whitelister);
        token.changeWhitelist(user1, false);
        assertFalse(token.isUserAllowed(user1));

        uint256 user1InitialBalance = token.balanceOf(user1);
        uint256 user2InitialBalance = token.balanceOf(user2);

        vm.prank(enforcer);
        vm.expectEmit(true, true, true, true); // Transfer event
        emit IERC20.Transfer(user1, user2, FORCE_TRANSFER_AMOUNT);
        vm.expectEmit(true, true, true, true); // ForcedTransfer event
        emit IERC7943.ForcedTransfer(user1, user2, 0, FORCE_TRANSFER_AMOUNT);

        token.forceTransfer(user1, user2, 0, FORCE_TRANSFER_AMOUNT); // Succeeds as 'from' whitelist status is not checked by forceTransfer
        assertEq(token.balanceOf(user1), user1InitialBalance - FORCE_TRANSFER_AMOUNT);
        assertEq(token.balanceOf(user2), user2InitialBalance + FORCE_TRANSFER_AMOUNT);
    }

    function test_Revert_ForceTransfer_ToNonWhitelisted() public {
        // force transfer to non-whitelisted user
        assertFalse(token.isUserAllowed(nonWhitelistedUser));
        vm.prank(enforcer);
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedUser.selector, nonWhitelistedUser));
        token.forceTransfer(user1, nonWhitelistedUser, 0, FORCE_TRANSFER_AMOUNT);
    }


    function test_Revert_ForceTransfer_NotEnforcer() public {
        vm.prank(user1); // Not enforcer
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user1, ENFORCER_ROLE));
        token.forceTransfer(user1, user2, 0, FORCE_TRANSFER_AMOUNT);
    }

    function test_Revert_ForceTransfer_InsufficientBalance() public {
        uint256 forceTransferAmount = INITIAL_MINT_AMOUNT + 1;
        uint256 available = token.balanceOf(user1) - token.getFrozen(user1, 0);

        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InsufficientBalance.selector, user1, available, forceTransferAmount));
        vm.prank(enforcer);
        token.forceTransfer(user1, user2, 0, forceTransferAmount);
    }

    function test_Revert_ForceTransfer_ToZeroAddress() public {
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedUser.selector, address(0)));
        vm.prank(enforcer);
        token.forceTransfer(user1, address(0), 0, FORCE_TRANSFER_AMOUNT);
    }

    // --- Freeze/Unfreeze/FrozenAmount Tests ---

    function test_Freeze_Success() public {
        vm.prank(enforcer);
        vm.expectEmit(true, true, true, true);
        emit IERC7943.Frozen(user1, 0, FREEZE_AMOUNT) ;
        token.setFrozen(user1, 0, FREEZE_AMOUNT);
        assertEq(token.getFrozen(user1, 0), FREEZE_AMOUNT);
    }

    function test_Revert_Freeze_NotEnforcer() public {
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user2, ENFORCER_ROLE));
        vm.prank(user2); // Not an enforcer
        token.setFrozen(user1, 0, FREEZE_AMOUNT);
    }

    function test_Revert_Freeze_InsufficientBalance() public {
        uint256 excessiveAmount = token.balanceOf(user1) + 1;

        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InsufficientBalance.selector, user1, token.balanceOf(user1), excessiveAmount));
        vm.prank(enforcer);
        token.setFrozen(user1, 0, excessiveAmount);
    }

    function test_Unfreeze_Success() public {

        vm.prank(enforcer);
        token.setFrozen(user1, 0, FREEZE_AMOUNT); // Freeze first
        assertEq(token.getFrozen(user1, 0), FREEZE_AMOUNT, "Tokens not frozen correctly");

        vm.expectEmit(true, true, true, true); 
        emit IERC7943.Frozen(user1, 0, 0);
        vm.prank(enforcer);
        token.setFrozen(user1, 0, 0);
        assertEq(token.getFrozen(user1, 0), 0);
    }

    function test_Revert_Unfreeze_NotEnforcer() public {
        vm.prank(user2); // Not an enforcer
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user2, ENFORCER_ROLE));
        token.setFrozen(user1, 0, 0);
    }
 
    function test_GetFrozen_ReturnsCorrectValue() public {
        assertEq(token.getFrozen(user1, 0), 0, "Initial frozen amount should be 0");

        vm.prank(enforcer);
        token.setFrozen(user1, 0, FREEZE_AMOUNT);
        assertEq(token.getFrozen(user1, 0), FREEZE_AMOUNT, "Frozen amount mismatch after freeze");

        uint256 partialUnfreezeAmount = FREEZE_AMOUNT / 2;
        vm.prank(enforcer);
        token.setFrozen(user1, 0, partialUnfreezeAmount);
        assertEq(token.getFrozen(user1, 0), partialUnfreezeAmount, "Frozen amount mismatch after partial unfreeze");
        vm.prank(enforcer);
        token.setFrozen(user1, 0, 0); // Unfreeze the rest
        assertEq(token.getFrozen(user1, 0), 0, "Frozen amount should be 0 after full unfreeze");
    }

    // --- Tests for operations with frozen tokens ---

    function test_Revert_Transfer_When_AllSenderBalanceFrozen() public {

        vm.prank(enforcer);
        token.setFrozen(user1, 0, INITIAL_MINT_AMOUNT); // Freeze all of user1's tokens

        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedTransfer.selector, user1, user2, 0, TRANSFER_AMOUNT));
        vm.prank(user1);
        token.transfer(user2, TRANSFER_AMOUNT);
    }

    function test_Revert_Transfer_When_TransferExceedsAvailableAfterFreeze() public {
        uint256 amountToLeave = TRANSFER_AMOUNT / 2;
        uint256 amountToFreeze = INITIAL_MINT_AMOUNT - amountToLeave;

        vm.prank(enforcer);
        token.setFrozen(user1, 0, amountToFreeze);
        uint256 available = token.balanceOf(user1) - token.getFrozen(user1, 0);

        assertEq(available, amountToLeave, "Available balance calculation error");


        vm.prank(user1);
        // Attempt to transfer more than available
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedTransfer.selector, user1, user2, 0, TRANSFER_AMOUNT));
        token.transfer(user2, TRANSFER_AMOUNT);
    }

    function test_Transfer_Success_When_TransferIsWithinAvailableAfterPartialFreeze() public {
        uint256 amountToFreeze = FREEZE_AMOUNT;
        uint256 availableAmountToTransfer = TRANSFER_AMOUNT / 2;

        // Ensure user1 has enough balance for freeze + transfer
        assertTrue(INITIAL_MINT_AMOUNT >= amountToFreeze + availableAmountToTransfer, "Initial amount too low for test");

        vm.prank(enforcer);
        token.setFrozen(user1, 0, amountToFreeze);

        uint256 user1InitialBalance = token.balanceOf(user1);
        uint256 user2InitialBalance = token.balanceOf(user2);

        vm.prank(user1);
        vm.expectEmit(true, true, true, true);
        emit IERC20.Transfer(user1, user2, availableAmountToTransfer);
        assertTrue(token.transfer(user2, availableAmountToTransfer));

        assertEq(token.balanceOf(user1), user1InitialBalance - availableAmountToTransfer);
        assertEq(token.balanceOf(user2), user2InitialBalance + availableAmountToTransfer);
        assertEq(token.getFrozen(user1, 0), amountToFreeze, "Frozen amount changed unexpectedly");
    }


    function test_Revert_Burn_When_TokensAreFrozenAndBurnExceedsAvailable() public {
        vm.prank(admin);
        token.grantRole(BURNER_ROLE, user1); // Ensure user1 can burn

        uint256 amountToFreeze = INITIAL_MINT_AMOUNT - (BURN_AMOUNT / 2); // Leave less than BURN_AMOUNT available

        vm.prank(enforcer);
        token.setFrozen(user1, 0, amountToFreeze);
        uint256 available = token.balanceOf(user1) - token.getFrozen(user1, 0);
        assertTrue(available < BURN_AMOUNT, "Available balance not less than burn amount");

        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943InsufficientUnfrozenBalance.selector, user1, 0, BURN_AMOUNT, available));
        vm.prank(user1);
        token.burn(BURN_AMOUNT);
    }

    function test_Revert_TransferFrom_When_FromBalanceFrozenAndTransferExceedsAvailable() public {
        vm.prank(user1);
        token.approve(user2, APPROVE_AMOUNT);

        vm.prank(admin); // Whitelist otherUser if not already
        token.changeWhitelist(otherUser, true);

        uint256 amountToFreeze = INITIAL_MINT_AMOUNT - (APPROVE_AMOUNT / 2); // Leave less than APPROVE_AMOUNT available for user1

        vm.prank(enforcer);
        token.setFrozen(user1, 0, amountToFreeze);
        uint256 available = token.balanceOf(user1) - token.getFrozen(user1, 0);

        assertTrue(available < APPROVE_AMOUNT, "Available balance for user1 not less than approve amount");

        vm.prank(user2); // Spender
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedTransfer.selector, user1, otherUser, 0, APPROVE_AMOUNT));
        token.transferFrom(user1, otherUser, APPROVE_AMOUNT);
    }

    // --- Interface Support Tests ---

    function test_Interface_SupportsIERC7943() public view {
        assertTrue(token.supportsInterface(type(IERC7943).interfaceId));
    }

    function test_Interface_SupportsIERC20() public view {
        assertTrue(token.supportsInterface(type(IERC20).interfaceId));
    }

     function test_Interface_SupportsIERC165() public view {
        assertTrue(token.supportsInterface(type(IERC165).interfaceId));
    }

    function test_Interface_SupportsAccessControl() public view {
        assertTrue(token.supportsInterface(type(IAccessControlEnumerable).interfaceId));
    }

    function test_Interface_DoesNotSupportRandom() public view {
        assertFalse(token.supportsInterface(bytes4(0xdeadbeef)));
    }

     // --- Access Control Tests ---

    function test_AccessControl_GrantRevokeRole() public {
        assertFalse(token.hasRole(MINTER_ROLE, user1));
        vm.prank(admin);
        token.grantRole(MINTER_ROLE, user1);
        assertTrue(token.hasRole(MINTER_ROLE, user1));
        vm.prank(admin);
        token.revokeRole(MINTER_ROLE, user1);
        assertFalse(token.hasRole(MINTER_ROLE, user1));
    }

    function test_Revert_AccessControl_GrantRole_NotAdmin() public {
        vm.prank(user1); // Not admin
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user1, ADMIN_ROLE));
        token.grantRole(MINTER_ROLE, user2);
    }

    // --- isTransferAllowed Tests ---

    function test_IsTransferAllowed_Success() public view {
        assertTrue(token.isTransferAllowed(user1, user2, 0, TRANSFER_AMOUNT));
    }

    function test_IsTransferAllowed_Fail_InsufficientBalance() public view {
        assertFalse(token.isTransferAllowed(user1, user2, 0, INITIAL_MINT_AMOUNT + 1));
    }

    function test_IsTransferAllowed_Fail_FromNotWhitelisted() public {
        vm.prank(whitelister);
        token.changeWhitelist(user1, false); // Remove sender from whitelist
        assertFalse(token.isTransferAllowed(user1, user2, 0, TRANSFER_AMOUNT));
    }

    function test_IsTransferAllowed_Fail_ToNotWhitelisted() public view {
        assertFalse(token.isTransferAllowed(user1, nonWhitelistedUser, 0, TRANSFER_AMOUNT));
    }

    function test_IsTransferAllowed_Fail_ZeroAddress() public view {
        assertFalse(token.isTransferAllowed(user1, address(0), 0, TRANSFER_AMOUNT));
    }

    // --- isUserAllowed Tests ---

    function test_IsUserAllowed_Success() public view {
        assertTrue(token.isUserAllowed(user1));
    }

    function test_IsUserAllowed_Fail_NotWhitelisted() public view {
        assertFalse(token.isUserAllowed(nonWhitelistedUser));
    }
}