# Contributing

Thanks for helping out. This repository is the standalone reference implementation of [ERC-7943](https://eips.ethereum.org/EIPS/eip-7943). Contributions of any size are welcome.

## What helps most

- **Bug reports**, especially anything where a contract does something the spec forbids. Please include a failing Foundry test if you can.
- **Conformance cases**: if you maintain another ERC-7943 implementation and found a case where it and this one disagree, that case belongs in the tests.
- **Extensions** under `contracts/modules/`, kept small and optional.
- **Docs** fixes.

For changes to the standard itself (the interface, MUST/SHOULD wording), please open a discussion in the [Ethereum Magicians thread](https://ethereum-magicians.org/t/erc-7943-universal-rwa-interface-urwa/23972) first. The interface here must keep matching Final ERC-7943; `test/ERC7943InterfaceIds.t.sol` pins it.

## Workflow

1. Fork the repository and create a branch.
2. Set up and run the tests:
   ```bash
   git submodule update --init --recursive
   forge build
   forge test
   ```
3. Add or update tests for your change. Bug fixes should come with a test that fails without the fix.
4. Keep PRs focused. Separate commits for separate concerns make review faster.
5. Open the PR describing what changed and why, and link the issue if there is one.

## Notes

- Solidity `^0.8.29`, compiled with the settings in `foundry.toml`.
- Follow the existing NatSpec style: `@inheritdoc` for interface functions, `@dev` for implementation choices.
- `canTransfer`, `canSend` and `canReceive` must never revert. Return `false` instead.
- The code is unaudited and meant as a reference. Don't add anything that suggests otherwise.

By contributing, you agree that your contributions are licensed under the MIT License.
