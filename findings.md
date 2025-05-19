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