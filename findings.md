Denial of Service (DoS) Attack

### [M-#] Looping through players array to check for duplicates in `PuppyRaffle::enterRaffle` is a potential denial of service (DoS) attack. It leads to incrementing gas costs for future entrants.

**Description:** The `PuppyRaffle::enterRaffle` function loops through the `players` array to check for duplicates. However, teh longer the array gets, the more checks have to be made. This results in significantly higher gas costs for those who enter the raffle later. Every additional address is an additional check that the loop will have to make. 

```js
// @audit DoS Attack
@>   for (uint256 i = 0; i < players.length - 1; i++) {
        for (uint256 j = i + 1; j < players.length; j++) {
            require(
                players[i] != players[j],
                "PuppyRaffle: Duplicate player"
            );
        }
    }
```

**Impact:** Gas cost for raffle entrants will greatly increase as more players enter the raffle, discouraging later entrants and causing a rush at start of a raffle. 

An attacker could make the `PuppyRaffle::enterRaffle` arry so big that on one else could enter, thus guaranteeing themselves the winner. 

**Proof of Concept:** If we have 2 sets of 100 players enter, the gas costs will be:
- 1st set:  6,503,275 gas
- 2nd set: 18,995,515 gas

The result shows the it is over 3x more expensive for entrants in the second round

<details>
<summary>PoC</summary>
Place this test into `PuppyRaffleTest.t.sol`

```js
function test_denialOfService() public {    
    vm.txGasPrice(1);

    // Let's enter 100 players
    uint256 playersNum = 100;
    address[] memory players = new address[](playersNum);
    for (uint256 i = 0; i < playersNum; i++) {
        players[i] = address(i);
    }
    // check how much gas it takes to enter round of 100 players
    uint256 gasBefore = gasleft();
    puppyRaffle.enterRaffle{value: entranceFee * players.length}(players);
    uint256 gasAfter = gasleft();
    uint256 gasUsedFirst = (gasBefore - gasAfter) * tx.gasprice;
    console.log("Gas used for 1000 players: ", gasUsedFirst);

    // a second round
    address[] memory playersTwo = new address[](playersNum);
    for (uint256 i = 0; i < playersNum; i++) {
        playersTwo[i] = address(i + playersNum);
    }
    // check how much gas it takes to enter round of 100 players
    uint256 gasBeforeSecond = gasleft();
    puppyRaffle.enterRaffle{value: entranceFee * players.length}(
        playersTwo
    );
    uint256 gasAfterSecond = gasleft();
    uint256 gasUsedSecond = (gasBeforeSecond - gasAfterSecond) *
        tx.gasprice;
    console.log("Gas used for second round 1000 players: ", gasUsedSecond);

    assert(gasUsedFirst < gasUsedSecond);
}
```
 
**OUTPUT:**
Ran 1 test for test/PuppyRaffleTest.t.sol:PuppyRaffleTest
[PASS] test_denialOfService() (gas: 25536100)

    Logs:
    Gas used for 1st 100 players:  6503275.
    Gas used for 2nd 100 players:  18995515.

</details>

#

**Recommended Mitigation:** Here are a few recomendations.
1. Consider allowing duplicates. - Since users can make new wallet addresses, the duplicate check doesn't fully prevent players from entering multiple times. It only blocks same wallet addresses.
2. Consider using a mapping to check for duplicates. This would allow constant time lookup of whether a user has already entered.

```diff
+    mapping(address => uint256) public addressToRaffleId;
+    uint256 public raffleId = 0;
    .
    .
    .
    function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
        for (uint256 i = 0; i < newPlayers.length; i++) {
            players.push(newPlayers[i]);
+            addressToRaffleId[newPlayers[i]] = raffleId;            
        }

-        // Check for duplicates
+       // Check for duplicates only from the new players
+       for (uint256 i = 0; i < newPlayers.length; i++) {
+          require(addressToRaffleId[newPlayers[i]] != raffleId, "PuppyRaffle: Duplicate player");
+       }    
-        for (uint256 i = 0; i < players.length; i++) {
-            for (uint256 j = i + 1; j < players.length; j++) {
-                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
-            }
-        }
        emit RaffleEnter(newPlayers);
    }
.
.
.
    function selectWinner() external {
+       raffleId = raffleId + 1;
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
```

**Alternatively**, you could use [OpenZeppelin's `EnumerableSet` library.](https://docs.openzeppelin.com/contracts/4.x/api/utils#EnumerableSet)