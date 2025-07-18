const deploymentHelper = require("../utils/testDeploymentHelpers.js");
const testHelpers = require("../utils/testHelpers.js");

const th = testHelpers.TestHelper;

const dec = th.dec;
const toBN = th.toBN;
const timeValues = testHelpers.TimeValues;

const ZERO_ADDRESS = th.ZERO_ADDRESS;
const assertRevert = th.assertRevert;

/* NOTE: Some of the borrowing tests do not test for specific debt token fee values. They only test that the
 * fees are non-zero when they should occur, and that they decay over time.
 *
 * Specific debt token fee values will depend on the final fee schedule used, and the final choice for
 *  the parameter MINUTE_DECAY_FACTOR in the TroveManager, which is still TBD based on economic
 * modelling.
 *
 */

contract("BorrowerOperations", async () => {
  let owner, alice, bob, carol, dennis, whale, A, B, C, D, E, F, G, H;
  let lpRewardsAddress, multisig;

  let priceFeed;
  let debtToken;
  let sortedTroves;
  let troveManager;
  let activePool;
  let defaultPool;
  let borrowerOperations;
  let protocolTokenStaking;
  let protocolToken;

  let contracts;

  const getOpenTroveDebtTokenAmount = async (totalDebt) =>
    th.getOpenTroveDebtTokenAmount(contracts, totalDebt);
  const getNetBorrowingAmount = async (debtWithFee) =>
    th.getNetBorrowingAmount(contracts, debtWithFee);
  const getActualDebtFromComposite = async (compositeDebt) =>
    th.getActualDebtFromComposite(compositeDebt, contracts);
  const openTrove = async (params) => th.openTrove(contracts, params);
  const getTroveEntireColl = async (trove) => th.getTroveEntireColl(contracts, trove);
  const getTroveEntireDebt = async (trove) => th.getTroveEntireDebt(contracts, trove);
  const getTroveStake = async (trove) => th.getTroveStake(contracts, trove);

  let GAS_COMPENSATION;
  let MIN_NET_DEBT;
  let BORROWING_FEE_FLOOR;

  before(async () => {
    const signers = await ethers.getSigners();

    [owner, alice, bob, carol, dennis, whale, A, B, C, D, E, F, G, H] = signers;
    [lpRewardsAddress, multisig] = signers.slice(998, 1000);
  });

  const testCorpus = ({ withProxy = false }) => {
    beforeEach(async () => {
      await hre.network.provider.send("hardhat_reset");

      const transactionCount = await owner.getTransactionCount();
      const cpTesterContracts = await deploymentHelper.computeContractAddresses(
        owner.address,
        transactionCount,
        7,
      );
      const cpContracts = await deploymentHelper.computeCoreProtocolContracts(
        owner.address,
        transactionCount + 7,
      );

      // Overwrite contracts with computed tester addresses
      cpContracts.troveManager = cpTesterContracts[2];
      cpContracts.borrowerOperations = cpTesterContracts[4];
      cpContracts.debtToken = cpTesterContracts[6];

      const troveManagerTester = await deploymentHelper.deployTroveManagerTester(
        th.GAS_COMPENSATION,
        th.MIN_NET_DEBT,
        cpContracts,
      );
      const borrowerOperationsTester = await deploymentHelper.deployBorrowerOperationsTester(
        th.GAS_COMPENSATION,
        th.MIN_NET_DEBT,
        cpContracts,
      );
      const debtTokenTester = await deploymentHelper.deployDebtTokenTester(cpContracts);

      contracts = await deploymentHelper.deployProtocolCore(
        th.GAS_COMPENSATION,
        th.MIN_NET_DEBT,
        cpContracts,
      );

      contracts.troveManager = troveManagerTester;
      contracts.borrowerOperations = borrowerOperationsTester;
      contracts.debtToken = debtTokenTester;

      const protocolTokenContracts = await deploymentHelper.deployProtocolTokenTesterContracts(
        owner.address,
        cpContracts,
      );

      const allocation = [
        { address: multisig.address, amount: toBN(dec(67000000, 18)) },
        { address: lpRewardsAddress.address, amount: toBN(dec(1000000, 18)) },
        {
          address: protocolTokenContracts.communityIssuance.address,
          amount: toBN(dec(32000000, 18)),
        },
      ];
      await deploymentHelper.allocateProtocolToken(protocolTokenContracts, allocation);

      if (withProxy) {
        const users = [alice, bob, carol, dennis, whale, A, B, C, D, E];
        await deploymentHelper.deployProxyScripts(contracts, protocolTokenContracts, owner, users);
      }

      priceFeed = contracts.priceFeedTestnet;
      debtToken = contracts.debtToken;
      sortedTroves = contracts.sortedTroves;
      troveManager = contracts.troveManager;
      activePool = contracts.activePool;
      defaultPool = contracts.defaultPool;
      borrowerOperations = contracts.borrowerOperations;
      hintHelpers = contracts.hintHelpers;

      protocolTokenStaking = protocolTokenContracts.protocolTokenStaking;
      protocolToken = protocolTokenContracts.protocolToken;
      communityIssuance = protocolTokenContracts.communityIssuance;
      lockupContractFactory = protocolTokenContracts.lockupContractFactory;

      GAS_COMPENSATION = await borrowerOperations.GAS_COMPENSATION();
      MIN_NET_DEBT = await borrowerOperations.MIN_NET_DEBT();
      BORROWING_FEE_FLOOR = await borrowerOperations.BORROWING_FEE_FLOOR();
    });

    it("addColl(): reverts when top-up would leave trove with ICR < MCR", async () => {
      // alice creates a Trove and adds first collateral
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: alice } });
      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: bob } });

      // Price drops
      await priceFeed.setPrice(dec(100, 18));
      const price = await priceFeed.getPrice();

      assert.isFalse(await troveManager.checkRecoveryMode(price));
      assert.isTrue(
        (await troveManager.getCurrentICR(alice.address, price)).lt(toBN(dec(110, 16))),
      );

      const collTopUp = 1; // 1 wei top up

      await assertRevert(
        borrowerOperations
          .connect(alice)
          .addColl(alice.address, alice.address, { value: collTopUp }),
        "BorrowerOps: An operation that would result in ICR < MCR is not permitted",
      );
    });

    it("addColl(): Increases the activePool FIL and raw ether balance by correct amount", async () => {
      const { collateral: aliceColl } = await openTrove({
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });

      const activePool_FIL_Before = await activePool.getFIL();
      const activePool_RawEther_Before = toBN(await web3.eth.getBalance(activePool.address));

      assert.isTrue(activePool_FIL_Before.eq(aliceColl));
      assert.isTrue(activePool_RawEther_Before.eq(aliceColl));

      await borrowerOperations
        .connect(alice)
        .addColl(alice.address, alice.address, { value: dec(1, "ether") });

      const activePool_FIL_After = await activePool.getFIL();
      const activePool_RawEther_After = toBN(await web3.eth.getBalance(activePool.address));
      assert.isTrue(activePool_FIL_After.eq(aliceColl.add(toBN(dec(1, "ether")))));
      assert.isTrue(activePool_RawEther_After.eq(aliceColl.add(toBN(dec(1, "ether")))));
    });

    it("addColl(), active Trove: adds the correct collateral amount to the Trove", async () => {
      // alice creates a Trove and adds first collateral
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: alice } });

      const alice_Trove_Before = await troveManager.Troves(alice.address);
      const coll_before = alice_Trove_Before[1];
      const status_Before = alice_Trove_Before[3];

      // check status before
      assert.equal(status_Before, 1);

      // Alice adds second collateral
      await borrowerOperations
        .connect(alice)
        .addColl(alice.address, alice.address, { value: dec(1, "ether") });

      const alice_Trove_After = await troveManager.Troves(alice.address);
      const coll_After = alice_Trove_After[1];
      const status_After = alice_Trove_After[3];

      // check coll increases by correct amount,and status remains active
      assert.isTrue(coll_After.eq(coll_before.add(toBN(dec(1, "ether")))));
      assert.equal(status_After, 1);
    });

    it("addColl(), active Trove: Trove is in sortedList before and after", async () => {
      // alice creates a Trove and adds first collateral
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: alice } });

      // check Alice is in list before
      const aliceTroveInList_Before = await sortedTroves.contains(alice.address);
      const listIsEmpty_Before = await sortedTroves.isEmpty();
      assert.equal(aliceTroveInList_Before, true);
      assert.equal(listIsEmpty_Before, false);

      await borrowerOperations
        .connect(alice)
        .addColl(alice.address, alice.address, { value: dec(1, "ether") });

      // check Alice is still in list after
      const aliceTroveInList_After = await sortedTroves.contains(alice.address);
      const listIsEmpty_After = await sortedTroves.isEmpty();
      assert.equal(aliceTroveInList_After, true);
      assert.equal(listIsEmpty_After, false);
    });

    it("addColl(), active Trove: updates the stake and updates the total stakes", async () => {
      //  Alice creates initial Trove with 1 ether
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: alice } });

      const alice_Trove_Before = await troveManager.Troves(alice.address);
      const alice_Stake_Before = alice_Trove_Before[2];
      const totalStakes_Before = await troveManager.totalStakes();

      assert.isTrue(totalStakes_Before.eq(alice_Stake_Before));

      // Alice tops up Trove collateral with 2 ether
      await borrowerOperations
        .connect(alice)
        .addColl(alice.address, alice.address, { value: dec(2, "ether") });

      // Check stake and total stakes get updated
      const alice_Trove_After = await troveManager.Troves(alice.address);
      const alice_Stake_After = alice_Trove_After[2];
      const totalStakes_After = await troveManager.totalStakes();

      assert.isTrue(alice_Stake_After.eq(alice_Stake_Before.add(toBN(dec(2, "ether")))));
      assert.isTrue(totalStakes_After.eq(totalStakes_Before.add(toBN(dec(2, "ether")))));
    });

    it("addColl(), active Trove: applies pending rewards and updates user's L_FIL, L_Debt snapshots", async () => {
      // --- SETUP ---

      const { collateral: aliceCollBefore, totalDebt: aliceDebtBefore } = await openTrove({
        extraDebtTokenAmount: toBN(dec(15000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });
      const { collateral: bobCollBefore, totalDebt: bobDebtBefore } = await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: bob },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: carol },
      });

      // --- TEST ---

      // price drops to 1FIL:100DebtToken, reducing Carol's ICR below MCR
      await priceFeed.setPrice("100000000000000000000");

      // Liquidate Carol's Trove,
      const tx = await troveManager.connect(owner).liquidate(carol.address);

      assert.isFalse(await sortedTroves.contains(carol.address));

      const L_FIL = await troveManager.L_FIL();
      const L_Debt = await troveManager.L_Debt();

      // check Alice and Bob's reward snapshots are zero before they alter their Troves
      const alice_rewardSnapshot_Before = await troveManager.rewardSnapshots(alice.address);
      const alice_FILrewardSnapshot_Before = alice_rewardSnapshot_Before[0];
      const alice_DebtRewardSnapshot_Before = alice_rewardSnapshot_Before[1];

      const bob_rewardSnapshot_Before = await troveManager.rewardSnapshots(bob.address);
      const bob_FILrewardSnapshot_Before = bob_rewardSnapshot_Before[0];
      const bob_DebtRewardSnapshot_Before = bob_rewardSnapshot_Before[1];

      assert.equal(alice_FILrewardSnapshot_Before, 0);
      assert.equal(alice_DebtRewardSnapshot_Before, 0);
      assert.equal(bob_FILrewardSnapshot_Before, 0);
      assert.equal(bob_DebtRewardSnapshot_Before, 0);

      const alicePendingFILReward = await troveManager.getPendingFILReward(alice.address);
      const bobPendingFILReward = await troveManager.getPendingFILReward(bob.address);
      const alicePendingDebtReward = await troveManager.getPendingDebtReward(alice.address);
      const bobPendingDebtReward = await troveManager.getPendingDebtReward(bob.address);
      for (reward of [
        alicePendingFILReward,
        bobPendingFILReward,
        alicePendingDebtReward,
        bobPendingDebtReward,
      ]) {
        assert.isTrue(reward.gt(toBN("0")));
      }

      // Alice and Bob top up their Troves
      const aliceTopUp = toBN(dec(5, "ether"));
      const bobTopUp = toBN(dec(1, "ether"));

      await borrowerOperations
        .connect(alice)
        .addColl(alice.address, alice.address, { value: aliceTopUp });
      await borrowerOperations.connect(bob).addColl(bob.address, bob.address, { value: bobTopUp });

      // Check that both alice and Bob have had pending rewards applied in addition to their top-ups.
      const aliceNewColl = await getTroveEntireColl(alice.address);
      const aliceNewDebt = await getTroveEntireDebt(alice.address);
      const bobNewColl = await getTroveEntireColl(bob.address);
      const bobNewDebt = await getTroveEntireDebt(bob.address);

      assert.isTrue(aliceNewColl.eq(aliceCollBefore.add(alicePendingFILReward).add(aliceTopUp)));
      assert.isTrue(aliceNewDebt.eq(aliceDebtBefore.add(alicePendingDebtReward)));
      assert.isTrue(bobNewColl.eq(bobCollBefore.add(bobPendingFILReward).add(bobTopUp)));
      assert.isTrue(bobNewDebt.eq(bobDebtBefore.add(bobPendingDebtReward)));

      /* Check that both Alice and Bob's snapshots of the rewards-per-unit-staked metrics should be updated
       to the latest values of L_FIL and L_Debt */
      const alice_rewardSnapshot_After = await troveManager.rewardSnapshots(alice.address);
      const alice_FILrewardSnapshot_After = alice_rewardSnapshot_After[0];
      const alice_DebtRewardSnapshot_After = alice_rewardSnapshot_After[1];

      const bob_rewardSnapshot_After = await troveManager.rewardSnapshots(bob.address);
      const bob_FILrewardSnapshot_After = bob_rewardSnapshot_After[0];
      const bob_DebtRewardSnapshot_After = bob_rewardSnapshot_After[1];

      assert.isAtMost(th.getDifference(alice_FILrewardSnapshot_After, L_FIL), 100);
      assert.isAtMost(th.getDifference(alice_DebtRewardSnapshot_After, L_Debt), 100);
      assert.isAtMost(th.getDifference(bob_FILrewardSnapshot_After, L_FIL), 100);
      assert.isAtMost(th.getDifference(bob_DebtRewardSnapshot_After, L_Debt), 100);
    });

    it("addColl(), reverts if trove is non-existent or closed", async () => {
      // A, B open troves
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: alice } });
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: bob } });

      // Carol attempts to add collateral to her non-existent trove
      try {
        const txCarol = await borrowerOperations
          .connect(carol)
          .addColl(carol.address, carol.address, {
            value: dec(1, "ether"),
          });
        const receipt = await txCarol.wait();
        assert.equal(receipt.status, 0);
      } catch (error) {
        assert.include(error.message, "revert");
        assert.include(error.message, "Trove does not exist or is closed");
      }

      // Price drops
      await priceFeed.setPrice(dec(100, 18));

      // Bob gets liquidated
      await troveManager.liquidate(bob.address);

      assert.isFalse(await sortedTroves.contains(bob.address));

      // Bob attempts to add collateral to his closed trove
      try {
        const txBob = await borrowerOperations.connect(bob).addColl(bob.address, bob.address, {
          value: dec(1, "ether"),
        });
        const receipt = await txBob.wait();
        assert.equal(receipt.status, 0);
      } catch (error) {
        assert.include(error.message, "revert");
        assert.include(error.message, "Trove does not exist or is closed");
      }
    });

    it("addColl(): can add collateral in Recovery Mode", async () => {
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: alice } });
      const aliceCollBefore = await getTroveEntireColl(alice.address);
      assert.isFalse(await th.checkRecoveryMode(contracts));

      await priceFeed.setPrice("105000000000000000000");

      assert.isTrue(await th.checkRecoveryMode(contracts));

      const collTopUp = toBN(dec(1, "ether"));
      await borrowerOperations
        .connect(alice)
        .addColl(alice.address, alice.address, { value: collTopUp });

      // Check Alice's collateral
      const aliceCollAfter = (await troveManager.Troves(alice.address))[1];
      assert.isTrue(aliceCollAfter.eq(aliceCollBefore.add(collTopUp)));
    });

    // --- withdrawColl() ---

    it("withdrawColl(): reverts when withdrawal would leave trove with ICR < MCR", async () => {
      // alice creates a Trove and adds first collateral
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: alice } });
      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: bob } });

      // Price drops
      await priceFeed.setPrice(dec(100, 18));
      const price = await priceFeed.getPrice();

      assert.isFalse(await troveManager.checkRecoveryMode(price));
      assert.isTrue(
        (await troveManager.getCurrentICR(alice.address, price)).lt(toBN(dec(110, 16))),
      );

      const collWithdrawal = 1; // 1 wei withdrawal

      await assertRevert(
        borrowerOperations.connect(alice).withdrawColl(1, alice.address, alice.address),
        "BorrowerOps: An operation that would result in ICR < MCR is not permitted",
      );
    });

    // reverts when calling address does not have active trove
    it("withdrawColl(): reverts when calling address does not have active trove", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: bob },
      });

      // Bob successfully withdraws some coll
      const txBob = await borrowerOperations
        .connect(bob)
        .withdrawColl(dec(100, "finney"), bob.address, bob.address);
      const receipt = await txBob.wait();
      assert.equal(receipt.status, 1);

      // Carol with no active trove attempts to withdraw
      try {
        const txCarol = await borrowerOperations
          .connect(carol)
          .withdrawColl(dec(1, "ether"), carol.address, carol.address);
        assert.isFalse(txCarol.receipt.status);
      } catch (err) {
        assert.include(err.message, "revert");
      }
    });

    it("withdrawColl(): reverts when system is in Recovery Mode", async () => {
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: alice } });
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: bob } });

      assert.isFalse(await th.checkRecoveryMode(contracts));

      // Withdrawal possible when recoveryMode == false
      const txAlice = await borrowerOperations
        .connect(alice)
        .withdrawColl(1000, alice.address, alice.address);
      const receipt = await txAlice.wait();
      assert.equal(receipt.status, 1);

      await priceFeed.setPrice("105000000000000000000");

      assert.isTrue(await th.checkRecoveryMode(contracts));

      //Check withdrawal impossible when recoveryMode == true
      try {
        const txBob = await borrowerOperations
          .connect(bob)
          .withdrawColl(1000, bob.address, bob.address);
        const receipt = await txBob.wait();
        assert.equal(receipt.status, 0);
      } catch (err) {
        assert.include(err.message, "revert");
      }
    });

    it("withdrawColl(): reverts when requested FIL withdrawal is > the trove's collateral", async () => {
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: alice } });
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: bob } });
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: carol } });

      const carolColl = await getTroveEntireColl(carol.address);
      const bobColl = await getTroveEntireColl(bob.address);
      // Carol withdraws exactly all her collateral
      await assertRevert(
        borrowerOperations.connect(carol).withdrawColl(carolColl, carol.address, carol.address),
        "BorrowerOps: An operation that would result in ICR < MCR is not permitted",
      );

      // Bob attempts to withdraw 1 wei more than his collateral
      try {
        const txBob = await borrowerOperations
          .connect(bob)
          .withdrawColl(bobColl.add(toBN(1)), bob.address, bob.address);
        assert.isFalse(txBob.receipt.status);
      } catch (err) {
        assert.include(err.message, "revert");
      }
    });

    it("withdrawColl(): reverts when withdrawal would bring the user's ICR < MCR", async () => {
      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: whale } });

      await openTrove({ ICR: toBN(dec(11, 17)), extraParams: { from: bob } }); // 110% ICR

      // Bob attempts to withdraws 1 wei, Which would leave him with < 110% ICR.

      try {
        const txBob = await borrowerOperations
          .connect(bob)
          .withdrawColl(1, bob.address, bob.address);
        assert.isFalse(txBob.receipt.status);
      } catch (err) {
        assert.include(err.message, "revert");
      }
    });

    it("withdrawColl(): reverts if system is in Recovery Mode", async () => {
      // --- SETUP ---

      // A and B open troves at 150% ICR
      await openTrove({ ICR: toBN(dec(15, 17)), extraParams: { from: bob } });
      await openTrove({ ICR: toBN(dec(15, 17)), extraParams: { from: alice } });

      const TCR = (await th.getTCR(contracts)).toString();
      assert.equal(TCR, "1500000000000000000");

      // --- TEST ---

      // price drops to 1FIL:150DebtToken, reducing TCR below 150%
      await priceFeed.setPrice("150000000000000000000");

      //Alice tries to withdraw collateral during Recovery Mode
      try {
        const txData = await borrowerOperations
          .connect(alice)
          .withdrawColl("1", alice.address, alice.address);
        assert.isFalse(txData.receipt.status);
      } catch (err) {
        assert.include(err.message, "revert");
      }
    });

    it("withdrawColl(): doesn't allow a user to completely withdraw all collateral from their Trove (due to gas compensation)", async () => {
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: bob } });
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: alice } });

      const aliceColl = (await troveManager.getEntireDebtAndColl(alice.address))[1];

      // Check Trove is active
      const alice_Trove_Before = await troveManager.Troves(alice.address);
      const status_Before = alice_Trove_Before[3];
      assert.equal(status_Before, 1);
      assert.isTrue(await sortedTroves.contains(alice.address));

      // Alice attempts to withdraw all collateral
      await assertRevert(
        borrowerOperations.connect(alice).withdrawColl(aliceColl, alice.address, alice.address),
        "BorrowerOps: An operation that would result in ICR < MCR is not permitted",
      );
    });

    it("withdrawColl(): leaves the Trove active when the user withdraws less than all the collateral", async () => {
      // Open Trove
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: alice } });

      // Check Trove is active
      const alice_Trove_Before = await troveManager.Troves(alice.address);
      const status_Before = alice_Trove_Before[3];
      assert.equal(status_Before, 1);
      assert.isTrue(await sortedTroves.contains(alice.address));

      // Withdraw some collateral
      await borrowerOperations
        .connect(alice)
        .withdrawColl(dec(100, "finney"), alice.address, alice.address);

      // Check Trove is still active
      const alice_Trove_After = await troveManager.Troves(alice.address);
      const status_After = alice_Trove_After[3];
      assert.equal(status_After, 1);
      assert.isTrue(await sortedTroves.contains(alice.address));
    });

    it("withdrawColl(): reduces the Trove's collateral by the correct amount", async () => {
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: alice } });
      const aliceCollBefore = await getTroveEntireColl(alice.address);

      // Alice withdraws 1 ether
      await borrowerOperations
        .connect(alice)
        .withdrawColl(dec(1, "ether"), alice.address, alice.address);

      // Check 1 ether remaining
      const alice_Trove_After = await troveManager.Troves(alice.address);
      const aliceCollAfter = await getTroveEntireColl(alice.address);

      assert.isTrue(aliceCollAfter.eq(aliceCollBefore.sub(toBN(dec(1, "ether")))));
    });

    it("withdrawColl(): reduces ActivePool FIL and raw ether by correct amount", async () => {
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: alice } });
      const aliceCollBefore = await getTroveEntireColl(alice.address);

      // check before
      const activePool_FIL_before = await activePool.getFIL();
      const activePool_RawEther_before = toBN(await web3.eth.getBalance(activePool.address));

      await borrowerOperations
        .connect(alice)
        .withdrawColl(dec(1, "ether"), alice.address, alice.address);

      // check after
      const activePool_FIL_After = await activePool.getFIL();
      const activePool_RawEther_After = toBN(await web3.eth.getBalance(activePool.address));
      assert.isTrue(activePool_FIL_After.eq(activePool_FIL_before.sub(toBN(dec(1, "ether")))));
      assert.isTrue(
        activePool_RawEther_After.eq(activePool_RawEther_before.sub(toBN(dec(1, "ether")))),
      );
    });

    it("withdrawColl(): updates the stake and updates the total stakes", async () => {
      //  Alice creates initial Trove with 2 ether
      await openTrove({
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice, value: toBN(dec(5, "ether")) },
      });
      const aliceColl = await getTroveEntireColl(alice.address);
      assert.isTrue(aliceColl.gt(toBN("0")));

      const alice_Trove_Before = await troveManager.Troves(alice.address);
      const alice_Stake_Before = alice_Trove_Before[2];
      const totalStakes_Before = await troveManager.totalStakes();

      assert.isTrue(alice_Stake_Before.eq(aliceColl));
      assert.isTrue(totalStakes_Before.eq(aliceColl));

      // Alice withdraws 1 ether
      await borrowerOperations
        .connect(alice)
        .withdrawColl(dec(1, "ether"), alice.address, alice.address);

      // Check stake and total stakes get updated
      const alice_Trove_After = await troveManager.Troves(alice.address);
      const alice_Stake_After = alice_Trove_After[2];
      const totalStakes_After = await troveManager.totalStakes();

      assert.isTrue(alice_Stake_After.eq(alice_Stake_Before.sub(toBN(dec(1, "ether")))));
      assert.isTrue(totalStakes_After.eq(totalStakes_Before.sub(toBN(dec(1, "ether")))));
    });

    it("withdrawColl(): sends the correct amount of FIL to the user", async () => {
      await openTrove({
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice, value: dec(2, "ether") },
      });

      const alice_FILBalance_Before = toBN(toBN(await web3.eth.getBalance(alice.address)));
      await borrowerOperations
        .connect(alice)
        .withdrawColl(dec(1, "ether"), alice.address, alice.address, {
          gasPrice: 0,
        });

      const alice_FILBalance_After = toBN(toBN(await web3.eth.getBalance(alice.address)));
      const balanceDiff = alice_FILBalance_After.sub(alice_FILBalance_Before);

      assert.isTrue(balanceDiff.eq(toBN(dec(1, "ether"))));
    });

    it("withdrawColl(): applies pending rewards and updates user's L_FIL, L_Debt snapshots", async () => {
      // --- SETUP ---
      // Alice adds 15 ether, Bob adds 5 ether, Carol adds 1 ether
      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: whale } });
      await openTrove({
        ICR: toBN(dec(3, 18)),
        extraParams: { from: alice, value: toBN(dec(100, "ether")) },
      });
      await openTrove({
        ICR: toBN(dec(3, 18)),
        extraParams: { from: bob, value: toBN(dec(100, "ether")) },
      });
      await openTrove({
        ICR: toBN(dec(2, 18)),
        extraParams: { from: carol, value: toBN(dec(10, "ether")) },
      });

      const aliceCollBefore = await getTroveEntireColl(alice.address);
      const aliceDebtBefore = await getTroveEntireDebt(alice.address);
      const bobCollBefore = await getTroveEntireColl(bob.address);
      const bobDebtBefore = await getTroveEntireDebt(bob.address);

      // --- TEST ---

      // price drops to 1FIL:100DebtToken, reducing Carol's ICR below MCR
      await priceFeed.setPrice("100000000000000000000");

      // close Carol's Trove, liquidating her 1 ether and 180DebtToken.
      await troveManager.connect(owner).liquidate(carol.address);

      const L_FIL = await troveManager.L_FIL();
      const L_Debt = await troveManager.L_Debt();

      // check Alice and Bob's reward snapshots are zero before they alter their Troves
      const alice_rewardSnapshot_Before = await troveManager.rewardSnapshots(alice.address);
      const alice_FILrewardSnapshot_Before = alice_rewardSnapshot_Before[0];
      const alice_DebtRewardSnapshot_Before = alice_rewardSnapshot_Before[1];

      const bob_rewardSnapshot_Before = await troveManager.rewardSnapshots(bob.address);
      const bob_FILrewardSnapshot_Before = bob_rewardSnapshot_Before[0];
      const bob_DebtRewardSnapshot_Before = bob_rewardSnapshot_Before[1];

      assert.equal(alice_FILrewardSnapshot_Before, 0);
      assert.equal(alice_DebtRewardSnapshot_Before, 0);
      assert.equal(bob_FILrewardSnapshot_Before, 0);
      assert.equal(bob_DebtRewardSnapshot_Before, 0);

      // Check A and B have pending rewards
      const pendingCollReward_A = await troveManager.getPendingFILReward(alice.address);
      const pendingDebtReward_A = await troveManager.getPendingDebtReward(alice.address);
      const pendingCollReward_B = await troveManager.getPendingFILReward(bob.address);
      const pendingDebtReward_B = await troveManager.getPendingDebtReward(bob.address);
      for (reward of [
        pendingCollReward_A,
        pendingDebtReward_A,
        pendingCollReward_B,
        pendingDebtReward_B,
      ]) {
        assert.isTrue(reward.gt(toBN("0")));
      }

      // Alice and Bob withdraw from their Troves
      const aliceCollWithdrawal = toBN(dec(5, "ether"));
      const bobCollWithdrawal = toBN(dec(1, "ether"));

      await borrowerOperations
        .connect(alice)
        .withdrawColl(aliceCollWithdrawal, alice.address, alice.address);
      await borrowerOperations
        .connect(bob)
        .withdrawColl(bobCollWithdrawal, bob.address, bob.address);

      // Check that both alice and Bob have had pending rewards applied in addition to their top-ups.
      const aliceCollAfter = await getTroveEntireColl(alice.address);
      const aliceDebtAfter = await getTroveEntireDebt(alice.address);
      const bobCollAfter = await getTroveEntireColl(bob.address);
      const bobDebtAfter = await getTroveEntireDebt(bob.address);

      // Check rewards have been applied to troves
      th.assertIsApproximatelyEqual(
        aliceCollAfter,
        aliceCollBefore.add(pendingCollReward_A).sub(aliceCollWithdrawal),
        10000,
      );
      th.assertIsApproximatelyEqual(
        aliceDebtAfter,
        aliceDebtBefore.add(pendingDebtReward_A),
        10000,
      );
      th.assertIsApproximatelyEqual(
        bobCollAfter,
        bobCollBefore.add(pendingCollReward_B).sub(bobCollWithdrawal),
        10000,
      );
      th.assertIsApproximatelyEqual(bobDebtAfter, bobDebtBefore.add(pendingDebtReward_B), 10000);

      /* After top up, both Alice and Bob's snapshots of the rewards-per-unit-staked metrics should be updated
       to the latest values of L_FIL and L_Debt */
      const alice_rewardSnapshot_After = await troveManager.rewardSnapshots(alice.address);
      const alice_FILrewardSnapshot_After = alice_rewardSnapshot_After[0];
      const alice_DebtRewardSnapshot_After = alice_rewardSnapshot_After[1];

      const bob_rewardSnapshot_After = await troveManager.rewardSnapshots(bob.address);
      const bob_FILrewardSnapshot_After = bob_rewardSnapshot_After[0];
      const bob_DebtRewardSnapshot_After = bob_rewardSnapshot_After[1];

      assert.isAtMost(th.getDifference(alice_FILrewardSnapshot_After, L_FIL), 100);
      assert.isAtMost(th.getDifference(alice_DebtRewardSnapshot_After, L_Debt), 100);
      assert.isAtMost(th.getDifference(bob_FILrewardSnapshot_After, L_FIL), 100);
      assert.isAtMost(th.getDifference(bob_DebtRewardSnapshot_After, L_Debt), 100);
    });

    // --- withdrawDebtToken() ---

    it("withdrawDebtToken(): reverts when withdrawal would leave trove with ICR < MCR", async () => {
      // alice creates a Trove and adds first collateral
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: alice } });
      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: bob } });

      // Price drops
      await priceFeed.setPrice(dec(100, 18));
      const price = await priceFeed.getPrice();

      assert.isFalse(await troveManager.checkRecoveryMode(price));
      assert.isTrue(
        (await troveManager.getCurrentICR(alice.address, price)).lt(toBN(dec(110, 16))),
      );

      const debtTokenWithdrawal = 1; // withdraw 1 wei debt token

      await assertRevert(
        borrowerOperations
          .connect(alice)
          .withdrawDebtToken(th._100pct, debtTokenWithdrawal, alice.address, alice.address),
        "BorrowerOps: An operation that would result in ICR < MCR is not permitted",
      );
    });

    it("withdrawDebtToken(): decays a non-zero base rate", async () => {
      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: whale } });

      await openTrove({
        extraDebtTokenAmount: toBN(dec(20, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(20, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(20, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(20, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: E },
      });

      const A_DebtTokenBal = await debtToken.balanceOf(A.address);

      // Artificially set base rate to 5%
      await troveManager.setBaseRate(dec(5, 16));

      // Check baseRate is now non-zero
      const baseRate_1 = await troveManager.baseRate();
      assert.isTrue(baseRate_1.gt(toBN("0")));

      // 2 hours pass
      await th.fastForwardTime(7200, web3.currentProvider);

      // D withdraws debt token
      await borrowerOperations
        .connect(D)
        .withdrawDebtToken(th._100pct, dec(1, 18), A.address, A.address);

      // Check baseRate has decreased
      const baseRate_2 = await troveManager.baseRate();
      assert.isTrue(baseRate_2.lt(baseRate_1));

      // 1 hour passes
      await th.fastForwardTime(3600, web3.currentProvider);

      // E withdraws debt token
      await borrowerOperations
        .connect(E)
        .withdrawDebtToken(th._100pct, dec(1, 18), A.address, A.address);

      const baseRate_3 = await troveManager.baseRate();
      assert.isTrue(baseRate_3.lt(baseRate_2));
    });

    it("withdrawDebtToken(): reverts if max fee > 100%", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(20, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });

      await assertRevert(
        borrowerOperations
          .connect(A)
          .withdrawDebtToken(dec(2, 18), dec(1, 18), A.address, A.address),
        "Max fee percentage must be between 0.5% and 100%",
      );
      await assertRevert(
        borrowerOperations
          .connect(A)
          .withdrawDebtToken("1000000000000000001", dec(1, 18), A.address, A.address),
        "Max fee percentage must be between 0.5% and 100%",
      );
    });

    it("withdrawDebtToken(): reverts if max fee < 0.5% in Normal mode", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(20, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });

      await assertRevert(
        borrowerOperations.connect(A).withdrawDebtToken(0, dec(1, 18), A.address, A.address),
        "Max fee percentage must be between 0.5% and 100%",
      );
      await assertRevert(
        borrowerOperations.connect(A).withdrawDebtToken(1, dec(1, 18), A.address, A.address),
        "Max fee percentage must be between 0.5% and 100%",
      );
      await assertRevert(
        borrowerOperations
          .connect(A)
          .withdrawDebtToken("4999999999999999", dec(1, 18), A.address, A.address),
        "Max fee percentage must be between 0.5% and 100%",
      );
    });

    it("withdrawDebtToken(): reverts if fee exceeds max fee percentage", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(60, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(60, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(70, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(80, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(180, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: E },
      });

      const totalSupply = await debtToken.totalSupply();

      // Artificially make baseRate 5%
      await troveManager.setBaseRate(dec(5, 16));
      await troveManager.setLastFeeOpTimeToNow();

      let baseRate = await troveManager.baseRate(); // expect 5% base rate
      assert.equal(baseRate, dec(5, 16));

      // 100%: 1e18,  10%: 1e17,  1%: 1e16,  0.1%: 1e15
      // 5%: 5e16
      // 0.5%: 5e15
      // actual: 0.5%, 5e15

      // DebtTokenFee:                  15000000558793542
      // absolute _fee:            15000000558793542
      // actual feePercentage:      5000000186264514
      // user's _maxFeePercentage: 49999999999999999

      const lessThan5pct = "49999999999999999";
      await assertRevert(
        borrowerOperations
          .connect(A)
          .withdrawDebtToken(lessThan5pct, dec(3, 18), A.address, A.address),
        "Fee exceeded provided maximum",
      );

      baseRate = await troveManager.baseRate(); // expect 5% base rate
      assert.equal(baseRate, dec(5, 16));
      // Attempt with maxFee 1%
      await assertRevert(
        borrowerOperations
          .connect(B)
          .withdrawDebtToken(dec(1, 16), dec(1, 18), A.address, A.address),
        "Fee exceeded provided maximum",
      );

      baseRate = await troveManager.baseRate(); // expect 5% base rate
      assert.equal(baseRate, dec(5, 16));
      // Attempt with maxFee 3.754%
      await assertRevert(
        borrowerOperations
          .connect(C)
          .withdrawDebtToken(dec(3754, 13), dec(1, 18), A.address, A.address),
        "Fee exceeded provided maximum",
      );

      baseRate = await troveManager.baseRate(); // expect 5% base rate
      assert.equal(baseRate, dec(5, 16));
      // Attempt with maxFee 0.5%%
      await assertRevert(
        borrowerOperations
          .connect(D)
          .withdrawDebtToken(dec(5, 15), dec(1, 18), A.address, A.address),
        "Fee exceeded provided maximum",
      );
    });

    it("withdrawDebtToken(): succeeds when fee is less than max fee percentage", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(60, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(60, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(70, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(80, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(180, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: E },
      });

      const totalSupply = await debtToken.totalSupply();

      // Artificially make baseRate 5%
      await troveManager.setBaseRate(dec(5, 16));
      await troveManager.setLastFeeOpTimeToNow();

      let baseRate = await troveManager.baseRate(); // expect 5% base rate
      assert.isTrue(baseRate.eq(toBN(dec(5, 16))));

      // Attempt with maxFee > 5%
      const moreThan5pct = "50000000000000001";
      const tx1 = await borrowerOperations
        .connect(A)
        .withdrawDebtToken(moreThan5pct, dec(1, 18), A.address, A.address);
      const receipt = await tx1.wait();
      assert.equal(receipt.status, 1);

      baseRate = await troveManager.baseRate(); // expect 5% base rate
      assert.equal(baseRate, dec(5, 16));

      // Attempt with maxFee = 5%
      const tx2 = await borrowerOperations
        .connect(B)
        .withdrawDebtToken(dec(5, 16), dec(1, 18), A.address, A.address);
      const receipt2 = await tx2.wait();
      assert.equal(receipt2.status, 1);

      baseRate = await troveManager.baseRate(); // expect 5% base rate
      assert.equal(baseRate, dec(5, 16));

      // Attempt with maxFee 10%
      const tx3 = await borrowerOperations
        .connect(C)
        .withdrawDebtToken(dec(1, 17), dec(1, 18), A.address, A.address);
      const receipt3 = await tx3.wait();
      assert.equal(receipt3.status, 1);

      baseRate = await troveManager.baseRate(); // expect 5% base rate
      assert.equal(baseRate, dec(5, 16));

      // Attempt with maxFee 37.659%
      const tx4 = await borrowerOperations
        .connect(D)
        .withdrawDebtToken(dec(37659, 13), dec(1, 18), A.address, A.address);
      const receipt4 = await tx4.wait();
      assert.equal(receipt4.status, 1);

      // Attempt with maxFee 100%
      const tx5 = await borrowerOperations
        .connect(E)
        .withdrawDebtToken(dec(1, 18), dec(1, 18), A.address, A.address);
      const receipt5 = await tx5.wait();
      assert.equal(receipt5.status, 1);
    });

    it("withdrawDebtToken(): doesn't change base rate if it is already zero", async () => {
      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: whale } });

      await openTrove({
        extraDebtTokenAmount: toBN(dec(30, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: E },
      });

      // Check baseRate is zero
      const baseRate_1 = await troveManager.baseRate();
      assert.equal(baseRate_1, "0");

      // 2 hours pass
      await th.fastForwardTime(7200, web3.currentProvider);

      // D withdraws debt token
      await borrowerOperations
        .connect(D)
        .withdrawDebtToken(th._100pct, dec(37, 18), A.address, A.address);

      // Check baseRate is still 0
      const baseRate_2 = await troveManager.baseRate();
      assert.equal(baseRate_2, "0");

      // 1 hour passes
      await th.fastForwardTime(3600, web3.currentProvider);

      // E opens trove
      await borrowerOperations
        .connect(E)
        .withdrawDebtToken(th._100pct, dec(12, 18), A.address, A.address);

      const baseRate_3 = await troveManager.baseRate();
      assert.equal(baseRate_3, "0");
    });

    it("withdrawDebtToken(): lastFeeOpTime doesn't update if less time than decay interval has passed since the last fee operation", async () => {
      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: whale } });

      await openTrove({
        extraDebtTokenAmount: toBN(dec(30, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });

      // Artificially make baseRate 5%
      await troveManager.setBaseRate(dec(5, 16));
      await troveManager.setLastFeeOpTimeToNow();

      // Check baseRate is now non-zero
      const baseRate_1 = await troveManager.baseRate();
      assert.isTrue(baseRate_1.gt(toBN("0")));

      const lastFeeOpTime_1 = await troveManager.lastFeeOperationTime();

      // 10 seconds pass
      await th.fastForwardTime(10, web3.currentProvider);

      // Borrower C triggers a fee
      await borrowerOperations
        .connect(C)
        .withdrawDebtToken(th._100pct, dec(1, 18), C.address, C.address);

      const lastFeeOpTime_2 = await troveManager.lastFeeOperationTime();

      // Check that the last fee operation time did not update, as borrower D's debt issuance occured
      // since before minimum interval had passed
      assert.isTrue(lastFeeOpTime_2.eq(lastFeeOpTime_1));

      // 60 seconds passes
      await th.fastForwardTime(60, web3.currentProvider);

      // Check that now, at least one minute has passed since lastFeeOpTime_1
      const timeNow = await th.getLatestBlockTimestamp(web3);
      assert.isTrue(toBN(timeNow).sub(lastFeeOpTime_1).gte(60));

      // Borrower C triggers a fee
      await borrowerOperations
        .connect(C)
        .withdrawDebtToken(th._100pct, dec(1, 18), C.address, C.address);

      const lastFeeOpTime_3 = await troveManager.lastFeeOperationTime();

      // Check that the last fee operation time DID update, as borrower's debt issuance occured
      // after minimum interval had passed
      assert.isTrue(lastFeeOpTime_3.gt(lastFeeOpTime_1));
    });

    it("withdrawDebtToken(): borrower can't grief the baseRate and stop it decaying by issuing debt at higher frequency than the decay granularity", async () => {
      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: whale } });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(30, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });

      // Artificially make baseRate 5%
      await troveManager.setBaseRate(dec(5, 16));
      await troveManager.setLastFeeOpTimeToNow();

      // Check baseRate is now non-zero
      const baseRate_1 = await troveManager.baseRate();
      assert.isTrue(baseRate_1.gt(toBN("0")));

      // 30 seconds pass
      await th.fastForwardTime(30, web3.currentProvider);

      // Borrower C triggers a fee, before decay interval has passed
      await borrowerOperations
        .connect(C)
        .withdrawDebtToken(th._100pct, dec(1, 18), C.address, C.address);

      // 30 seconds pass
      await th.fastForwardTime(30, web3.currentProvider);

      // Borrower C triggers another fee
      await borrowerOperations
        .connect(C)
        .withdrawDebtToken(th._100pct, dec(1, 18), C.address, C.address);

      // Check base rate has decreased even though Borrower tried to stop it decaying
      const baseRate_2 = await troveManager.baseRate();
      assert.isTrue(baseRate_2.lt(baseRate_1));
    });

    it("withdrawDebtToken(): borrowing at non-zero base rate sends debt token fee to ProtocolToken staking contract", async () => {
      // time fast-forwards 1 year, and multisig stakes 1 token
      await th.fastForwardTime(timeValues.SECONDS_IN_ONE_YEAR, web3.currentProvider);
      await protocolToken.connect(multisig).approve(protocolTokenStaking.address, dec(1, 18));
      await protocolTokenStaking.connect(multisig).stake(dec(1, 18));

      // Check ProtocolToken DebtToken balance before == 0
      const protocolTokenStaking_debtTokenBalance_Before = await debtToken.balanceOf(
        protocolTokenStaking.address,
      );
      assert.equal(protocolTokenStaking_debtTokenBalance_Before, "0");

      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: whale } });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(30, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });

      // Artificially make baseRate 5%
      await troveManager.setBaseRate(dec(5, 16));
      await troveManager.setLastFeeOpTimeToNow();

      // Check baseRate is now non-zero
      const baseRate_1 = await troveManager.baseRate();
      assert.isTrue(baseRate_1.gt(toBN("0")));

      // 2 hours pass
      await th.fastForwardTime(7200, web3.currentProvider);

      // D withdraws debt token
      await borrowerOperations
        .connect(D)
        .withdrawDebtToken(th._100pct, dec(37, 18), C.address, C.address);

      // Check ProtocolToken DebtToken balance after has increased
      const protocolTokenStaking_debtTokenBalance_After = await debtToken.balanceOf(
        protocolTokenStaking.address,
      );
      assert.isTrue(
        protocolTokenStaking_debtTokenBalance_After.gt(
          protocolTokenStaking_debtTokenBalance_Before,
        ),
      );
    });

    if (!withProxy) {
      // TODO: use rawLogs instead of logs
      it("withdrawDebtToken(): borrowing at non-zero base records the (drawn debt + fee) on the Trove struct", async () => {
        // time fast-forwards 1 year, and multisig stakes 1 token
        await th.fastForwardTime(timeValues.SECONDS_IN_ONE_YEAR, web3.currentProvider);
        await protocolToken.connect(multisig).approve(protocolTokenStaking.address, dec(1, 18));
        await protocolTokenStaking.connect(multisig).stake(dec(1, 18));

        await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: whale } });
        await openTrove({
          extraDebtTokenAmount: toBN(dec(30, 18)),
          ICR: toBN(dec(2, 18)),
          extraParams: { from: A },
        });
        await openTrove({
          extraDebtTokenAmount: toBN(dec(40, 18)),
          ICR: toBN(dec(2, 18)),
          extraParams: { from: B },
        });
        await openTrove({
          extraDebtTokenAmount: toBN(dec(50, 18)),
          ICR: toBN(dec(2, 18)),
          extraParams: { from: C },
        });
        await openTrove({
          extraDebtTokenAmount: toBN(dec(50, 18)),
          ICR: toBN(dec(2, 18)),
          extraParams: { from: D },
        });
        const D_debtBefore = await getTroveEntireDebt(D.address);

        // Artificially make baseRate 5%
        await troveManager.setBaseRate(dec(5, 16));
        await troveManager.setLastFeeOpTimeToNow();

        // Check baseRate is now non-zero
        const baseRate_1 = await troveManager.baseRate();
        assert.isTrue(baseRate_1.gt(toBN("0")));

        // 2 hours pass
        await th.fastForwardTime(7200, web3.currentProvider);

        // D withdraws debt token
        const withdrawal_D = toBN(dec(37, 18));
        const withdrawalTx = await borrowerOperations
          .connect(D)
          .withdrawDebtToken(th._100pct, toBN(dec(37, 18)), D.address, D.address);

        const emittedFee = toBN(await th.getFeeFromDebtTokenBorrowingEvent(withdrawalTx));
        assert.isTrue(emittedFee.gt(toBN("0")));

        const newDebt = (await troveManager.Troves(D.address))[0];

        // Check debt on Trove struct equals initial debt + withdrawal + emitted fee
        th.assertIsApproximatelyEqual(
          newDebt,
          D_debtBefore.add(withdrawal_D).add(emittedFee),
          10000,
        );
      });
    }

    it("withdrawDebtToken(): Borrowing at non-zero base rate increases the ProtocolToken staking contract debt token fees-per-unit-staked", async () => {
      // time fast-forwards 1 year, and multisig stakes 1 token
      await th.fastForwardTime(timeValues.SECONDS_IN_ONE_YEAR, web3.currentProvider);
      await protocolToken.connect(multisig).approve(protocolTokenStaking.address, dec(1, 18));
      await protocolTokenStaking.connect(multisig).stake(dec(1, 18));

      // Check ProtocolToken contract debt token fees-per-unit-staked is zero
      const F_DebtToken_Before = await protocolTokenStaking.F_DebtToken();
      assert.equal(F_DebtToken_Before, "0");

      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: whale } });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(30, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });

      // Artificially make baseRate 5%
      await troveManager.setBaseRate(dec(5, 16));
      await troveManager.setLastFeeOpTimeToNow();

      // Check baseRate is now non-zero
      const baseRate_1 = await troveManager.baseRate();
      assert.isTrue(baseRate_1.gt(toBN("0")));

      // 2 hours pass
      await th.fastForwardTime(7200, web3.currentProvider);

      // D withdraws debt token
      await borrowerOperations
        .connect(D)
        .withdrawDebtToken(th._100pct, toBN(dec(37, 18)), D.address, D.address);

      // Check ProtocolToken contract debt token fees-per-unit-staked has increased
      const F_DebtToken_After = await protocolTokenStaking.F_DebtToken();
      assert.isTrue(F_DebtToken_After.gt(F_DebtToken_Before));
    });

    it("withdrawDebtToken(): Borrowing at non-zero base rate sends requested amount to the user", async () => {
      // time fast-forwards 1 year, and multisig stakes 1 token
      await th.fastForwardTime(timeValues.SECONDS_IN_ONE_YEAR, web3.currentProvider);
      await protocolToken.connect(multisig).approve(protocolTokenStaking.address, dec(1, 18));
      await protocolTokenStaking.connect(multisig).stake(dec(1, 18));

      // Check ProtocolToken Staking contract balance before == 0
      const protocolTokenStaking_debtTokenBalance_Before = await debtToken.balanceOf(
        protocolTokenStaking.address,
      );
      assert.equal(protocolTokenStaking_debtTokenBalance_Before, "0");

      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: whale } });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(30, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });

      // Artificially make baseRate 5%
      await troveManager.setBaseRate(dec(5, 16));
      await troveManager.setLastFeeOpTimeToNow();

      // Check baseRate is now non-zero
      const baseRate_1 = await troveManager.baseRate();
      assert.isTrue(baseRate_1.gt(toBN("0")));

      // 2 hours pass
      await th.fastForwardTime(7200, web3.currentProvider);

      const D_DebtTokenBalanceBefore = await debtToken.balanceOf(D.address);

      // D withdraws debt token
      const D_DebtTokenRequest = toBN(dec(37, 18));
      await borrowerOperations
        .connect(D)
        .withdrawDebtToken(th._100pct, D_DebtTokenRequest, D.address, D.address);

      // Check ProtocolToken staking debt token balance has increased
      const protocolTokenStaking_debtTokenBalance_After = await debtToken.balanceOf(
        protocolTokenStaking.address,
      );
      assert.isTrue(
        protocolTokenStaking_debtTokenBalance_After.gt(
          protocolTokenStaking_debtTokenBalance_Before,
        ),
      );

      // Check D's debt token balance now equals their initial balance plus request debt token
      const D_DebtTokenBalanceAfter = await debtToken.balanceOf(D.address);
      assert.isTrue(D_DebtTokenBalanceAfter.eq(D_DebtTokenBalanceBefore.add(D_DebtTokenRequest)));
    });

    it("withdrawDebtToken(): Borrowing at zero base rate changes debt token fees-per-unit-staked", async () => {
      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: whale } });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(30, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });

      // Check baseRate is zero
      const baseRate_1 = await troveManager.baseRate();
      assert.equal(baseRate_1, "0");

      // A artificially receives ProtocolToken, then stakes it
      await protocolToken.unprotectedMint(A.address, dec(100, 18));
      await protocolTokenStaking.connect(A).stake(dec(100, 18));

      // 2 hours pass
      await th.fastForwardTime(7200, web3.currentProvider);

      // Check ProtocolToken debt token balance before == 0
      const F_DebtToken_Before = await protocolTokenStaking.F_DebtToken();
      assert.equal(F_DebtToken_Before, "0");

      // D withdraws debt token
      await borrowerOperations
        .connect(D)
        .withdrawDebtToken(th._100pct, dec(37, 18), D.address, D.address);

      // Check ProtocolToken debt token balance after > 0
      const F_DebtToken_After = await protocolTokenStaking.F_DebtToken();
      assert.isTrue(F_DebtToken_After.gt("0"));
    });

    it("withdrawDebtToken(): Borrowing at zero base rate sends debt request to user", async () => {
      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: whale } });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(30, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });

      // Check baseRate is zero
      const baseRate_1 = await troveManager.baseRate();
      assert.equal(baseRate_1, "0");

      // 2 hours pass
      await th.fastForwardTime(7200, web3.currentProvider);

      const D_DebtTokenBalanceBefore = await debtToken.balanceOf(D.address);

      // D withdraws debt token
      const D_DebtTokenRequest = toBN(dec(37, 18));
      await borrowerOperations
        .connect(D)
        .withdrawDebtToken(th._100pct, dec(37, 18), D.address, D.address);

      // Check D's debt token balance now equals their requested debt token
      const D_DebtTokenBalanceAfter = await debtToken.balanceOf(D.address);

      // Check D's trove debt == D's debt token balance + liquidation reserve
      assert.isTrue(D_DebtTokenBalanceAfter.eq(D_DebtTokenBalanceBefore.add(D_DebtTokenRequest)));
    });

    it("withdrawDebtToken(): reverts when calling address does not have active trove", async () => {
      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: alice } });
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: bob } });

      // Bob successfully withdraws debt token
      const txBob = await borrowerOperations
        .connect(bob)
        .withdrawDebtToken(th._100pct, dec(100, 18), bob.address, bob.address);
      const receiptBob = await txBob.wait();
      assert.equal(receiptBob.status, 1);

      // Carol with no active trove attempts to withdraw debt token
      try {
        const txCarol = await borrowerOperations
          .connect(carol)
          .withdrawDebtToken(th._100pct, dec(100, 18), carol.address, carol.address);
        const receiptCarol = await txCarol.wait();
        assert.equal(receiptCarol.status, 0);
      } catch (err) {
        assert.include(err.message, "revert");
      }
    });

    it("withdrawDebtToken(): reverts when requested withdrawal amount is zero debt token", async () => {
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: alice } });
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: bob } });

      // Bob successfully withdraws 1e-18 tokens
      const txBob = await borrowerOperations
        .connect(bob)
        .withdrawDebtToken(th._100pct, 1, bob.address, bob.address);
      const receiptBob = await txBob.wait();
      assert.equal(receiptBob.status, 1);

      // Alice attempts to withdraw 0 token
      try {
        const txAlice = await borrowerOperations
          .connect(alice)
          .withdrawDebtToken(th._100pct, 0, alice.address, alice.address);
        const receiptAlice = await txAlice.wait();
        assert.equal(receiptAlice.status, 0);
      } catch (err) {
        assert.include(err.message, "revert");
      }
    });

    it("withdrawDebtToken(): reverts when system is in Recovery Mode", async () => {
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: alice } });
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: bob } });
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: carol } });

      assert.isFalse(await th.checkRecoveryMode(contracts));

      // Withdrawal possible when recoveryMode == false
      const txAlice = await borrowerOperations
        .connect(alice)
        .withdrawDebtToken(th._100pct, dec(100, 18), alice.address, alice.address);
      const receiptAlice = await txAlice.wait();
      assert.equal(receiptAlice.status, 1);

      await priceFeed.setPrice("50000000000000000000");

      assert.isTrue(await th.checkRecoveryMode(contracts));

      //Check debt token withdrawal impossible when recoveryMode == true
      try {
        const txBob = await borrowerOperations
          .connect(bob)
          .withdrawDebtToken(th._100pct, 1, bob.address, bob.address);
        const receiptBob = await txBob.wait();
        assert.equal(receiptBob.status, 0);
      } catch (err) {
        assert.include(err.message, "revert");
      }
    });

    it("withdrawDebtToken(): reverts when withdrawal would bring the trove's ICR < MCR", async () => {
      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: alice } });
      await openTrove({ ICR: toBN(dec(11, 17)), extraParams: { from: bob } });

      // Bob tries to withdraw debt token that would bring his ICR < MCR
      try {
        const txBob = await borrowerOperations
          .connect(bob)
          .withdrawDebtToken(th._100pct, 1, bob.address, bob.address);
        const receipt = await txBob.wait();
        assert.equal(receipt.status, 0);
      } catch (err) {
        assert.include(err.message, "revert");
      }
    });

    it("withdrawDebtToken(): reverts when a withdrawal would cause the TCR of the system to fall below the CCR", async () => {
      await priceFeed.setPrice(dec(100, 18));
      const price = await priceFeed.getPrice();

      // Alice and Bob creates troves with 150% ICR.  System TCR = 150%.
      await openTrove({ ICR: toBN(dec(15, 17)), extraParams: { from: alice } });
      await openTrove({ ICR: toBN(dec(15, 17)), extraParams: { from: bob } });

      var TCR = (await th.getTCR(contracts)).toString();
      assert.equal(TCR, "1500000000000000000");

      // Bob attempts to withdraw 1 token.
      // System TCR would be: ((3+3) * 100 ) / (200+201) = 600/401 = 149.62%, i.e. below CCR of 150%.
      try {
        const txBob = await borrowerOperations
          .connect(bob)
          .withdrawDebtToken(th._100pct, dec(1, 18), bob.address, bob.address);
        const receipt = await txBob.wait();
        assert.equal(receipt.status, 0);
      } catch (err) {
        assert.include(err.message, "revert");
      }
    });

    it("withdrawDebtToken(): reverts if system is in Recovery Mode", async () => {
      // --- SETUP ---
      await openTrove({ ICR: toBN(dec(15, 17)), extraParams: { from: alice } });
      await openTrove({ ICR: toBN(dec(15, 17)), extraParams: { from: bob } });

      // --- TEST ---

      // price drops to 1FIL:150DebtToken, reducing TCR below 150%
      await priceFeed.setPrice("150000000000000000000");
      assert.isTrue((await th.getTCR(contracts)).lt(toBN(dec(15, 17))));

      try {
        const txData = await borrowerOperations
          .connect(alice)
          .withdrawDebtToken(th._100pct, "200", alice.address, alice.address);
        assert.isFalse(txData.receipt.status);
      } catch (err) {
        assert.include(err.message, "revert");
      }
    });

    it("withdrawDebtToken(): increases the Trove's debt by the correct amount", async () => {
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: alice } });

      // check before
      const aliceDebtBefore = await getTroveEntireDebt(alice.address);
      assert.isTrue(aliceDebtBefore.gt(toBN(0)));

      await borrowerOperations
        .connect(alice)
        .withdrawDebtToken(
          th._100pct,
          await getNetBorrowingAmount(100),
          alice.address,
          alice.address,
        );

      // check after
      const aliceDebtAfter = await getTroveEntireDebt(alice.address);
      th.assertIsApproximatelyEqual(aliceDebtAfter, aliceDebtBefore.add(toBN(100)));
    });

    it("withdrawDebtToken(): increases debt in ActivePool by correct amount", async () => {
      await openTrove({
        ICR: toBN(dec(10, 18)),
        extraParams: { from: alice, value: toBN(dec(100, "ether")) },
      });

      const aliceDebtBefore = await getTroveEntireDebt(alice.address);
      assert.isTrue(aliceDebtBefore.gt(toBN(0)));

      // check before
      const activePool_debtToken_Before = await activePool.getDebt();
      assert.isTrue(activePool_debtToken_Before.eq(aliceDebtBefore));

      await borrowerOperations
        .connect(alice)
        .withdrawDebtToken(
          th._100pct,
          await getNetBorrowingAmount(dec(10000, 18)),
          alice.address,
          alice.address,
        );

      // check after
      const activePool_debtToken_After = await activePool.getDebt();
      th.assertIsApproximatelyEqual(
        activePool_debtToken_After,
        activePool_debtToken_Before.add(toBN(dec(10000, 18))),
      );
    });

    it("withdrawDebtToken(): increases user DebtToken balance by correct amount", async () => {
      await openTrove({ extraParams: { value: toBN(dec(100, "ether")), from: alice } });

      // check before
      const alice_DebtTokenBalance_Before = await debtToken.balanceOf(alice.address);
      assert.isTrue(alice_DebtTokenBalance_Before.gt(toBN("0")));

      await borrowerOperations
        .connect(alice)
        .withdrawDebtToken(th._100pct, dec(10000, 18), alice.address, alice.address);

      // check after
      const alice_DebtTokenBalance_After = await debtToken.balanceOf(alice.address);
      assert.isTrue(
        alice_DebtTokenBalance_After.eq(alice_DebtTokenBalance_Before.add(toBN(dec(10000, 18)))),
      );
    });

    // --- repayDebtToken() ---
    it("repayDebtToken(): reverts when repayment would leave trove with ICR < MCR", async () => {
      // alice creates a Trove and adds first collateral
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: alice } });
      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: bob } });

      // Price drops
      await priceFeed.setPrice(dec(100, 18));
      const price = await priceFeed.getPrice();

      assert.isFalse(await troveManager.checkRecoveryMode(price));
      assert.isTrue(
        (await troveManager.getCurrentICR(alice.address, price)).lt(toBN(dec(110, 16))),
      );

      const debtTokenRepayment = 1; // 1 wei repayment

      await assertRevert(
        borrowerOperations
          .connect(alice)
          .repayDebtToken(debtTokenRepayment, alice.address, alice.address),
        "BorrowerOps: An operation that would result in ICR < MCR is not permitted",
      );
    });

    it("repayDebtToken(): Succeeds when it would leave trove with net debt >= minimum net debt", async () => {
      // Make the debt token request 2 wei above min net debt to correct for floor division, and make net debt = min net debt + 1 wei
      await borrowerOperations
        .connect(A)
        .openTrove(
          th._100pct,
          await getNetBorrowingAmount(MIN_NET_DEBT.add(toBN("2"))),
          A.address,
          A.address,
          {
            value: dec(100, 30),
          },
        );

      const repayTxA = await borrowerOperations.connect(A).repayDebtToken(1, A.address, A.address);
      const receiptA = await repayTxA.wait();
      assert.equal(receiptA.status, 1);

      await borrowerOperations.connect(B).openTrove(th._100pct, dec(20, 25), B.address, B.address, {
        value: dec(100, 30),
      });

      const repayTxB = await borrowerOperations
        .connect(B)
        .repayDebtToken(dec(19, 25), B.address, B.address);
      const receiptB = await repayTxB.wait();
      assert.equal(receiptB.status, 1);
    });

    it("repayDebtToken(): reverts when it would leave trove with net debt < minimum net debt", async () => {
      // Make the debt token request 2 wei above min net debt to correct for floor division, and make net debt = min net debt + 1 wei
      await borrowerOperations
        .connect(A)
        .openTrove(
          th._100pct,
          await getNetBorrowingAmount(MIN_NET_DEBT.add(toBN("2"))),
          A.address,
          A.address,
          {
            value: dec(100, 30),
          },
        );

      const repayTxAPromise = borrowerOperations.connect(A).repayDebtToken(2, A.address, A.address);
      await assertRevert(
        repayTxAPromise,
        "BorrowerOps: Trove's net debt must be greater than minimum",
      );
    });

    it("adjustTrove(): Reverts if repaid amount is greater than current debt", async () => {
      const { totalDebt } = await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: alice },
      });
      GAS_COMPENSATION = await borrowerOperations.GAS_COMPENSATION();
      const repayAmount = totalDebt.sub(GAS_COMPENSATION).add(toBN(1));
      await openTrove({
        extraDebtTokenAmount: repayAmount,
        ICR: toBN(dec(150, 16)),
        extraParams: { from: bob },
      });

      await debtToken.connect(bob).transfer(alice.address, repayAmount);

      await assertRevert(
        borrowerOperations
          .connect(alice)
          .adjustTrove(th._100pct, 0, repayAmount, false, alice.address, alice.address),
        "SafeMath: subtraction overflow",
      );
    });

    it("repayDebtToken(): reverts when calling address does not have active trove", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: bob },
      });
      // Bob successfully repays some debt token
      const txBob = await borrowerOperations
        .connect(bob)
        .repayDebtToken(dec(10, 18), bob.address, bob.address);
      const receiptBob = await txBob.wait();
      assert.equal(receiptBob.status, 1);

      // Carol with no active trove attempts to repayDebtToken
      try {
        const txCarol = await borrowerOperations
          .connect(carol)
          .repayDebtToken(dec(10, 18), carol.address, carol.address);
        const receiptCarol = await txCarol.wait();
        assert.equal(receiptCarol.status, 0);
      } catch (err) {
        assert.include(err.message, "revert");
      }
    });

    it("repayDebtToken(): reverts when attempted repayment is > the debt of the trove", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: bob },
      });
      const aliceDebt = await getTroveEntireDebt(alice.address);

      // Bob successfully repays some debt token
      const txBob = await borrowerOperations
        .connect(bob)
        .repayDebtToken(dec(10, 18), bob.address, bob.address);
      const receiptBob = await txBob.wait();
      assert.equal(receiptBob.status, 1);

      // Alice attempts to repay more than her debt
      try {
        const txAlice = await borrowerOperations
          .connect(alice)
          .repayDebtToken(aliceDebt.add(toBN(dec(1, 18))), alice.address, alice.address);
        const receiptAlice = await txAlice.wait();
        assert.equal(receiptAlice.status, 0);
      } catch (err) {
        assert.include(err.message, "revert");
      }
    });

    //repayDebtToken: reduces debt token debt in Trove
    it("repayDebtToken(): reduces the Trove's debt token debt by the correct amount", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: bob },
      });
      const aliceDebtBefore = await getTroveEntireDebt(alice.address);
      assert.isTrue(aliceDebtBefore.gt(toBN("0")));

      await borrowerOperations
        .connect(alice)
        .repayDebtToken(aliceDebtBefore.div(toBN(10)), alice.address, alice.address); // Repays 1/10 her debt

      const aliceDebtAfter = await getTroveEntireDebt(alice.address);
      assert.isTrue(aliceDebtAfter.gt(toBN("0")));

      th.assertIsApproximatelyEqual(aliceDebtAfter, aliceDebtBefore.mul(toBN(9)).div(toBN(10))); // check 9/10 debt remaining
    });

    it("repayDebtToken(): decreases debt token debt in ActivePool by correct amount", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: bob },
      });
      const aliceDebtBefore = await getTroveEntireDebt(alice.address);
      assert.isTrue(aliceDebtBefore.gt(toBN("0")));

      // Check before
      const activePool_debtToken_Before = await activePool.getDebt();
      assert.isTrue(activePool_debtToken_Before.gt(toBN("0")));

      await borrowerOperations
        .connect(alice)
        .repayDebtToken(aliceDebtBefore.div(toBN(10)), alice.address, alice.address); // Repays 1/10 her debt

      // check after
      const activePool_debtToken_After = await activePool.getDebt();
      th.assertIsApproximatelyEqual(
        activePool_debtToken_After,
        activePool_debtToken_Before.sub(aliceDebtBefore.div(toBN(10))),
      );
    });

    it("repayDebtToken(): decreases user DebtToken balance by correct amount", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: bob },
      });
      const aliceDebtBefore = await getTroveEntireDebt(alice.address);
      assert.isTrue(aliceDebtBefore.gt(toBN("0")));

      // check before
      const alice_DebtTokenBalance_Before = await debtToken.balanceOf(alice.address);
      assert.isTrue(alice_DebtTokenBalance_Before.gt(toBN("0")));

      await borrowerOperations
        .connect(alice)
        .repayDebtToken(aliceDebtBefore.div(toBN(10)), alice.address, alice.address); // Repays 1/10 her debt

      // check after
      const alice_DebtTokenBalance_After = await debtToken.balanceOf(alice.address);
      th.assertIsApproximatelyEqual(
        alice_DebtTokenBalance_After,
        alice_DebtTokenBalance_Before.sub(aliceDebtBefore.div(toBN(10))),
      );
    });

    it("repayDebtToken(): can repay debt in Recovery Mode", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: bob },
      });
      const aliceDebtBefore = await getTroveEntireDebt(alice.address);
      assert.isTrue(aliceDebtBefore.gt(toBN("0")));

      assert.isFalse(await th.checkRecoveryMode(contracts));

      await priceFeed.setPrice("105000000000000000000");

      assert.isTrue(await th.checkRecoveryMode(contracts));

      const tx = await borrowerOperations
        .connect(alice)
        .repayDebtToken(aliceDebtBefore.div(toBN(10)), alice.address, alice.address);
      const receipt = await tx.wait();
      assert.equal(receipt.status, 1);

      // Check Alice's debt: 110 (initial) - 50 (repaid)
      const aliceDebtAfter = await getTroveEntireDebt(alice.address);
      th.assertIsApproximatelyEqual(aliceDebtAfter, aliceDebtBefore.mul(toBN(9)).div(toBN(10)));
    });

    it("repayDebtToken(): Reverts if borrower has insufficient debt token balance to cover his debt repayment", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      const bobBalBefore = await debtToken.balanceOf(B.address);
      assert.isTrue(bobBalBefore.gt(toBN("0")));

      // Bob transfers all but 5 of his debt token to Carol
      await debtToken.connect(B).transfer(C.address, bobBalBefore.sub(toBN(dec(5, 18))));

      //Confirm B's debt token balance has decreased to 5 tokens
      const bobBalAfter = await debtToken.balanceOf(B.address);

      assert.isTrue(bobBalAfter.eq(toBN(dec(5, 18))));

      // Bob tries to repay 6 tokens
      const repayDebtTokenPromise_B = borrowerOperations
        .connect(B)
        .repayDebtToken(toBN(dec(6, 18)), B.address, B.address);

      await assertRevert(
        repayDebtTokenPromise_B,
        "Caller doesnt have enough tokens to make repayment",
      );
    });

    // --- adjustTrove() ---

    it("adjustTrove(): reverts when adjustment would leave trove with ICR < MCR", async () => {
      // alice creates a Trove and adds first collateral
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: alice } });
      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: bob } });

      // Price drops
      await priceFeed.setPrice(dec(100, 18));
      const price = await priceFeed.getPrice();

      assert.isFalse(await troveManager.checkRecoveryMode(price));
      assert.isTrue(
        (await troveManager.getCurrentICR(alice.address, price)).lt(toBN(dec(110, 16))),
      );

      const debtTokenRepayment = 1; // 1 wei repayment
      const collTopUp = 1;

      await assertRevert(
        borrowerOperations
          .connect(alice)
          .adjustTrove(th._100pct, 0, debtTokenRepayment, false, alice.address, alice.address, {
            value: collTopUp,
          }),
        "BorrowerOps: An operation that would result in ICR < MCR is not permitted",
      );
    });

    it("adjustTrove(): reverts if max fee < 0.5% in Normal mode", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });

      await assertRevert(
        borrowerOperations.connect(A).adjustTrove(0, 0, dec(1, 18), true, A.address, A.address, {
          value: dec(2, 16),
        }),
        "Max fee percentage must be between 0.5% and 100%",
      );
      await assertRevert(
        borrowerOperations.connect(A).adjustTrove(1, 0, dec(1, 18), true, A.address, A.address, {
          value: dec(2, 16),
        }),
        "Max fee percentage must be between 0.5% and 100%",
      );
      await assertRevert(
        borrowerOperations
          .connect(A)
          .adjustTrove("4999999999999999", 0, dec(1, 18), true, A.address, A.address, {
            value: dec(2, 16),
          }),
        "Max fee percentage must be between 0.5% and 100%",
      );
    });

    it("adjustTrove(): allows max fee < 0.5% in Recovery mode", async () => {
      await openTrove({
        ICR: toBN(dec(2, 18)),
        extraParams: { from: whale, value: toBN(dec(100, "ether")) },
      });

      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });

      await priceFeed.setPrice(dec(120, 18));
      assert.isTrue(await th.checkRecoveryMode(contracts));

      await borrowerOperations.connect(A).adjustTrove(0, 0, dec(1, 9), true, A.address, A.address, {
        value: dec(300, 18),
      });
      await priceFeed.setPrice(dec(1, 18));
      assert.isTrue(await th.checkRecoveryMode(contracts));
      await borrowerOperations.connect(A).adjustTrove(1, 0, dec(1, 9), true, A.address, A.address, {
        value: dec(30000, 18),
      });
      await priceFeed.setPrice(dec(1, 16));
      assert.isTrue(await th.checkRecoveryMode(contracts));
      await borrowerOperations
        .connect(A)
        .adjustTrove("4999999999999999", 0, dec(1, 9), true, A.address, A.address, {
          value: dec(3000000, 18),
        });
    });

    it("adjustTrove(): decays a non-zero base rate", async () => {
      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: whale } });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(30, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: E },
      });

      // Artificially make baseRate 5%
      await troveManager.setBaseRate(dec(5, 16));
      await troveManager.setLastFeeOpTimeToNow();

      // Check baseRate is now non-zero
      const baseRate_1 = await troveManager.baseRate();
      assert.isTrue(baseRate_1.gt(toBN("0")));

      // 2 hours pass
      await th.fastForwardTime(7200, web3.currentProvider);

      // D adjusts trove
      await borrowerOperations
        .connect(D)
        .adjustTrove(th._100pct, 0, dec(37, 18), true, D.address, D.address);

      // Check baseRate has decreased
      const baseRate_2 = await troveManager.baseRate();
      assert.isTrue(baseRate_2.lt(baseRate_1));

      // 1 hour passes
      await th.fastForwardTime(3600, web3.currentProvider);

      // E adjusts trove
      await borrowerOperations
        .connect(D)
        .adjustTrove(th._100pct, 0, dec(37, 15), true, E.address, E.address);

      const baseRate_3 = await troveManager.baseRate();
      assert.isTrue(baseRate_3.lt(baseRate_2));
    });

    it("adjustTrove(): doesn't decay a non-zero base rate when user issues 0 debt", async () => {
      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: whale } });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(30, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });

      // Artificially make baseRate 5%
      await troveManager.setBaseRate(dec(5, 16));
      await troveManager.setLastFeeOpTimeToNow();

      // D opens trove
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });

      // Check baseRate is now non-zero
      const baseRate_1 = await troveManager.baseRate();
      assert.isTrue(baseRate_1.gt(toBN("0")));

      // 2 hours pass
      await th.fastForwardTime(7200, web3.currentProvider);

      // D adjusts trove with 0 debt
      await borrowerOperations
        .connect(D)
        .adjustTrove(th._100pct, 0, 0, false, D.address, D.address, {
          value: dec(1, "ether"),
        });

      // Check baseRate has not decreased
      const baseRate_2 = await troveManager.baseRate();
      assert.isTrue(baseRate_2.eq(baseRate_1));
    });

    it("adjustTrove(): doesn't change base rate if it is already zero", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: E },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });

      // Check baseRate is zero
      const baseRate_1 = await troveManager.baseRate();
      assert.equal(baseRate_1, "0");

      // 2 hours pass
      await th.fastForwardTime(7200, web3.currentProvider);

      // D adjusts trove
      await borrowerOperations
        .connect(D)
        .adjustTrove(th._100pct, 0, dec(37, 18), true, D.address, D.address);

      // Check baseRate is still 0
      const baseRate_2 = await troveManager.baseRate();
      assert.equal(baseRate_2, "0");

      // 1 hour passes
      await th.fastForwardTime(3600, web3.currentProvider);

      // E adjusts trove
      await borrowerOperations
        .connect(D)
        .adjustTrove(th._100pct, 0, dec(37, 15), true, E.address, E.address);

      const baseRate_3 = await troveManager.baseRate();
      assert.equal(baseRate_3, "0");
    });

    it("adjustTrove(): lastFeeOpTime doesn't update if less time than decay interval has passed since the last fee operation", async () => {
      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: whale } });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(30, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });

      // Artificially make baseRate 5%
      await troveManager.setBaseRate(dec(5, 16));
      await troveManager.setLastFeeOpTimeToNow();

      // Check baseRate is now non-zero
      const baseRate_1 = await troveManager.baseRate();
      assert.isTrue(baseRate_1.gt(toBN("0")));

      const lastFeeOpTime_1 = await troveManager.lastFeeOperationTime();

      // 10 seconds pass
      await th.fastForwardTime(10, web3.currentProvider);

      // Borrower C triggers a fee
      await borrowerOperations
        .connect(C)
        .adjustTrove(th._100pct, 0, dec(1, 18), true, C.address, C.address);

      const lastFeeOpTime_2 = await troveManager.lastFeeOperationTime();

      // Check that the last fee operation time did not update, as borrower D's debt issuance occured
      // since before minimum interval had passed
      assert.isTrue(lastFeeOpTime_2.eq(lastFeeOpTime_1));

      // 60 seconds passes
      await th.fastForwardTime(60, web3.currentProvider);

      // Check that now, at least one minute has passed since lastFeeOpTime_1
      const timeNow = await th.getLatestBlockTimestamp(web3);
      assert.isTrue(toBN(timeNow).sub(lastFeeOpTime_1).gte(60));

      // Borrower C triggers a fee
      await borrowerOperations
        .connect(C)
        .adjustTrove(th._100pct, 0, dec(1, 18), true, C.address, C.address);

      const lastFeeOpTime_3 = await troveManager.lastFeeOperationTime();

      // Check that the last fee operation time DID update, as borrower's debt issuance occured
      // after minimum interval had passed
      assert.isTrue(lastFeeOpTime_3.gt(lastFeeOpTime_1));
    });

    it("adjustTrove(): borrower can't grief the baseRate and stop it decaying by issuing debt at higher frequency than the decay granularity", async () => {
      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: whale } });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(30, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });

      // Artificially make baseRate 5%
      await troveManager.setBaseRate(dec(5, 16));
      await troveManager.setLastFeeOpTimeToNow();

      // Check baseRate is now non-zero
      const baseRate_1 = await troveManager.baseRate();
      assert.isTrue(baseRate_1.gt(toBN("0")));

      // Borrower C triggers a fee, before decay interval of 1 minute has passed
      await borrowerOperations
        .connect(C)
        .adjustTrove(th._100pct, 0, dec(1, 18), true, C.address, C.address);

      // 1 minute passes
      await th.fastForwardTime(60, web3.currentProvider);

      // Borrower C triggers another fee
      await borrowerOperations
        .connect(C)
        .adjustTrove(th._100pct, 0, dec(1, 18), true, C.address, C.address);

      // Check base rate has decreased even though Borrower tried to stop it decaying
      const baseRate_2 = await troveManager.baseRate();
      assert.isTrue(baseRate_2.lt(baseRate_1));
    });

    it("adjustTrove(): borrowing at non-zero base rate sends debt token fee to ProtocolToken staking contract", async () => {
      // time fast-forwards 1 year, and multisig stakes 1 token
      await th.fastForwardTime(timeValues.SECONDS_IN_ONE_YEAR, web3.currentProvider);
      await protocolToken.connect(multisig).approve(protocolTokenStaking.address, dec(1, 18));
      await protocolTokenStaking.connect(multisig).stake(dec(1, 18));

      // Check ProtocolToken debt token balance before == 0
      const protocolTokenStaking_debtTokenBalance_Before = await debtToken.balanceOf(
        protocolTokenStaking.address,
      );
      assert.equal(protocolTokenStaking_debtTokenBalance_Before, "0");

      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: whale } });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(30, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });

      // Artificially make baseRate 5%
      await troveManager.setBaseRate(dec(5, 16));
      await troveManager.setLastFeeOpTimeToNow();

      // Check baseRate is now non-zero
      const baseRate_1 = await troveManager.baseRate();
      assert.isTrue(baseRate_1.gt(toBN("0")));

      // 2 hours pass
      await th.fastForwardTime(7200, web3.currentProvider);

      // D adjusts trove
      await openTrove({
        extraDebtTokenAmount: toBN(dec(37, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });

      // Check ProtocolToken debt token balance after has increased
      const protocolTokenStaking_debtTokenBalance_After = await debtToken.balanceOf(
        protocolTokenStaking.address,
      );
      assert.isTrue(
        protocolTokenStaking_debtTokenBalance_After.gt(
          protocolTokenStaking_debtTokenBalance_Before,
        ),
      );
    });

    if (!withProxy) {
      // TODO: use rawLogs instead of logs
      it("adjustTrove(): borrowing at non-zero base records the (drawn debt + fee) on the Trove struct", async () => {
        // time fast-forwards 1 year, and multisig stakes 1 token
        await th.fastForwardTime(timeValues.SECONDS_IN_ONE_YEAR, web3.currentProvider);
        await protocolToken.connect(multisig).approve(protocolTokenStaking.address, dec(1, 18));
        await protocolTokenStaking.connect(multisig).stake(dec(1, 18));

        await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: whale } });
        await openTrove({
          extraDebtTokenAmount: toBN(dec(30, 18)),
          ICR: toBN(dec(2, 18)),
          extraParams: { from: A },
        });
        await openTrove({
          extraDebtTokenAmount: toBN(dec(40, 18)),
          ICR: toBN(dec(2, 18)),
          extraParams: { from: B },
        });
        await openTrove({
          extraDebtTokenAmount: toBN(dec(50, 18)),
          ICR: toBN(dec(2, 18)),
          extraParams: { from: C },
        });
        await openTrove({
          extraDebtTokenAmount: toBN(dec(50, 18)),
          ICR: toBN(dec(2, 18)),
          extraParams: { from: D },
        });
        const D_debtBefore = await getTroveEntireDebt(D.address);

        // Artificially make baseRate 5%
        await troveManager.setBaseRate(dec(5, 16));
        await troveManager.setLastFeeOpTimeToNow();

        // Check baseRate is now non-zero
        const baseRate_1 = await troveManager.baseRate();
        assert.isTrue(baseRate_1.gt(toBN("0")));

        // 2 hours pass
        await th.fastForwardTime(7200, web3.currentProvider);

        const withdrawal_D = toBN(dec(37, 18));

        // D withdraws debt token
        const adjustmentTx = await borrowerOperations
          .connect(D)
          .adjustTrove(th._100pct, 0, withdrawal_D, true, D.address, D.address);

        const emittedFee = toBN(await th.getFeeFromDebtTokenBorrowingEvent(adjustmentTx));
        assert.isTrue(emittedFee.gt(toBN("0")));

        const D_newDebt = (await troveManager.Troves(D.address))[0];

        // Check debt on Trove struct equals initila debt plus drawn debt plus emitted fee
        assert.isTrue(D_newDebt.eq(D_debtBefore.add(withdrawal_D).add(emittedFee)));
      });
    }

    it("adjustTrove(): Borrowing at non-zero base rate increases the ProtocolToken staking contract debt token fees-per-unit-staked", async () => {
      // time fast-forwards 1 year, and multisig stakes 1 token
      await th.fastForwardTime(timeValues.SECONDS_IN_ONE_YEAR, web3.currentProvider);
      await protocolToken.connect(multisig).approve(protocolTokenStaking.address, dec(1, 18));
      await protocolTokenStaking.connect(multisig).stake(dec(1, 18));

      // Check ProtocolToken contract debt token fees-per-unit-staked is zero
      const F_DebtToken_Before = await protocolTokenStaking.F_DebtToken();
      assert.equal(F_DebtToken_Before, "0");

      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: whale } });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(30, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });

      // Artificially make baseRate 5%
      await troveManager.setBaseRate(dec(5, 16));
      await troveManager.setLastFeeOpTimeToNow();

      // Check baseRate is now non-zero
      const baseRate_1 = await troveManager.baseRate();
      assert.isTrue(baseRate_1.gt(toBN("0")));

      // 2 hours pass
      await th.fastForwardTime(7200, web3.currentProvider);

      // D adjusts trove
      await borrowerOperations
        .connect(D)
        .adjustTrove(th._100pct, 0, dec(37, 18), true, D.address, D.address);

      // Check ProtocolToken contract debt token fees-per-unit-staked has increased
      const F_DebtToken_After = await protocolTokenStaking.F_DebtToken();
      assert.isTrue(F_DebtToken_After.gt(F_DebtToken_Before));
    });

    it("adjustTrove(): Borrowing at non-zero base rate sends requested amount to the user", async () => {
      // time fast-forwards 1 year, and multisig stakes 1 token
      await th.fastForwardTime(timeValues.SECONDS_IN_ONE_YEAR, web3.currentProvider);
      await protocolToken.connect(multisig).approve(protocolTokenStaking.address, dec(1, 18));
      await protocolTokenStaking.connect(multisig).stake(dec(1, 18));

      // Check ProtocolToken Staking contract balance before == 0
      const protocolTokenStaking_debtTokenBalance_Before = await debtToken.balanceOf(
        protocolTokenStaking.address,
      );
      assert.equal(protocolTokenStaking_debtTokenBalance_Before, "0");

      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: whale } });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(30, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });

      const D_DebtTokenBalanceBefore = await debtToken.balanceOf(D.address);

      // Artificially make baseRate 5%
      await troveManager.setBaseRate(dec(5, 16));
      await troveManager.setLastFeeOpTimeToNow();

      // Check baseRate is now non-zero
      const baseRate_1 = await troveManager.baseRate();
      assert.isTrue(baseRate_1.gt(toBN("0")));

      // 2 hours pass
      await th.fastForwardTime(7200, web3.currentProvider);

      // D adjusts trove
      const debtTokenRequest_D = toBN(dec(40, 18));
      await borrowerOperations
        .connect(D)
        .adjustTrove(th._100pct, 0, debtTokenRequest_D, true, D.address, D.address);

      // Check ProtocolToken staking debt token balance has increased
      const protocolTokenStaking_debtTokenBalance_After = await debtToken.balanceOf(
        protocolTokenStaking.address,
      );
      assert.isTrue(
        protocolTokenStaking_debtTokenBalance_After.gt(
          protocolTokenStaking_debtTokenBalance_Before,
        ),
      );

      // Check D's debt token balance has increased by their requested debt token
      const D_DebtTokenBalanceAfter = await debtToken.balanceOf(D.address);
      assert.isTrue(D_DebtTokenBalanceAfter.eq(D_DebtTokenBalanceBefore.add(debtTokenRequest_D)));
    });

    it("adjustTrove(): Borrowing at zero base rate changes debt token balance of ProtocolToken staking contract", async () => {
      await openTrove({ ICR: toBN(dec(10, 18)), extraParams: { from: whale } });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(30, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(50, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });

      // Check baseRate is zero
      const baseRate_1 = await troveManager.baseRate();
      assert.equal(baseRate_1, "0");

      // 2 hours pass
      await th.fastForwardTime(7200, web3.currentProvider);

      // Check staking debt token balance before > 0
      const protocolTokenStaking_debtTokenBalance_Before = await debtToken.balanceOf(
        protocolTokenStaking.address,
      );
      assert.isTrue(protocolTokenStaking_debtTokenBalance_Before.gt(toBN("0")));

      // D adjusts trove
      await borrowerOperations
        .connect(D)
        .adjustTrove(th._100pct, 0, dec(37, 18), true, D.address, D.address);

      // Check staking debt token balance after > staking balance before
      const protocolTokenStaking_debtTokenBalance_After = await debtToken.balanceOf(
        protocolTokenStaking.address,
      );
      assert.isTrue(
        protocolTokenStaking_debtTokenBalance_After.gt(
          protocolTokenStaking_debtTokenBalance_Before,
        ),
      );
    });

    it("adjustTrove(): Borrowing at zero base rate changes ProtocolToken staking contract debt token fees-per-unit-staked", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(20000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: whale, value: toBN(dec(100, "ether")) },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });

      // Check baseRate is zero
      const baseRate_1 = await troveManager.baseRate();
      assert.equal(baseRate_1, "0");

      // 2 hours pass
      await th.fastForwardTime(7200, web3.currentProvider);

      // A artificially receives ProtocolToken, then stakes it
      await protocolToken.unprotectedMint(A.address, dec(100, 18));
      await protocolTokenStaking.connect(A).stake(dec(100, 18));

      // Check staking debt token balance before == 0
      const F_DebtToken_Before = await protocolTokenStaking.F_DebtToken();
      assert.isTrue(F_DebtToken_Before.eq(toBN("0")));

      // D adjusts trove
      await borrowerOperations
        .connect(D)
        .adjustTrove(th._100pct, 0, dec(37, 18), true, D.address, D.address);

      // Check staking debt token balance increases
      const F_DebtToken_After = await protocolTokenStaking.F_DebtToken();
      assert.isTrue(F_DebtToken_After.gt(F_DebtToken_Before));
    });

    it("adjustTrove(): Borrowing at zero base rate sends total requested debt token to the user", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(20000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: whale, value: toBN(dec(100, "ether")) },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });

      const D_DebtTOkenBalBefore = await debtToken.balanceOf(D.address);
      // Check baseRate is zero
      const baseRate_1 = await troveManager.baseRate();
      assert.equal(baseRate_1, "0");

      // 2 hours pass
      await th.fastForwardTime(7200, web3.currentProvider);

      const DUSDBalanceBefore = await debtToken.balanceOf(D.address);

      // D adjusts trove
      const debtTokenRequest_D = toBN(dec(40, 18));
      await borrowerOperations
        .connect(D)
        .adjustTrove(th._100pct, 0, debtTokenRequest_D, true, D.address, D.address);

      // Check D's debt token balance increased by their requested debt token
      const debtTokenBalanceAfter = await debtToken.balanceOf(D.address);
      assert.isTrue(debtTokenBalanceAfter.eq(D_DebtTOkenBalBefore.add(debtTokenRequest_D)));
    });

    it("adjustTrove(): reverts when calling address has no active trove", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(20000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: bob },
      });

      // Alice coll and debt increase(+1 FIL, +50 DebtToken)
      await borrowerOperations
        .connect(alice)
        .adjustTrove(th._100pct, 0, dec(50, 18), true, alice.address, alice.address, {
          value: dec(1, "ether"),
        });

      try {
        const txCarol = await borrowerOperations
          .connect(carol)
          .adjustTrove(th._100pct, 0, dec(50, 18), true, carol.address, carol.address, {
            value: dec(1, "ether"),
          });
        const receipt = await txCarol.wait();
        assert.equal(receipt.status, 0);
      } catch (err) {
        assert.include(err.message, "revert");
      }
    });

    it("adjustTrove(): reverts in Recovery Mode when the adjustment would reduce the TCR", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(20000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: bob },
      });

      assert.isFalse(await th.checkRecoveryMode(contracts));

      const txAlice = await borrowerOperations
        .connect(alice)
        .adjustTrove(th._100pct, 0, dec(50, 18), true, alice.address, alice.address, {
          value: dec(1, "ether"),
        });
      const receipt = await txAlice.wait();
      assert.equal(receipt.status, 1);

      await priceFeed.setPrice(dec(120, 18)); // trigger drop in FIL price

      assert.isTrue(await th.checkRecoveryMode(contracts));

      try {
        // collateral withdrawal should also fail
        const txAlice = await borrowerOperations
          .connect(alice)
          .adjustTrove(th._100pct, dec(1, "ether"), 0, false, alice.address, alice.address);
        const receipt = await txAlice.wait();
        assert.equal(receipt.status, 0);
      } catch (err) {
        assert.include(err.message, "revert");
      }

      try {
        // debt increase should fail
        const txBob = await borrowerOperations
          .connect(bob)
          .adjustTrove(th._100pct, 0, dec(50, 18), true, bob.address, bob.address);
        const receipt = await txBob.wait();
        assert.equal(receipt.status, 0);
      } catch (err) {
        assert.include(err.message, "revert");
      }

      try {
        // debt increase that's also a collateral increase should also fail, if ICR will be worse off
        const txBob = await borrowerOperations
          .connect(bob)
          .adjustTrove(th._100pct, 0, dec(111, 18), true, bob.address, bob.address, {
            value: dec(1, "ether"),
          });
        const receipt = await txBob.wait();
        assert.equal(receipt.status, 0);
      } catch (err) {
        assert.include(err.message, "revert");
      }
    });

    it("adjustTrove(): collateral withdrawal reverts in Recovery Mode", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(20000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: bob },
      });

      assert.isFalse(await th.checkRecoveryMode(contracts));

      await priceFeed.setPrice(dec(120, 18)); // trigger drop in FIL price

      assert.isTrue(await th.checkRecoveryMode(contracts));

      // Alice attempts an adjustment that repays half her debt BUT withdraws 1 wei collateral, and fails
      await assertRevert(
        borrowerOperations
          .connect(alice)
          .adjustTrove(th._100pct, 1, dec(5000, 18), false, alice.address, alice.address),
        "BorrowerOps: Collateral withdrawal not permitted Recovery Mode",
      );
    });

    it("adjustTrove(): debt increase that would leave ICR < 150% reverts in Recovery Mode", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(20000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: bob },
      });
      const CCR = await troveManager.CCR();

      assert.isFalse(await th.checkRecoveryMode(contracts));

      await priceFeed.setPrice(dec(120, 18)); // trigger drop in FIL price
      const price = await priceFeed.getPrice();

      assert.isTrue(await th.checkRecoveryMode(contracts));

      const ICR_A = await troveManager.getCurrentICR(alice.address, price);

      const aliceDebt = await getTroveEntireDebt(alice.address);
      const aliceColl = await getTroveEntireColl(alice.address);
      const debtIncrease = toBN(dec(50, 18));
      const collIncrease = toBN(dec(1, "ether"));

      // Check the new ICR would be an improvement, but less than the CCR (150%)
      const newICR = await troveManager.computeICR(
        aliceColl.add(collIncrease),
        aliceDebt.add(debtIncrease),
        price,
      );

      assert.isTrue(newICR.gt(ICR_A) && newICR.lt(CCR));

      await assertRevert(
        borrowerOperations
          .connect(alice)
          .adjustTrove(th._100pct, 0, debtIncrease, true, alice.address, alice.address, {
            value: collIncrease,
          }),
        "BorrowerOps: Operation must leave trove with ICR >= CCR",
      );
    });

    it("adjustTrove(): debt increase that would reduce the ICR reverts in Recovery Mode", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(3, 18)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: bob },
      });
      const CCR = await troveManager.CCR();

      assert.isFalse(await th.checkRecoveryMode(contracts));

      await priceFeed.setPrice(dec(105, 18)); // trigger drop in FIL price
      const price = await priceFeed.getPrice();

      assert.isTrue(await th.checkRecoveryMode(contracts));

      //--- Alice with ICR > 150% tries to reduce her ICR ---

      const ICR_A = await troveManager.getCurrentICR(alice.address, price);

      // Check Alice's initial ICR is above 150%
      assert.isTrue(ICR_A.gt(CCR));

      const aliceDebt = await getTroveEntireDebt(alice.address);
      const aliceColl = await getTroveEntireColl(alice.address);
      const aliceDebtIncrease = toBN(dec(150, 18));
      const aliceCollIncrease = toBN(dec(1, "ether"));

      const newICR_A = await troveManager.computeICR(
        aliceColl.add(aliceCollIncrease),
        aliceDebt.add(aliceDebtIncrease),
        price,
      );

      // Check Alice's new ICR would reduce but still be greater than 150%
      assert.isTrue(newICR_A.lt(ICR_A) && newICR_A.gt(CCR));

      await assertRevert(
        borrowerOperations
          .connect(alice)
          .adjustTrove(th._100pct, 0, aliceDebtIncrease, true, alice.address, alice.address, {
            value: aliceCollIncrease,
          }),
        "BorrowerOps: Cannot decrease your Trove's ICR in Recovery Mode",
      );

      //--- Bob with ICR < 150% tries to reduce his ICR ---

      const ICR_B = await troveManager.getCurrentICR(bob.address, price);

      // Check Bob's initial ICR is below 150%
      assert.isTrue(ICR_B.lt(CCR));

      const bobDebt = await getTroveEntireDebt(bob.address);
      const bobColl = await getTroveEntireColl(bob.address);
      const bobDebtIncrease = toBN(dec(450, 18));
      const bobCollIncrease = toBN(dec(1, "ether"));

      const newICR_B = await troveManager.computeICR(
        bobColl.add(bobCollIncrease),
        bobDebt.add(bobDebtIncrease),
        price,
      );

      // Check Bob's new ICR would reduce
      assert.isTrue(newICR_B.lt(ICR_B));

      await assertRevert(
        borrowerOperations
          .connect(bob)
          .adjustTrove(th._100pct, 0, bobDebtIncrease, true, bob.address, bob.address, {
            value: bobCollIncrease,
          }),
        "BorrowerOps: Operation must leave trove with ICR >= CCR",
      );
    });

    it("adjustTrove(): A trove with ICR < CCR in Recovery Mode can adjust their trove to ICR > CCR", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: bob },
      });
      const CCR = await troveManager.CCR();

      assert.isFalse(await th.checkRecoveryMode(contracts));

      await priceFeed.setPrice(dec(100, 18)); // trigger drop in FIL price
      const price = await priceFeed.getPrice();

      assert.isTrue(await th.checkRecoveryMode(contracts));

      const ICR_A = await troveManager.getCurrentICR(alice.address, price);
      // Check initial ICR is below 150%
      assert.isTrue(ICR_A.lt(CCR));

      const aliceDebt = await getTroveEntireDebt(alice.address);
      const aliceColl = await getTroveEntireColl(alice.address);
      const debtIncrease = toBN(dec(5000, 18));
      const collIncrease = toBN(dec(150, "ether"));

      const newICR = await troveManager.computeICR(
        aliceColl.add(collIncrease),
        aliceDebt.add(debtIncrease),
        price,
      );

      // Check new ICR would be > 150%
      assert.isTrue(newICR.gt(CCR));

      const tx = await borrowerOperations
        .connect(alice)
        .adjustTrove(th._100pct, 0, debtIncrease, true, alice.address, alice.address, {
          value: collIncrease,
        });
      const receipt = await tx.wait();
      assert.equal(receipt.status, 1);

      const actualNewICR = await troveManager.getCurrentICR(alice.address, price);
      assert.isTrue(actualNewICR.gt(CCR));
    });

    it("adjustTrove(): A trove with ICR > CCR in Recovery Mode can improve their ICR", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(3, 18)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: bob },
      });
      const CCR = await troveManager.CCR();

      assert.isFalse(await th.checkRecoveryMode(contracts));

      await priceFeed.setPrice(dec(105, 18)); // trigger drop in FIL price
      const price = await priceFeed.getPrice();

      assert.isTrue(await th.checkRecoveryMode(contracts));

      const initialICR = await troveManager.getCurrentICR(alice.address, price);
      // Check initial ICR is above 150%
      assert.isTrue(initialICR.gt(CCR));

      const aliceDebt = await getTroveEntireDebt(alice.address);
      const aliceColl = await getTroveEntireColl(alice.address);
      const debtIncrease = toBN(dec(5000, 18));
      const collIncrease = toBN(dec(150, "ether"));

      const newICR = await troveManager.computeICR(
        aliceColl.add(collIncrease),
        aliceDebt.add(debtIncrease),
        price,
      );

      // Check new ICR would be > old ICR
      assert.isTrue(newICR.gt(initialICR));

      const tx = await borrowerOperations
        .connect(alice)
        .adjustTrove(th._100pct, 0, debtIncrease, true, alice.address, alice.address, {
          value: collIncrease,
        });
      const receipt = await tx.wait();
      assert.equal(receipt.status, 1);

      const actualNewICR = await troveManager.getCurrentICR(alice.address, price);
      assert.isTrue(actualNewICR.gt(initialICR));
    });

    it("adjustTrove(): debt increase in Recovery Mode charges no fee", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(200000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: bob },
      });

      assert.isFalse(await th.checkRecoveryMode(contracts));

      await priceFeed.setPrice(dec(120, 18)); // trigger drop in FIL price

      assert.isTrue(await th.checkRecoveryMode(contracts));

      // B stakes ProtocolToken
      await protocolToken.unprotectedMint(bob.address, dec(100, 18));
      await protocolTokenStaking.connect(bob).stake(dec(100, 18));

      const protocolTokenStakingDebtTokenBalanceBefore = await debtToken.balanceOf(
        protocolTokenStaking.address,
      );
      assert.isTrue(protocolTokenStakingDebtTokenBalanceBefore.gt(toBN("0")));

      const txAlice = await borrowerOperations
        .connect(alice)
        .adjustTrove(th._100pct, 0, dec(50, 18), true, alice.address, alice.address, {
          value: dec(100, "ether"),
        });
      const receipt = await txAlice.wait();
      assert.equal(receipt.status, 1);

      // Check emitted fee = 0
      const emittedFee = toBN(
        await th.getEventArgByName(txAlice, "DebtTokenBorrowingFeePaid", "_debtTokenFee"),
      );
      assert.isTrue(emittedFee.eq(toBN("0")));

      assert.isTrue(await th.checkRecoveryMode(contracts));

      // Check no fee was sent to staking contract
      const protocolTokenStakingdebtTokenBalanceAfter = await debtToken.balanceOf(
        protocolTokenStaking.address,
      );
      assert.equal(
        protocolTokenStakingdebtTokenBalanceAfter.toString(),
        protocolTokenStakingDebtTokenBalanceBefore.toString(),
      );
    });

    it("adjustTrove(): reverts when change would cause the TCR of the system to fall below the CCR", async () => {
      await priceFeed.setPrice(dec(100, 18));

      await openTrove({ ICR: toBN(dec(15, 17)), extraParams: { from: alice } });
      await openTrove({ ICR: toBN(dec(15, 17)), extraParams: { from: bob } });

      // Check TCR and Recovery Mode
      const TCR = (await th.getTCR(contracts)).toString();
      assert.equal(TCR, "1500000000000000000");
      assert.isFalse(await th.checkRecoveryMode(contracts));

      // Bob attempts an operation that would bring the TCR below the CCR
      try {
        const txBob = await borrowerOperations
          .connect(bob)
          .adjustTrove(th._100pct, 0, dec(1, 18), true, bob.address, bob.address);
        const receipt = await txBob.wait();
        assert.equal(receipt.status, 0);
      } catch (err) {
        assert.include(err.message, "revert");
      }
    });

    it("adjustTrove(): reverts when debt token repaid is > debt of the trove", async () => {
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: alice } });
      const bobOpenTx = (await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: bob } })).tx;

      const bobDebt = await getTroveEntireDebt(bob.address);
      assert.isTrue(bobDebt.gt(toBN("0")));

      const test = await th.getEventArgByIndex(bobOpenTx, "DebtTokenBorrowingFeePaid", 1);
      const bobFee = toBN(await th.getEventArgByIndex(bobOpenTx, "DebtTokenBorrowingFeePaid", 1));

      assert.isTrue(bobFee.gt(toBN("0")));

      // Alice transfers debt token to bob to compensate borrowing fees
      await debtToken.connect(alice).transfer(bob.address, bobFee);

      const remainingDebt = (await troveManager.getTroveDebt(bob.address)).sub(GAS_COMPENSATION);

      // Bob attempts an adjustment that would repay 1 wei more than his debt
      await assertRevert(
        borrowerOperations
          .connect(bob)
          .adjustTrove(th._100pct, 0, remainingDebt.add(toBN(1)), false, bob.address, bob.address, {
            value: dec(1, "ether"),
          }),
        "revert",
      );
    });

    it("adjustTrove(): reverts when attempted FIL withdrawal is >= the trove's collateral", async () => {
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: alice } });
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: bob } });
      await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: carol } });

      const carolColl = await getTroveEntireColl(carol.address);

      // Carol attempts an adjustment that would withdraw 1 wei more than her FIL
      try {
        const txCarol = await borrowerOperations
          .connect(carol)
          .adjustTrove(th._100pct, carolColl.add(toBN(1)), 0, true, carol.address, carol.address);
        const receipt = await txCarol.wait();
        assert.equal(receipt.status, 0);
      } catch (err) {
        assert.include(err.message, "revert");
      }
    });

    it("adjustTrove(): reverts when change would cause the ICR of the trove to fall below the MCR", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(100, 18)),
        extraParams: { from: whale },
      });

      await priceFeed.setPrice(dec(100, 18));

      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(11, 17)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(11, 17)),
        extraParams: { from: bob },
      });

      // Bob attempts to increase debt by 100 debt tokens and 1 ether, i.e. a change that constitutes a 100% ratio of coll:debt.
      // Since his ICR prior is 110%, this change would reduce his ICR below MCR.
      try {
        const txBob = await borrowerOperations
          .connect(bob)
          .adjustTrove(th._100pct, 0, dec(100, 18), true, bob.address, bob.address, {
            value: dec(1, "ether"),
          });
        assert.isFalse(txBob.receipt.status);
      } catch (err) {
        assert.include(err.message, "revert");
      }
    });

    it("adjustTrove(): With 0 coll change, doesnt change borrower's coll or ActivePool coll", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });

      const aliceCollBefore = await getTroveEntireColl(alice.address);
      const activePoolCollBefore = await activePool.getFIL();

      assert.isTrue(aliceCollBefore.gt(toBN("0")));
      assert.isTrue(aliceCollBefore.eq(activePoolCollBefore));

      // Alice adjusts trove. No coll change, and a debt increase (+50 tokens)
      await borrowerOperations
        .connect(alice)
        .adjustTrove(th._100pct, 0, dec(50, 18), true, alice.address, alice.address, {
          value: 0,
        });

      const aliceCollAfter = await getTroveEntireColl(alice.address);
      const activePoolCollAfter = await activePool.getFIL();

      assert.isTrue(aliceCollAfter.eq(activePoolCollAfter));
      assert.isTrue(activePoolCollAfter.eq(activePoolCollAfter));
    });

    it("adjustTrove(): With 0 debt change, doesnt change borrower's debt or ActivePool debt", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });

      const aliceDebtBefore = await getTroveEntireDebt(alice.address);
      const activePoolDebtBefore = await activePool.getDebt();

      assert.isTrue(aliceDebtBefore.gt(toBN("0")));
      assert.isTrue(aliceDebtBefore.eq(activePoolDebtBefore));

      // Alice adjusts trove. Coll change, no debt change
      await borrowerOperations
        .connect(alice)
        .adjustTrove(th._100pct, 0, 0, false, alice.address, alice.address, {
          value: dec(1, "ether"),
        });

      const aliceDebtAfter = await getTroveEntireDebt(alice.address);
      const activePoolDebtAfter = await activePool.getDebt();

      assert.isTrue(aliceDebtAfter.eq(aliceDebtBefore));
      assert.isTrue(activePoolDebtAfter.eq(activePoolDebtBefore));
    });

    it("adjustTrove(): updates borrower's debt and coll with an increase in both", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });

      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: alice },
      });

      const debtBefore = await getTroveEntireDebt(alice.address);
      const collBefore = await getTroveEntireColl(alice.address);
      assert.isTrue(debtBefore.gt(toBN("0")));
      assert.isTrue(collBefore.gt(toBN("0")));

      // Alice adjusts trove. Coll and debt increase(+1 FIL, +50 tokens)
      await borrowerOperations
        .connect(alice)
        .adjustTrove(
          th._100pct,
          0,
          await getNetBorrowingAmount(dec(50, 18)),
          true,
          alice.address,
          alice.address,
          { value: dec(1, "ether") },
        );

      const debtAfter = await getTroveEntireDebt(alice.address);
      const collAfter = await getTroveEntireColl(alice.address);

      th.assertIsApproximatelyEqual(debtAfter, debtBefore.add(toBN(dec(50, 18))), 10000);
      th.assertIsApproximatelyEqual(collAfter, collBefore.add(toBN(dec(1, 18))), 10000);
    });

    it("adjustTrove(): updates borrower's debt and coll with a decrease in both", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });

      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: alice },
      });

      const debtBefore = await getTroveEntireDebt(alice.address);
      const collBefore = await getTroveEntireColl(alice.address);
      assert.isTrue(debtBefore.gt(toBN("0")));
      assert.isTrue(collBefore.gt(toBN("0")));

      // Alice adjusts trove coll and debt decrease (-0.5 FIL, -50 tokens)
      await borrowerOperations
        .connect(alice)
        .adjustTrove(
          th._100pct,
          dec(500, "finney"),
          dec(50, 18),
          false,
          alice.address,
          alice.address,
        );

      const debtAfter = await getTroveEntireDebt(alice.address);
      const collAfter = await getTroveEntireColl(alice.address);

      assert.isTrue(debtAfter.eq(debtBefore.sub(toBN(dec(50, 18)))));
      assert.isTrue(collAfter.eq(collBefore.sub(toBN(dec(5, 17)))));
    });

    it("adjustTrove(): updates borrower's  debt and coll with coll increase, debt decrease", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });

      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: alice },
      });

      const debtBefore = await getTroveEntireDebt(alice.address);
      const collBefore = await getTroveEntireColl(alice.address);
      assert.isTrue(debtBefore.gt(toBN("0")));
      assert.isTrue(collBefore.gt(toBN("0")));

      // Alice adjusts trove - coll increase and debt decrease (+0.5 FIL, -50 tokens)
      await borrowerOperations
        .connect(alice)
        .adjustTrove(th._100pct, 0, dec(50, 18), false, alice.address, alice.address, {
          value: dec(500, "finney"),
        });

      const debtAfter = await getTroveEntireDebt(alice.address);
      const collAfter = await getTroveEntireColl(alice.address);

      th.assertIsApproximatelyEqual(debtAfter, debtBefore.sub(toBN(dec(50, 18))), 10000);
      th.assertIsApproximatelyEqual(collAfter, collBefore.add(toBN(dec(5, 17))), 10000);
    });

    it("adjustTrove(): updates borrower's debt and coll with coll decrease, debt increase", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });

      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: alice },
      });

      const debtBefore = await getTroveEntireDebt(alice.address);
      const collBefore = await getTroveEntireColl(alice.address);
      assert.isTrue(debtBefore.gt(toBN("0")));
      assert.isTrue(collBefore.gt(toBN("0")));

      // Alice adjusts trove - coll decrease and debt increase (0.1 FIL, 10 tokens)
      await borrowerOperations
        .connect(alice)
        .adjustTrove(
          th._100pct,
          dec(1, 17),
          await getNetBorrowingAmount(dec(1, 18)),
          true,
          alice.address,
          alice.address,
        );

      const debtAfter = await getTroveEntireDebt(alice.address);
      const collAfter = await getTroveEntireColl(alice.address);

      th.assertIsApproximatelyEqual(debtAfter, debtBefore.add(toBN(dec(1, 18))), 10000);
      th.assertIsApproximatelyEqual(collAfter, collBefore.sub(toBN(dec(1, 17))), 10000);
    });

    it("adjustTrove(): updates borrower's stake and totalStakes with a coll increase", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });

      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: alice },
      });

      const stakeBefore = await troveManager.getTroveStake(alice.address);
      const totalStakesBefore = await troveManager.totalStakes();
      assert.isTrue(stakeBefore.gt(toBN("0")));
      assert.isTrue(totalStakesBefore.gt(toBN("0")));

      // Alice adjusts trove - coll and debt increase (+1 FIL, +50 tokens)
      await borrowerOperations
        .connect(alice)
        .adjustTrove(th._100pct, 0, dec(50, 18), true, alice.address, alice.address, {
          value: dec(1, "ether"),
        });

      const stakeAfter = await troveManager.getTroveStake(alice.address);
      const totalStakesAfter = await troveManager.totalStakes();

      assert.isTrue(stakeAfter.eq(stakeBefore.add(toBN(dec(1, 18)))));
      assert.isTrue(totalStakesAfter.eq(totalStakesBefore.add(toBN(dec(1, 18)))));
    });

    it("adjustTrove(): updates borrower's stake and totalStakes with a coll decrease", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });

      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: alice },
      });

      const stakeBefore = await troveManager.getTroveStake(alice.address);
      const totalStakesBefore = await troveManager.totalStakes();
      assert.isTrue(stakeBefore.gt(toBN("0")));
      assert.isTrue(totalStakesBefore.gt(toBN("0")));

      // Alice adjusts trove - coll decrease and debt decrease
      await borrowerOperations
        .connect(alice)
        .adjustTrove(
          th._100pct,
          dec(500, "finney"),
          dec(50, 18),
          false,
          alice.address,
          alice.address,
        );

      const stakeAfter = await troveManager.getTroveStake(alice.address);
      const totalStakesAfter = await troveManager.totalStakes();

      assert.isTrue(stakeAfter.eq(stakeBefore.sub(toBN(dec(5, 17)))));
      assert.isTrue(totalStakesAfter.eq(totalStakesBefore.sub(toBN(dec(5, 17)))));
    });

    it("adjustTrove(): changes DebtToken balance by the requested decrease", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });

      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: alice },
      });

      const alice_DebtTokenBalance_Before = await debtToken.balanceOf(alice.address);
      assert.isTrue(alice_DebtTokenBalance_Before.gt(toBN("0")));

      // Alice adjusts trove - coll decrease and debt decrease
      await borrowerOperations
        .connect(alice)
        .adjustTrove(
          th._100pct,
          dec(100, "finney"),
          dec(10, 18),
          false,
          alice.address,
          alice.address,
        );

      // check after
      const alice_DebtTokenBalance_After = await debtToken.balanceOf(alice.address);
      assert.isTrue(
        alice_DebtTokenBalance_After.eq(alice_DebtTokenBalance_Before.sub(toBN(dec(10, 18)))),
      );
    });

    it("adjustTrove(): changes DebtToken balance by the requested increase", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });

      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: alice },
      });

      const alice_DebtTokenBalance_Before = await debtToken.balanceOf(alice.address);
      assert.isTrue(alice_DebtTokenBalance_Before.gt(toBN("0")));

      // Alice adjusts trove - coll increase and debt increase
      await borrowerOperations
        .connect(alice)
        .adjustTrove(th._100pct, 0, dec(100, 18), true, alice.address, alice.address, {
          value: dec(1, "ether"),
        });

      // check after
      const alice_DebtTokenBalance_After = await debtToken.balanceOf(alice.address);
      assert.isTrue(
        alice_DebtTokenBalance_After.eq(alice_DebtTokenBalance_Before.add(toBN(dec(100, 18)))),
      );
    });

    it("adjustTrove(): Changes the activePool FIL and raw ether balance by the requested decrease", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });

      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: alice },
      });

      const activePool_FIL_Before = await activePool.getFIL();
      const activePool_RawEther_Before = toBN(await web3.eth.getBalance(activePool.address));
      assert.isTrue(activePool_FIL_Before.gt(toBN("0")));
      assert.isTrue(activePool_RawEther_Before.gt(toBN("0")));

      // Alice adjusts trove - coll decrease and debt decrease
      await borrowerOperations
        .connect(alice)
        .adjustTrove(
          th._100pct,
          dec(100, "finney"),
          dec(10, 18),
          false,
          alice.address,
          alice.address,
        );

      const activePool_FIL_After = await activePool.getFIL();
      const activePool_RawEther_After = toBN(await web3.eth.getBalance(activePool.address));
      assert.isTrue(activePool_FIL_After.eq(activePool_FIL_Before.sub(toBN(dec(1, 17)))));
      assert.isTrue(activePool_RawEther_After.eq(activePool_FIL_Before.sub(toBN(dec(1, 17)))));
    });

    it("adjustTrove(): Changes the activePool FIL and raw ether balance by the amount of FIL sent", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });

      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: alice },
      });

      const activePool_FIL_Before = await activePool.getFIL();
      const activePool_RawEther_Before = toBN(await web3.eth.getBalance(activePool.address));
      assert.isTrue(activePool_FIL_Before.gt(toBN("0")));
      assert.isTrue(activePool_RawEther_Before.gt(toBN("0")));

      // Alice adjusts trove - coll increase and debt increase
      await borrowerOperations
        .connect(alice)
        .adjustTrove(th._100pct, 0, dec(100, 18), true, alice.address, alice.address, {
          value: dec(1, "ether"),
        });

      const activePool_FIL_After = await activePool.getFIL();
      const activePool_RawEther_After = toBN(await web3.eth.getBalance(activePool.address));
      assert.isTrue(activePool_FIL_After.eq(activePool_FIL_Before.add(toBN(dec(1, 18)))));
      assert.isTrue(activePool_RawEther_After.eq(activePool_FIL_Before.add(toBN(dec(1, 18)))));
    });

    it("adjustTrove(): Changes the debt in ActivePool by requested decrease", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });

      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: alice },
      });

      const activePool_debt_Before = await activePool.getDebt();
      assert.isTrue(activePool_debt_Before.gt(toBN("0")));

      // Alice adjusts trove - coll increase and debt decrease
      await borrowerOperations
        .connect(alice)
        .adjustTrove(th._100pct, 0, dec(30, 18), false, alice.address, alice.address, {
          value: dec(1, "ether"),
        });

      const activePool_debt_After = await activePool.getDebt();
      assert.isTrue(activePool_debt_After.eq(activePool_debt_Before.sub(toBN(dec(30, 18)))));
    });

    it("adjustTrove(): Changes the debt in ActivePool by requested increase", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: alice },
      });

      const activePool_debt_Before = await activePool.getDebt();
      assert.isTrue(activePool_debt_Before.gt(toBN("0")));

      // Alice adjusts trove - coll increase and debt increase
      await borrowerOperations
        .connect(alice)
        .adjustTrove(
          th._100pct,
          0,
          await getNetBorrowingAmount(dec(100, 18)),
          true,
          alice.address,
          alice.address,
          { value: dec(1, "ether") },
        );

      const activePool_debt_After = await activePool.getDebt();

      th.assertIsApproximatelyEqual(
        activePool_debt_After,
        activePool_debt_Before.add(toBN(dec(100, 18))),
      );
    });

    it("adjustTrove(): new coll = 0 and new debt = 0 is not allowed, as gas compensation still counts toward ICR", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });

      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: alice },
      });
      const aliceColl = await getTroveEntireColl(alice.address);
      const aliceDebt = await getTroveEntireColl(alice.address);
      const status_Before = await troveManager.getTroveStatus(alice.address);
      const isInSortedList_Before = await sortedTroves.contains(alice.address);

      assert.equal(status_Before, 1); // 1: Active
      assert.isTrue(isInSortedList_Before);

      await assertRevert(
        borrowerOperations
          .connect(alice)
          .adjustTrove(th._100pct, aliceColl, aliceDebt, true, alice.address, alice.address),
        "BorrowerOps: An operation that would result in ICR < MCR is not permitted",
      );
    });

    it("adjustTrove(): Reverts if requested debt increase and amount is zero", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: alice },
      });

      await assertRevert(
        borrowerOperations
          .connect(alice)
          .adjustTrove(th._100pct, 0, 0, true, alice.address, alice.address),
        "BorrowerOps: Debt increase requires non-zero debtChange",
      );
    });

    it("adjustTrove(): Reverts if requested coll withdrawal and ether is sent", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: alice },
      });

      await assertRevert(
        borrowerOperations
          .connect(alice)
          .adjustTrove(
            th._100pct,
            dec(1, "ether"),
            dec(100, 18),
            true,
            alice.address,
            alice.address,
            {
              value: dec(3, "ether"),
            },
          ),
        "BorrowerOps: Cannot withdraw and add coll",
      );
    });

    it("adjustTrove(): Reverts if it's zero adjustment", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: alice },
      });

      await assertRevert(
        borrowerOperations
          .connect(alice)
          .adjustTrove(th._100pct, 0, 0, false, alice.address, alice.address),
        "BorrowerOps: There must be either a collateral change or a debt change",
      );
    });

    it("adjustTrove(): Reverts if requested coll withdrawal is greater than trove's collateral", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: alice },
      });

      const aliceColl = await getTroveEntireColl(alice.address);

      // Requested coll withdrawal > coll in the trove
      await assertRevert(
        borrowerOperations
          .connect(alice)
          .adjustTrove(th._100pct, aliceColl.add(toBN(1)), 0, false, alice.address, alice.address),
      );
      await assertRevert(
        borrowerOperations
          .connect(bob)
          .adjustTrove(
            th._100pct,
            aliceColl.add(toBN(dec(37, "ether"))),
            0,
            false,
            bob.address,
            bob.address,
          ),
      );
    });

    it("adjustTrove(): Reverts if borrower has insufficient debt token balance to cover his debt repayment", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: B },
      });
      const bobDebt = await getTroveEntireDebt(B.address);

      // Bob transfers some debt token to carol
      await debtToken.connect(B).transfer(C.address, dec(10, 18));

      //Confirm B's debt token balance is less than 50 tokens
      const B_DebtTokenBal = await debtToken.balanceOf(B.address);
      assert.isTrue(B_DebtTokenBal.lt(bobDebt));

      const repayDebtTokenPromise_B = borrowerOperations
        .connect(B)
        .adjustTrove(th._100pct, 0, bobDebt, false, B.address, B.address);

      // B attempts to repay all his debt
      await assertRevert(repayDebtTokenPromise_B, "revert");
    });

    // --- closeTrove() ---

    it("closeTrove(): reverts when it would lower the TCR below CCR", async () => {
      await openTrove({ ICR: toBN(dec(300, 16)), extraParams: { from: alice } });
      await openTrove({
        ICR: toBN(dec(120, 16)),
        extraDebtTokenAmount: toBN(dec(300, 18)),
        extraParams: { from: bob },
      });

      const price = await priceFeed.getPrice();

      // to compensate borrowing fees
      await debtToken.connect(bob).transfer(alice.address, dec(300, 18));

      assert.isFalse(await troveManager.checkRecoveryMode(price));

      await assertRevert(
        borrowerOperations.connect(alice).closeTrove(),
        "BorrowerOps: An operation that would result in TCR < CCR is not permitted",
      );
    });

    it("closeTrove(): reverts when calling address does not have active trove", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: bob },
      });

      // Carol with no active trove attempts to close her trove
      try {
        const txCarol = await borrowerOperations.connect(carol).closeTrove();
        const receipt = await txCarol.wait();
        assert.equal(receipt.status, 0);
      } catch (err) {
        assert.include(err.message, "revert");
      }
    });

    it("closeTrove(): reverts when system is in Recovery Mode", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(100000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: bob },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: carol },
      });

      // Alice transfers her debt token to Bob and Carol so they can cover fees
      const aliceBal = await debtToken.balanceOf(alice.address);
      await debtToken.connect(alice).transfer(bob.address, aliceBal.div(toBN(2)));
      await debtToken.connect(alice).transfer(carol.address, aliceBal.div(toBN(2)));

      // check Recovery Mode
      assert.isFalse(await th.checkRecoveryMode(contracts));

      // Bob successfully closes his trove
      const txBob = await borrowerOperations.connect(bob).closeTrove();
      const receiptBob = await txBob.wait();
      assert.equal(receiptBob.status, 1);

      await priceFeed.setPrice(dec(100, 18));

      assert.isTrue(await th.checkRecoveryMode(contracts));

      // Carol attempts to close her trove during Recovery Mode
      await assertRevert(
        borrowerOperations.connect(carol).closeTrove(),
        "BorrowerOps: Operation not permitted during Recovery Mode",
      );
    });

    it("closeTrove(): reverts when trove is the only one in the system", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(100000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });

      // Artificially mint to Alice so she has enough to close her trove
      await debtToken.unprotectedMint(alice.address, dec(100000, 18));

      // Check she has more debt token than her trove debt
      const aliceBal = await debtToken.balanceOf(alice.address);
      const aliceDebt = await getTroveEntireDebt(alice.address);
      assert.isTrue(aliceBal.gt(aliceDebt));

      // check Recovery Mode
      assert.isFalse(await th.checkRecoveryMode(contracts));

      // Alice attempts to close her trove
      await assertRevert(
        borrowerOperations.connect(alice).closeTrove(),
        "TroveManager: Only one trove in the system",
      );
    });

    it("closeTrove(): reduces a Trove's collateral to zero", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: dennis },
      });

      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });

      const aliceCollBefore = await getTroveEntireColl(alice.address);
      const dennisDebtToken = await debtToken.balanceOf(dennis.address);
      assert.isTrue(aliceCollBefore.gt(toBN("0")));
      assert.isTrue(dennisDebtToken.gt(toBN("0")));

      // To compensate borrowing fees
      await debtToken.connect(dennis).transfer(alice.address, dennisDebtToken.div(toBN(2)));

      // Alice attempts to close trove
      await borrowerOperations.connect(alice).closeTrove();

      const aliceCollAfter = await getTroveEntireColl(alice.address);
      assert.equal(aliceCollAfter, "0");
    });

    it("closeTrove(): reduces a Trove's debt to zero", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: dennis },
      });

      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });

      const aliceDebtBefore = await getTroveEntireColl(alice.address);
      const dennisDebtToken = await debtToken.balanceOf(dennis.address);
      assert.isTrue(aliceDebtBefore.gt(toBN("0")));
      assert.isTrue(dennisDebtToken.gt(toBN("0")));

      // To compensate borrowing fees
      await debtToken.connect(dennis).transfer(alice.address, dennisDebtToken.div(toBN(2)));

      // Alice attempts to close trove
      await borrowerOperations.connect(alice).closeTrove();

      const aliceCollAfter = await getTroveEntireColl(alice.address);
      assert.equal(aliceCollAfter, "0");
    });

    it("closeTrove(): sets Trove's stake to zero", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: dennis },
      });

      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });

      const aliceStakeBefore = await getTroveStake(alice.address);
      assert.isTrue(aliceStakeBefore.gt(toBN("0")));

      const dennisDebtToken = await debtToken.balanceOf(dennis.address);
      assert.isTrue(aliceStakeBefore.gt(toBN("0")));
      assert.isTrue(dennisDebtToken.gt(toBN("0")));

      // To compensate borrowing fees
      await debtToken.connect(dennis).transfer(alice.address, dennisDebtToken.div(toBN(2)));

      // Alice attempts to close trove
      await borrowerOperations.connect(alice).closeTrove();

      const stakeAfter = (await troveManager.Troves(alice.address))[2].toString();
      assert.equal(stakeAfter, "0");
      // check withdrawal was successful
    });

    it("closeTrove(): zero's the troves reward snapshots", async () => {
      // Dennis opens trove and transfers tokens to alice
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: dennis },
      });

      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: bob },
      });

      // Price drops
      await priceFeed.setPrice(dec(100, 18));

      // Liquidate Bob
      await troveManager.liquidate(bob.address);
      assert.isFalse(await sortedTroves.contains(bob.address));

      // Price bounces back
      await priceFeed.setPrice(dec(200, 18));

      // Alice and Carol open troves
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: carol },
      });

      // Price drops ...again
      await priceFeed.setPrice(dec(100, 18));

      // Get Alice's pending reward snapshots
      const L_FIL_A_Snapshot = (await troveManager.rewardSnapshots(alice.address))[0];
      const L_Debt_A_Snapshot = (await troveManager.rewardSnapshots(alice.address))[1];
      assert.isTrue(L_FIL_A_Snapshot.gt(toBN("0")));
      assert.isTrue(L_Debt_A_Snapshot.gt(toBN("0")));

      // Liquidate Carol
      await troveManager.liquidate(carol.address);
      assert.isFalse(await sortedTroves.contains(carol.address));

      // Get Alice's pending reward snapshots after Carol's liquidation. Check above 0
      const L_FIL_Snapshot_A_AfterLiquidation = (
        await troveManager.rewardSnapshots(alice.address)
      )[0];
      const L_Debt_Snapshot_A_AfterLiquidation = (
        await troveManager.rewardSnapshots(alice.address)
      )[1];

      assert.isTrue(L_FIL_Snapshot_A_AfterLiquidation.gt(toBN("0")));
      assert.isTrue(L_Debt_Snapshot_A_AfterLiquidation.gt(toBN("0")));

      // to compensate borrowing fees
      await debtToken
        .connect(dennis)
        .transfer(alice.address, await debtToken.balanceOf(dennis.address));

      await priceFeed.setPrice(dec(200, 18));

      // Alice closes trove
      await borrowerOperations.connect(alice).closeTrove();

      // Check Alice's pending reward snapshots are zero
      const L_FIL_Snapshot_A_afterAliceCloses = (
        await troveManager.rewardSnapshots(alice.address)
      )[0];
      const L_Debt_Snapshot_A_afterAliceCloses = (
        await troveManager.rewardSnapshots(alice.address)
      )[1];

      assert.equal(L_FIL_Snapshot_A_afterAliceCloses, "0");
      assert.equal(L_Debt_Snapshot_A_afterAliceCloses, "0");
    });

    it("closeTrove(): sets trove's status to closed and removes it from sorted troves list", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: dennis },
      });

      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });

      // Check Trove is active
      const alice_Trove_Before = await troveManager.Troves(alice.address);
      const status_Before = alice_Trove_Before[3];

      assert.equal(status_Before, 1);
      assert.isTrue(await sortedTroves.contains(alice.address));

      // to compensate borrowing fees
      await debtToken
        .connect(dennis)
        .transfer(alice.address, await debtToken.balanceOf(dennis.address));

      // Close the trove
      await borrowerOperations.connect(alice).closeTrove();

      const alice_Trove_After = await troveManager.Troves(alice.address);
      const status_After = alice_Trove_After[3];

      assert.equal(status_After, 2);
      assert.isFalse(await sortedTroves.contains(alice.address));
    });

    it("closeTrove(): reduces ActivePool FIL and raw ether by correct amount", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: dennis },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });

      const dennisColl = await getTroveEntireColl(dennis.address);
      const aliceColl = await getTroveEntireColl(alice.address);
      assert.isTrue(dennisColl.gt("0"));
      assert.isTrue(aliceColl.gt("0"));

      // Check active Pool FIL before
      const activePool_FIL_before = await activePool.getFIL();
      const activePool_RawEther_before = toBN(await web3.eth.getBalance(activePool.address));
      assert.isTrue(activePool_FIL_before.eq(aliceColl.add(dennisColl)));
      assert.isTrue(activePool_FIL_before.gt(toBN("0")));
      assert.isTrue(activePool_RawEther_before.eq(activePool_FIL_before));

      // to compensate borrowing fees
      await debtToken
        .connect(dennis)
        .transfer(alice.address, await debtToken.balanceOf(dennis.address));

      // Close the trove
      await borrowerOperations.connect(alice).closeTrove();

      // Check after
      const activePool_FIL_After = await activePool.getFIL();
      const activePool_RawEther_After = toBN(await web3.eth.getBalance(activePool.address));
      assert.isTrue(activePool_FIL_After.eq(dennisColl));
      assert.isTrue(activePool_RawEther_After.eq(dennisColl));
    });

    it("closeTrove(): reduces ActivePool debt by correct amount", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: dennis },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });

      const dennisDebt = await getTroveEntireDebt(dennis.address);
      const aliceDebt = await getTroveEntireDebt(alice.address);
      assert.isTrue(dennisDebt.gt("0"));
      assert.isTrue(aliceDebt.gt("0"));

      // Check before
      const activePool_Debt_before = await activePool.getDebt();
      assert.isTrue(activePool_Debt_before.eq(aliceDebt.add(dennisDebt)));
      assert.isTrue(activePool_Debt_before.gt(toBN("0")));

      // to compensate borrowing fees
      await debtToken
        .connect(dennis)
        .transfer(alice.address, await debtToken.balanceOf(dennis.address));

      // Close the trove
      await borrowerOperations.connect(alice).closeTrove();

      // Check after
      const activePool_Debt_After = (await activePool.getDebt()).toString();
      th.assertIsApproximatelyEqual(activePool_Debt_After, dennisDebt);
    });

    it("closeTrove(): updates the the total stakes", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: dennis },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: bob },
      });

      // Get individual stakes
      const aliceStakeBefore = await getTroveStake(alice.address);
      const bobStakeBefore = await getTroveStake(bob.address);
      const dennisStakeBefore = await getTroveStake(dennis.address);
      assert.isTrue(aliceStakeBefore.gt("0"));
      assert.isTrue(bobStakeBefore.gt("0"));
      assert.isTrue(dennisStakeBefore.gt("0"));

      const totalStakesBefore = await troveManager.totalStakes();

      assert.isTrue(
        totalStakesBefore.eq(aliceStakeBefore.add(bobStakeBefore).add(dennisStakeBefore)),
      );

      // to compensate borrowing fees
      await debtToken
        .connect(dennis)
        .transfer(alice.address, await debtToken.balanceOf(dennis.address));

      // Alice closes trove
      await borrowerOperations.connect(alice).closeTrove();

      // Check stake and total stakes get updated
      const aliceStakeAfter = await getTroveStake(alice.address);
      const totalStakesAfter = await troveManager.totalStakes();

      assert.equal(aliceStakeAfter, 0);
      assert.isTrue(totalStakesAfter.eq(totalStakesBefore.sub(aliceStakeBefore)));
    });

    if (!withProxy) {
      // TODO: wrap web3.eth.getBalance to be able to go through proxies
      it("closeTrove(): sends the correct amount of FIL to the user", async () => {
        await openTrove({
          extraDebtTokenAmount: toBN(dec(10000, 18)),
          ICR: toBN(dec(2, 18)),
          extraParams: { from: dennis },
        });
        await openTrove({
          extraDebtTokenAmount: toBN(dec(10000, 18)),
          ICR: toBN(dec(2, 18)),
          extraParams: { from: alice },
        });

        const aliceColl = await getTroveEntireColl(alice.address);
        assert.isTrue(aliceColl.gt(toBN("0")));

        const alice_FILBalance_Before = toBN(await web3.eth.getBalance(alice.address));

        // to compensate borrowing fees
        await debtToken
          .connect(dennis)
          .transfer(alice.address, await debtToken.balanceOf(dennis.address));

        await borrowerOperations.connect(alice).closeTrove({ gasPrice: 0 });

        const alice_FILBalance_After = toBN(await web3.eth.getBalance(alice.address));
        const balanceDiff = alice_FILBalance_After.sub(alice_FILBalance_Before);

        assert.isTrue(balanceDiff.eq(aliceColl));
      });
    }

    it("closeTrove(): subtracts the debt of the closed Trove from the Borrower's DebtToken balance", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: dennis },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });

      const aliceDebt = await getTroveEntireDebt(alice.address);
      assert.isTrue(aliceDebt.gt(toBN("0")));

      // to compensate borrowing fees
      await debtToken
        .connect(dennis)
        .transfer(alice.address, await debtToken.balanceOf(dennis.address));

      const alice_DebtTokenBalance_Before = await debtToken.balanceOf(alice.address);
      assert.isTrue(alice_DebtTokenBalance_Before.gt(toBN("0")));

      // close trove
      await borrowerOperations.connect(alice).closeTrove();

      // check alice debt token balance after
      const alice_DebtTokenBalance_After = await debtToken.balanceOf(alice.address);
      th.assertIsApproximatelyEqual(
        alice_DebtTokenBalance_After,
        alice_DebtTokenBalance_Before.sub(aliceDebt.sub(GAS_COMPENSATION)),
      );
    });

    it("closeTrove(): applies pending rewards", async () => {
      // --- SETUP ---
      await openTrove({
        extraDebtTokenAmount: toBN(dec(1000000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });
      const whaleDebt = await getTroveEntireDebt(whale.address);
      const whaleColl = await getTroveEntireColl(whale.address);

      await openTrove({
        extraDebtTokenAmount: toBN(dec(15000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: bob },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: carol },
      });

      const carolDebt = await getTroveEntireDebt(carol.address);
      const carolColl = await getTroveEntireColl(carol.address);

      // Whale transfers to A and B to cover their fees
      await debtToken.connect(whale).transfer(alice.address, dec(10000, 18));
      await debtToken.connect(whale).transfer(bob.address, dec(10000, 18));

      // --- TEST ---

      // price drops to 1FIL:100DebtToken, reducing Carol's ICR below MCR
      await priceFeed.setPrice(dec(100, 18));
      const price = await priceFeed.getPrice();

      // liquidate Carol's Trove, Alice and Bob earn rewards.
      const liquidationTx = await troveManager.connect(owner).liquidate(carol.address);
      const [liquidatedDebt_C, liquidatedColl_C, gasComp_C] =
        await th.getEmittedLiquidationValues(liquidationTx);

      // Dennis opens a new Trove
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: carol },
      });

      // check Alice and Bob's reward snapshots are zero before they alter their Troves
      const alice_rewardSnapshot_Before = await troveManager.rewardSnapshots(alice.address);
      const alice_FILrewardSnapshot_Before = alice_rewardSnapshot_Before[0];
      const alice_DebtRewardSnapshot_Before = alice_rewardSnapshot_Before[1];

      const bob_rewardSnapshot_Before = await troveManager.rewardSnapshots(bob.address);
      const bob_FILrewardSnapshot_Before = bob_rewardSnapshot_Before[0];
      const bob_DebtRewardSnapshot_Before = bob_rewardSnapshot_Before[1];

      assert.equal(alice_FILrewardSnapshot_Before, 0);
      assert.equal(alice_DebtRewardSnapshot_Before, 0);
      assert.equal(bob_FILrewardSnapshot_Before, 0);
      assert.equal(bob_DebtRewardSnapshot_Before, 0);

      const defaultPool_FIL = await defaultPool.getFIL();
      const defaultPool_Debt = await defaultPool.getDebt();

      // Carol's liquidated coll (1 FIL) and drawn debt should have entered the Default Pool
      assert.isAtMost(th.getDifference(defaultPool_FIL, liquidatedColl_C), 100);
      assert.isAtMost(th.getDifference(defaultPool_Debt, liquidatedDebt_C), 100);

      const pendingCollReward_A = await troveManager.getPendingFILReward(alice.address);
      const pendingDebtReward_A = await troveManager.getPendingDebtReward(alice.address);
      assert.isTrue(pendingCollReward_A.gt("0"));
      assert.isTrue(pendingDebtReward_A.gt("0"));

      // Close Alice's trove. Alice's pending rewards should be removed from the DefaultPool when she close.
      await borrowerOperations.connect(alice).closeTrove();

      const defaultPool_FIL_afterAliceCloses = await defaultPool.getFIL();
      const defaultPool_Debt_afterAliceCloses = await defaultPool.getDebt();

      assert.isAtMost(
        th.getDifference(
          defaultPool_FIL_afterAliceCloses,
          defaultPool_FIL.sub(pendingCollReward_A),
        ),
        1000,
      );
      assert.isAtMost(
        th.getDifference(
          defaultPool_Debt_afterAliceCloses,
          defaultPool_Debt.sub(pendingDebtReward_A),
        ),
        1000,
      );

      // whale adjusts trove, pulling their rewards out of DefaultPool
      await borrowerOperations
        .connect(whale)
        .adjustTrove(th._100pct, 0, dec(1, 18), true, whale.address, whale.address);

      // Close Bob's trove. Expect DefaultPool coll and debt to drop to 0, since closing pulls his rewards out.
      await borrowerOperations.connect(bob).closeTrove();

      const defaultPool_FIL_afterBobCloses = await defaultPool.getFIL();
      const defaultPool_Debt_afterBobCloses = await defaultPool.getDebt();

      assert.isAtMost(th.getDifference(defaultPool_FIL_afterBobCloses, 0), 100000);
      assert.isAtMost(th.getDifference(defaultPool_Debt_afterBobCloses, 0), 100000);
    });

    it("closeTrove(): reverts if borrower has insufficient debt token balance to repay his entire debt", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(15000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });

      //Confirm Bob's debt token balance is less than his trove debt
      const B_DebtTokenBal = await debtToken.balanceOf(B.address);
      const B_troveDebt = await getTroveEntireDebt(B.address);

      assert.isTrue(B_DebtTokenBal.lt(B_troveDebt));

      const closeTrovePromise_B = borrowerOperations.connect(B).closeTrove();

      // Check closing trove reverts
      await assertRevert(
        closeTrovePromise_B,
        "BorrowerOps: Caller doesnt have enough tokens to make repayment",
      );
    });

    // --- openTrove() ---

    if (!withProxy) {
      // TODO: use rawLogs instead of logs
      it("openTrove(): emits a TroveUpdated event with the correct collateral and debt", async () => {
        const txA = (
          await openTrove({
            extraDebtTokenAmount: toBN(dec(15000, 18)),
            ICR: toBN(dec(2, 18)),
            extraParams: { from: A },
          })
        ).tx;
        const txB = (
          await openTrove({
            extraDebtTokenAmount: toBN(dec(5000, 18)),
            ICR: toBN(dec(2, 18)),
            extraParams: { from: B },
          })
        ).tx;
        const txC = (
          await openTrove({
            extraDebtTokenAmount: toBN(dec(3000, 18)),
            ICR: toBN(dec(2, 18)),
            extraParams: { from: C },
          })
        ).tx;

        const A_Coll = await getTroveEntireColl(A.address);
        const B_Coll = await getTroveEntireColl(B.address);
        const C_Coll = await getTroveEntireColl(C.address);
        const A_Debt = await getTroveEntireDebt(A.address);
        const B_Debt = await getTroveEntireDebt(B.address);
        const C_Debt = await getTroveEntireDebt(C.address);

        const A_emittedDebt = toBN(await th.getEventArgByName(txA, "TroveUpdated", "_debt"));
        const A_emittedColl = toBN(await th.getEventArgByName(txA, "TroveUpdated", "_coll"));
        const B_emittedDebt = toBN(await th.getEventArgByName(txB, "TroveUpdated", "_debt"));
        const B_emittedColl = toBN(await th.getEventArgByName(txB, "TroveUpdated", "_coll"));
        const C_emittedDebt = toBN(await th.getEventArgByName(txC, "TroveUpdated", "_debt"));
        const C_emittedColl = toBN(await th.getEventArgByName(txC, "TroveUpdated", "_coll"));

        // Check emitted debt values are correct
        assert.isTrue(A_Debt.eq(A_emittedDebt));
        assert.isTrue(B_Debt.eq(B_emittedDebt));
        assert.isTrue(C_Debt.eq(C_emittedDebt));

        // Check emitted coll values are correct
        assert.isTrue(A_Coll.eq(A_emittedColl));
        assert.isTrue(B_Coll.eq(B_emittedColl));
        assert.isTrue(C_Coll.eq(C_emittedColl));

        const baseRateBefore = await troveManager.baseRate();

        // Artificially make baseRate 5%
        await troveManager.setBaseRate(dec(5, 16));
        await troveManager.setLastFeeOpTimeToNow();

        assert.isTrue((await troveManager.baseRate()).gt(baseRateBefore));

        const txD = (
          await openTrove({
            extraDebtTokenAmount: toBN(dec(5000, 18)),
            ICR: toBN(dec(2, 18)),
            extraParams: { from: D },
          })
        ).tx;
        const txE = (
          await openTrove({
            extraDebtTokenAmount: toBN(dec(3000, 18)),
            ICR: toBN(dec(2, 18)),
            extraParams: { from: E },
          })
        ).tx;
        const D_Coll = await getTroveEntireColl(D.address);
        const E_Coll = await getTroveEntireColl(E.address);
        const D_Debt = await getTroveEntireDebt(D.address);
        const E_Debt = await getTroveEntireDebt(E.address);

        const D_emittedDebt = toBN(await th.getEventArgByName(txD, "TroveUpdated", "_debt"));
        const D_emittedColl = toBN(await th.getEventArgByName(txD, "TroveUpdated", "_coll"));

        const E_emittedDebt = toBN(await th.getEventArgByName(txE, "TroveUpdated", "_debt"));
        const E_emittedColl = toBN(await th.getEventArgByName(txE, "TroveUpdated", "_coll"));

        // Check emitted debt values are correct
        assert.isTrue(D_Debt.eq(D_emittedDebt));
        assert.isTrue(E_Debt.eq(E_emittedDebt));

        // Check emitted coll values are correct
        assert.isTrue(D_Coll.eq(D_emittedColl));
        assert.isTrue(E_Coll.eq(E_emittedColl));
      });
    }

    it("openTrove(): Opens a trove with net debt >= minimum net debt", async () => {
      // Add 1 wei to correct for rounding error in helper function
      const txA = await borrowerOperations
        .connect(A)
        .openTrove(
          th._100pct,
          await getNetBorrowingAmount(MIN_NET_DEBT.add(toBN(1))),
          A.address,
          A.address,
          { value: dec(100, 30) },
        );
      const receiptA = await txA.wait();
      assert.equal(receiptA.status, 1);
      assert.isTrue(await sortedTroves.contains(A.address));

      const txC = await borrowerOperations
        .connect(C)
        .openTrove(
          th._100pct,
          await getNetBorrowingAmount(MIN_NET_DEBT.add(toBN(dec(47789898, 22)))),
          A.address,
          A.address,
          { value: dec(100, 30) },
        );
      const receiptC = await txC.wait();
      assert.equal(receiptC.status, 1);
      assert.isTrue(await sortedTroves.contains(C.address));
    });

    it("openTrove(): reverts if net debt < minimum net debt", async () => {
      const txAPromise = borrowerOperations
        .connect(A)
        .openTrove(th._100pct, 0, A.address, A.address, {
          value: dec(100, 30),
        });
      await assertRevert(txAPromise, "revert");

      const txBPromise = borrowerOperations
        .connect(B)
        .openTrove(
          th._100pct,
          await getNetBorrowingAmount(MIN_NET_DEBT.sub(toBN(1))),
          B.address,
          B.address,
          { value: dec(100, 30) },
        );
      await assertRevert(txBPromise, "revert");

      const txCPromise = borrowerOperations
        .connect(C)
        .openTrove(th._100pct, MIN_NET_DEBT.sub(toBN(dec(173, 18))), C.address, C.address, {
          value: dec(100, 30),
        });
      await assertRevert(txCPromise, "revert");
    });

    it("openTrove(): decays a non-zero base rate", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(20000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(30000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });

      // Artificially make baseRate 5%
      await troveManager.setBaseRate(dec(5, 16));
      await troveManager.setLastFeeOpTimeToNow();

      // Check baseRate is now non-zero
      const baseRate_1 = await troveManager.baseRate();
      assert.isTrue(baseRate_1.gt(toBN("0")));

      // 2 hours pass
      await th.fastForwardTime(7200, web3.currentProvider);

      // D opens trove
      await openTrove({
        extraDebtTokenAmount: toBN(dec(37, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });

      // Check baseRate has decreased
      const baseRate_2 = await troveManager.baseRate();
      assert.isTrue(baseRate_2.lt(baseRate_1));

      // 1 hour passes
      await th.fastForwardTime(3600, web3.currentProvider);

      // E opens trove
      await openTrove({
        extraDebtTokenAmount: toBN(dec(12, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: E },
      });

      const baseRate_3 = await troveManager.baseRate();
      assert.isTrue(baseRate_3.lt(baseRate_2));
    });

    it("openTrove(): doesn't change base rate if it is already zero", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(20000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(30000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });

      // Check baseRate is zero
      const baseRate_1 = await troveManager.baseRate();
      assert.equal(baseRate_1, "0");

      // 2 hours pass
      await th.fastForwardTime(7200, web3.currentProvider);

      // D opens trove
      await openTrove({
        extraDebtTokenAmount: toBN(dec(37, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });

      // Check baseRate is still 0
      const baseRate_2 = await troveManager.baseRate();
      assert.equal(baseRate_2, "0");

      // 1 hour passes
      await th.fastForwardTime(3600, web3.currentProvider);

      // E opens trove
      await openTrove({
        extraDebtTokenAmount: toBN(dec(12, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: E },
      });

      const baseRate_3 = await troveManager.baseRate();
      assert.equal(baseRate_3, "0");
    });

    it("openTrove(): lastFeeOpTime doesn't update if less time than decay interval has passed since the last fee operation", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(20000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(30000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });

      // Artificially make baseRate 5%
      await troveManager.setBaseRate(dec(5, 16));
      await troveManager.setLastFeeOpTimeToNow();

      // Check baseRate is now non-zero
      const baseRate_1 = await troveManager.baseRate();
      assert.isTrue(baseRate_1.gt(toBN("0")));

      const lastFeeOpTime_1 = await troveManager.lastFeeOperationTime();

      // Borrower D triggers a fee
      await openTrove({
        extraDebtTokenAmount: toBN(dec(1, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });

      const lastFeeOpTime_2 = await troveManager.lastFeeOperationTime();

      // Check that the last fee operation time did not update, as borrower D's debt issuance occured
      // since before minimum interval had passed
      assert.isTrue(lastFeeOpTime_2.eq(lastFeeOpTime_1));

      // 1 minute passes
      await th.fastForwardTime(60, web3.currentProvider);

      // Check that now, at least one minute has passed since lastFeeOpTime_1
      const timeNow = await th.getLatestBlockTimestamp(web3);
      assert.isTrue(toBN(timeNow).sub(lastFeeOpTime_1).gte(60));

      // Borrower E triggers a fee
      await openTrove({
        extraDebtTokenAmount: toBN(dec(1, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: E },
      });

      const lastFeeOpTime_3 = await troveManager.lastFeeOperationTime();

      // Check that the last fee operation time DID update, as borrower's debt issuance occured
      // after minimum interval had passed
      assert.isTrue(lastFeeOpTime_3.gt(lastFeeOpTime_1));
    });

    it("openTrove(): reverts if max fee > 100%", async () => {
      await assertRevert(
        borrowerOperations.connect(A).openTrove(dec(2, 18), dec(10000, 18), A.address, A.address, {
          value: dec(1000, "ether"),
        }),
        "Max fee percentage must be between 0.5% and 100%",
      );
      await assertRevert(
        borrowerOperations
          .connect(B)
          .openTrove("1000000000000000001", dec(20000, 18), B.address, B.address, {
            value: dec(1000, "ether"),
          }),
        "Max fee percentage must be between 0.5% and 100%",
      );
    });

    it("openTrove(): reverts if max fee < 0.5% in Normal mode", async () => {
      await assertRevert(
        borrowerOperations.connect(A).openTrove(0, dec(195000, 18), A.address, A.address, {
          value: dec(1200, "ether"),
        }),
        "Max fee percentage must be between 0.5% and 100%",
      );
      await assertRevert(
        borrowerOperations.connect(A).openTrove(1, dec(195000, 18), A.address, A.address, {
          value: dec(1000, "ether"),
        }),
        "Max fee percentage must be between 0.5% and 100%",
      );
      await assertRevert(
        borrowerOperations
          .connect(B)
          .openTrove("4999999999999999", dec(195000, 18), B.address, B.address, {
            value: dec(1200, "ether"),
          }),
        "Max fee percentage must be between 0.5% and 100%",
      );
    });

    it("openTrove(): allows max fee < 0.5% in Recovery Mode", async () => {
      await borrowerOperations
        .connect(A)
        .openTrove(th._100pct, dec(195000, 18), A.address, A.address, {
          value: dec(2000, "ether"),
        });

      await priceFeed.setPrice(dec(100, 18));
      assert.isTrue(await th.checkRecoveryMode(contracts));

      await borrowerOperations.connect(B).openTrove(0, dec(19500, 18), B.address, B.address, {
        value: dec(3100, "ether"),
      });
      await priceFeed.setPrice(dec(50, 18));
      assert.isTrue(await th.checkRecoveryMode(contracts));
      await borrowerOperations.connect(C).openTrove(1, dec(19500, 18), C.address, C.address, {
        value: dec(3100, "ether"),
      });
      await priceFeed.setPrice(dec(25, 18));
      assert.isTrue(await th.checkRecoveryMode(contracts));
      await borrowerOperations
        .connect(D)
        .openTrove("4999999999999999", dec(19500, 18), D.address, D.address, {
          value: dec(3100, "ether"),
        });
    });

    it("openTrove(): reverts if fee exceeds max fee percentage", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(20000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(30000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });

      const totalSupply = await debtToken.totalSupply();

      // Artificially make baseRate 5%
      await troveManager.setBaseRate(dec(5, 16));
      await troveManager.setLastFeeOpTimeToNow();

      //       actual fee percentage: 0.005000000186264514
      // user's max fee percentage:  0.0049999999999999999
      let borrowingRate = await troveManager.getBorrowingRate(); // expect max(0.5 + 5%, 5%) rate
      assert.equal(borrowingRate, dec(5, 16));

      const lessThan5pct = "49999999999999999";
      await assertRevert(
        borrowerOperations
          .connect(D)
          .openTrove(lessThan5pct, dec(30000, 18), A.address, A.address, {
            value: dec(1000, "ether"),
          }),
        "Fee exceeded provided maximum",
      );

      borrowingRate = await troveManager.getBorrowingRate(); // expect 5% rate
      assert.equal(borrowingRate, dec(5, 16));
      // Attempt with maxFee 1%
      await assertRevert(
        borrowerOperations.connect(D).openTrove(dec(1, 16), dec(30000, 18), A.address, A.address, {
          value: dec(1000, "ether"),
        }),
        "Fee exceeded provided maximum",
      );

      borrowingRate = await troveManager.getBorrowingRate(); // expect 5% rate
      assert.equal(borrowingRate, dec(5, 16));
      // Attempt with maxFee 3.754%
      await assertRevert(
        borrowerOperations
          .connect(D)
          .openTrove(dec(3754, 13), dec(30000, 18), A.address, A.address, {
            value: dec(1000, "ether"),
          }),
        "Fee exceeded provided maximum",
      );

      borrowingRate = await troveManager.getBorrowingRate(); // expect 5% rate
      assert.equal(borrowingRate, dec(5, 16));
      // Attempt with maxFee 1e-16%
      await assertRevert(
        borrowerOperations.connect(D).openTrove(dec(5, 15), dec(30000, 18), A.address, A.address, {
          value: dec(1000, "ether"),
        }),
        "Fee exceeded provided maximum",
      );
    });

    it("openTrove(): succeeds when fee is less than max fee percentage", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(20000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(30000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });

      // Artificially make baseRate 5%
      await troveManager.setBaseRate(dec(5, 16));
      await troveManager.setLastFeeOpTimeToNow();

      let borrowingRate = await troveManager.getBorrowingRate(); // expect min(0.5 + 5%, 5%) rate
      assert.equal(borrowingRate, dec(5, 16));

      // Attempt with maxFee > 5%
      const moreThan5pct = "50000000000000001";
      const tx1 = await borrowerOperations
        .connect(D)
        .openTrove(moreThan5pct, dec(10000, 18), A.address, A.address, {
          value: dec(100, "ether"),
        });
      const receipt = await tx1.wait();
      assert.equal(receipt.status, 1);

      borrowingRate = await troveManager.getBorrowingRate(); // expect 5% rate
      assert.equal(borrowingRate, dec(5, 16));

      // Attempt with maxFee = 5%
      const tx2 = await borrowerOperations
        .connect(H)
        .openTrove(dec(5, 16), dec(10000, 18), A.address, A.address, {
          value: dec(100, "ether"),
        });
      const receipt2 = await tx2.wait();
      assert.equal(receipt2.status, 1);

      borrowingRate = await troveManager.getBorrowingRate(); // expect 5% rate
      assert.equal(borrowingRate, dec(5, 16));

      // Attempt with maxFee 10%
      const tx3 = await borrowerOperations
        .connect(E)
        .openTrove(dec(1, 17), dec(10000, 18), A.address, A.address, {
          value: dec(100, "ether"),
        });
      const receipt3 = await tx3.wait();
      assert.equal(receipt3.status, 1);

      borrowingRate = await troveManager.getBorrowingRate(); // expect 5% rate
      assert.equal(borrowingRate, dec(5, 16));

      // Attempt with maxFee 37.659%
      const tx4 = await borrowerOperations
        .connect(F)
        .openTrove(dec(37659, 13), dec(10000, 18), A.address, A.address, {
          value: dec(100, "ether"),
        });
      const receipt4 = await tx4.wait();
      assert.equal(receipt4.status, 1);

      // Attempt with maxFee 100%
      const tx5 = await borrowerOperations
        .connect(G)
        .openTrove(dec(1, 18), dec(10000, 18), A.address, A.address, {
          value: dec(100, "ether"),
        });
      const receipt5 = await tx5.wait();
      assert.equal(receipt5.status, 1);
    });

    it("openTrove(): borrower can't grief the baseRate and stop it decaying by issuing debt at higher frequency than the decay granularity", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(20000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(30000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });

      // Artificially make baseRate 5%
      await troveManager.setBaseRate(dec(5, 16));
      await troveManager.setLastFeeOpTimeToNow();

      // Check baseRate is non-zero
      const baseRate_1 = await troveManager.baseRate();
      assert.isTrue(baseRate_1.gt(toBN("0")));

      // 59 minutes pass
      await th.fastForwardTime(3540, web3.currentProvider);

      // Assume Borrower also owns accounts D and E
      // Borrower triggers a fee, before decay interval has passed
      await openTrove({
        extraDebtTokenAmount: toBN(dec(1, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });

      // 1 minute pass
      await th.fastForwardTime(3540, web3.currentProvider);

      // Borrower triggers another fee
      await openTrove({
        extraDebtTokenAmount: toBN(dec(1, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: E },
      });

      // Check base rate has decreased even though Borrower tried to stop it decaying
      const baseRate_2 = await troveManager.baseRate();
      assert.isTrue(baseRate_2.lt(baseRate_1));
    });

    it("openTrove(): borrowing at non-zero base rate sends debt token fee to ProtocolToken staking contract", async () => {
      // time fast-forwards 1 year, and multisig stakes 1 token
      await th.fastForwardTime(timeValues.SECONDS_IN_ONE_YEAR, web3.currentProvider);
      await protocolToken.connect(multisig).approve(protocolTokenStaking.address, dec(1, 18));
      await protocolTokenStaking.connect(multisig).stake(dec(1, 18));

      // Check ProtocolToken debt token balance before == 0
      const protocolTokenStaking_debtTokenBalance_Before = await debtToken.balanceOf(
        protocolTokenStaking.address,
      );
      assert.equal(protocolTokenStaking_debtTokenBalance_Before, "0");

      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(20000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(30000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });

      // Artificially make baseRate 5%
      await troveManager.setBaseRate(dec(5, 16));
      await troveManager.setLastFeeOpTimeToNow();

      // Check baseRate is now non-zero
      const baseRate_1 = await troveManager.baseRate();
      assert.isTrue(baseRate_1.gt(toBN("0")));

      // 2 hours pass
      await th.fastForwardTime(7200, web3.currentProvider);

      // D opens trove
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });

      // Check ProtocolToken debt token balance after has increased
      const protocolTokenStaking_debtTokenBalance_After = await debtToken.balanceOf(
        protocolTokenStaking.address,
      );
      assert.isTrue(
        protocolTokenStaking_debtTokenBalance_After.gt(
          protocolTokenStaking_debtTokenBalance_Before,
        ),
      );
    });

    if (!withProxy) {
      // TODO: use rawLogs instead of logs
      it("openTrove(): borrowing at non-zero base records the (drawn debt + fee  + liq. reserve) on the Trove struct", async () => {
        // time fast-forwards 1 year, and multisig stakes 1 token
        await th.fastForwardTime(timeValues.SECONDS_IN_ONE_YEAR, web3.currentProvider);
        await protocolToken.connect(multisig).approve(protocolTokenStaking.address, dec(1, 18));
        await protocolTokenStaking.connect(multisig).stake(dec(1, 18));

        await openTrove({
          extraDebtTokenAmount: toBN(dec(10000, 18)),
          ICR: toBN(dec(10, 18)),
          extraParams: { from: whale },
        });
        await openTrove({
          extraDebtTokenAmount: toBN(dec(20000, 18)),
          ICR: toBN(dec(2, 18)),
          extraParams: { from: A },
        });
        await openTrove({
          extraDebtTokenAmount: toBN(dec(30000, 18)),
          ICR: toBN(dec(2, 18)),
          extraParams: { from: B },
        });
        await openTrove({
          extraDebtTokenAmount: toBN(dec(40000, 18)),
          ICR: toBN(dec(2, 18)),
          extraParams: { from: C },
        });

        // Artificially make baseRate 5%
        await troveManager.setBaseRate(dec(5, 16));
        await troveManager.setLastFeeOpTimeToNow();

        // Check baseRate is now non-zero
        const baseRate_1 = await troveManager.baseRate();
        assert.isTrue(baseRate_1.gt(toBN("0")));

        // 2 hours pass
        await th.fastForwardTime(7200, web3.currentProvider);

        const D_DebtTokenRequest = toBN(dec(20000, 18));

        // D withdraws debt token
        const openTroveTx = await borrowerOperations
          .connect(D)
          .openTrove(th._100pct, D_DebtTokenRequest, ZERO_ADDRESS, ZERO_ADDRESS, {
            value: dec(200, "ether"),
          });

        const emittedFee = toBN(await th.getFeeFromDebtTokenBorrowingEvent(openTroveTx));
        assert.isTrue(toBN(emittedFee).gt(toBN("0")));

        const newDebt = (await troveManager.Troves(D.address))[0];

        // Check debt on Trove struct equals drawn debt plus emitted fee
        th.assertIsApproximatelyEqual(
          newDebt,
          D_DebtTokenRequest.add(emittedFee).add(GAS_COMPENSATION),
          100000,
        );
      });
    }

    it("openTrove(): Borrowing at non-zero base rate increases the ProtocolToken staking contract debt token fees-per-unit-staked", async () => {
      // time fast-forwards 1 year, and multisig stakes 1 token
      await th.fastForwardTime(timeValues.SECONDS_IN_ONE_YEAR, web3.currentProvider);
      await protocolToken.connect(multisig).approve(protocolTokenStaking.address, dec(1, 18));
      await protocolTokenStaking.connect(multisig).stake(dec(1, 18));

      // Check ProtocolToken contract debt token fees-per-unit-staked is zero
      const F_DebtToken_Before = await protocolTokenStaking.F_DebtToken();
      assert.equal(F_DebtToken_Before, "0");

      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(20000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(30000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });

      // Artificially make baseRate 5%
      await troveManager.setBaseRate(dec(5, 16));
      await troveManager.setLastFeeOpTimeToNow();

      // Check baseRate is now non-zero
      const baseRate_1 = await troveManager.baseRate();
      assert.isTrue(baseRate_1.gt(toBN("0")));

      // 2 hours pass
      await th.fastForwardTime(7200, web3.currentProvider);

      // D opens trove
      await openTrove({
        extraDebtTokenAmount: toBN(dec(37, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });

      // Check ProtocolToken contract debt token fees-per-unit-staked has increased
      const F_DebtToken_After = await protocolTokenStaking.F_DebtToken();
      assert.isTrue(F_DebtToken_After.gt(F_DebtToken_Before));
    });

    it("openTrove(): Borrowing at non-zero base rate sends requested amount to the user", async () => {
      // time fast-forwards 1 year, and multisig stakes 1 token
      await th.fastForwardTime(timeValues.SECONDS_IN_ONE_YEAR, web3.currentProvider);
      await protocolToken.connect(multisig).approve(protocolTokenStaking.address, dec(1, 18));
      await protocolTokenStaking.connect(multisig).stake(dec(1, 18));

      // Check ProtocolToken Staking contract balance before == 0
      const protocolTokenStaking_debtTokenBalance_Before = await debtToken.balanceOf(
        protocolTokenStaking.address,
      );
      assert.equal(protocolTokenStaking_debtTokenBalance_Before, "0");

      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(20000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(30000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(40000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });

      // Artificially make baseRate 5%
      await troveManager.setBaseRate(dec(5, 16));
      await troveManager.setLastFeeOpTimeToNow();

      // Check baseRate is non-zero
      const baseRate_1 = await troveManager.baseRate();
      assert.isTrue(baseRate_1.gt(toBN("0")));

      // 2 hours pass
      await th.fastForwardTime(7200, web3.currentProvider);

      // D opens trove
      const debtTokenRequest_D = toBN(dec(40000, 18));
      await borrowerOperations
        .connect(D)
        .openTrove(th._100pct, debtTokenRequest_D, D.address, D.address, {
          value: dec(500, "ether"),
        });

      // Check ProtocolToken staking debt token balance has increased
      const protocolTokenStaking_debtTokenBalance_After = await debtToken.balanceOf(
        protocolTokenStaking.address,
      );
      assert.isTrue(
        protocolTokenStaking_debtTokenBalance_After.gt(
          protocolTokenStaking_debtTokenBalance_Before,
        ),
      );

      // Check D's debt token balance now equals their requested debt token
      const debtTokenBalance_D = await debtToken.balanceOf(D.address);
      assert.isTrue(debtTokenRequest_D.eq(debtTokenBalance_D));
    });

    it("openTrove(): Borrowing at zero base rate changes the ProtocolToken staking contract debt token fees-per-unit-staked", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: C },
      });

      // Check baseRate is zero
      const baseRate_1 = await troveManager.baseRate();
      assert.equal(baseRate_1, "0");

      // 2 hours pass
      await th.fastForwardTime(7200, web3.currentProvider);

      // Check debt token reward per ProtocolToken staked == 0
      const F_DebtToken_Before = await protocolTokenStaking.F_DebtToken();
      assert.equal(F_DebtToken_Before, "0");

      // A stakes ProtocolToken
      await protocolToken.unprotectedMint(A.address, dec(100, 18));
      await protocolTokenStaking.connect(A).stake(dec(100, 18));

      // D opens trove
      await openTrove({
        extraDebtTokenAmount: toBN(dec(37, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: D },
      });

      // Check debt token reward per ProtocolToken staked > 0
      const F_DebtToken_After = await protocolTokenStaking.F_DebtToken();
      assert.isTrue(F_DebtToken_After.gt(toBN("0")));
    });

    it("openTrove(): Borrowing at zero base rate charges minimum fee", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: A },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: B },
      });

      const debtTokenRequest = toBN(dec(10000, 18));
      const txC = await borrowerOperations
        .connect(C)
        .openTrove(th._100pct, debtTokenRequest, ZERO_ADDRESS, ZERO_ADDRESS, {
          value: dec(100, "ether"),
        });
      const _debtTokenFee = toBN(
        await th.getEventArgByName(txC, "DebtTokenBorrowingFeePaid", "_debtTokenFee"),
      );

      const expectedFee = BORROWING_FEE_FLOOR.mul(toBN(debtTokenRequest)).div(toBN(dec(1, 18)));
      assert.isTrue(_debtTokenFee.eq(expectedFee));
    });

    it("openTrove(): reverts when system is in Recovery Mode and ICR < CCR", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: whale },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });
      assert.isFalse(await th.checkRecoveryMode(contracts));

      // price drops, and Recovery Mode kicks in
      await priceFeed.setPrice(dec(105, 18));

      assert.isTrue(await th.checkRecoveryMode(contracts));

      // Bob tries to open a trove with 149% ICR during Recovery Mode
      try {
        const txBob = await openTrove({
          extraDebtTokenAmount: toBN(dec(5000, 18)),
          ICR: toBN(dec(149, 16)),
          extraParams: { from: alice },
        });
        assert.isFalse(txBob.receipt.status);
      } catch (err) {
        assert.include(err.message, "revert");
      }
    });

    it("openTrove(): reverts when trove ICR < MCR", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: whale },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });

      assert.isFalse(await th.checkRecoveryMode(contracts));

      // Bob attempts to open a 109% ICR trove in Normal Mode
      try {
        const txBob = (
          await openTrove({
            extraDebtTokenAmount: toBN(dec(5000, 18)),
            ICR: toBN(dec(109, 16)),
            extraParams: { from: bob },
          })
        ).tx;
        assert.isFalse(txBob.receipt.status);
      } catch (err) {
        assert.include(err.message, "revert");
      }

      // price drops, and Recovery Mode kicks in
      await priceFeed.setPrice(dec(105, 18));

      assert.isTrue(await th.checkRecoveryMode(contracts));

      // Bob attempts to open a 109% ICR trove in Recovery Mode
      try {
        const txBob = await openTrove({
          extraDebtTokenAmount: toBN(dec(5000, 18)),
          ICR: toBN(dec(109, 16)),
          extraParams: { from: bob },
        });
        assert.isFalse(txBob.receipt.status);
      } catch (err) {
        assert.include(err.message, "revert");
      }
    });

    it("openTrove(): reverts when opening the trove would cause the TCR of the system to fall below the CCR", async () => {
      await priceFeed.setPrice(dec(100, 18));

      // Alice creates trove with 150% ICR.  System TCR = 150%.
      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(15, 17)),
        extraParams: { from: alice },
      });

      const TCR = await th.getTCR(contracts);
      assert.equal(TCR, dec(150, 16));

      // Bob attempts to open a trove with ICR = 149%
      // System TCR would fall below 150%
      try {
        const txBob = await openTrove({
          extraDebtTokenAmount: toBN(dec(5000, 18)),
          ICR: toBN(dec(149, 16)),
          extraParams: { from: bob },
        });
        assert.isFalse(txBob.receipt.status);
      } catch (err) {
        assert.include(err.message, "revert");
      }
    });

    it("openTrove(): reverts if trove is already active", async () => {
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(10, 18)),
        extraParams: { from: whale },
      });

      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(15, 17)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(15, 17)),
        extraParams: { from: bob },
      });

      try {
        const txB_1 = await openTrove({
          extraDebtTokenAmount: toBN(dec(5000, 18)),
          ICR: toBN(dec(3, 18)),
          extraParams: { from: bob },
        });

        assert.isFalse(txB_1.receipt.status);
      } catch (err) {
        assert.include(err.message, "revert");
      }

      try {
        const txB_2 = await openTrove({ ICR: toBN(dec(2, 18)), extraParams: { from: alice } });

        assert.isFalse(txB_2.receipt.status);
      } catch (err) {
        assert.include(err.message, "revert");
      }
    });

    it("openTrove(): Can open a trove with ICR >= CCR when system is in Recovery Mode", async () => {
      // --- SETUP ---
      //  Alice and Bob add coll and withdraw such  that the TCR is ~150%
      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(15, 17)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(15, 17)),
        extraParams: { from: bob },
      });

      const TCR = (await th.getTCR(contracts)).toString();
      assert.equal(TCR, "1500000000000000000");

      // price drops to 1FIL:100DebtToken, reducing TCR below 150%
      await priceFeed.setPrice("100000000000000000000");
      const price = await priceFeed.getPrice();

      assert.isTrue(await th.checkRecoveryMode(contracts));

      // Carol opens at 150% ICR in Recovery Mode
      const txCarol = (
        await openTrove({
          extraDebtTokenAmount: toBN(dec(5000, 18)),
          ICR: toBN(dec(15, 17)),
          extraParams: { from: carol },
        })
      ).tx;
      const receipt = await txCarol.wait();
      assert.equal(receipt.status, 1);
      assert.isTrue(await sortedTroves.contains(carol.address));

      const carol_TroveStatus = await troveManager.getTroveStatus(carol.address);
      assert.equal(carol_TroveStatus, 1);

      const carolICR = await troveManager.getCurrentICR(carol.address, price);
      assert.isTrue(carolICR.gt(toBN(dec(150, 16))));
    });

    it("openTrove(): Reverts opening a trove with min debt when system is in Recovery Mode", async () => {
      // --- SETUP ---
      //  Alice and Bob add coll and withdraw such  that the TCR is ~150%
      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(15, 17)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(15, 17)),
        extraParams: { from: bob },
      });

      const TCR = (await th.getTCR(contracts)).toString();
      assert.equal(TCR, "1500000000000000000");

      // price drops to 1FIL:100DebtToken, reducing TCR below 150%
      await priceFeed.setPrice("100000000000000000000");

      assert.isTrue(await th.checkRecoveryMode(contracts));

      await assertRevert(
        borrowerOperations
          .connect(carol)
          .openTrove(
            th._100pct,
            await getNetBorrowingAmount(MIN_NET_DEBT),
            carol.address,
            carol.address,
            {
              value: dec(1, "ether"),
            },
          ),
      );
    });

    it("openTrove(): creates a new Trove and assigns the correct collateral and debt amount", async () => {
      const debt_Before = await getTroveEntireDebt(alice.address);
      const coll_Before = await getTroveEntireColl(alice.address);
      const status_Before = await troveManager.getTroveStatus(alice.address);

      // check coll and debt before
      assert.equal(debt_Before, 0);
      assert.equal(coll_Before, 0);

      // check non-existent status
      assert.equal(status_Before, 0);

      const debtTokenRequest = MIN_NET_DEBT;
      await borrowerOperations
        .connect(alice)
        .openTrove(th._100pct, MIN_NET_DEBT, carol.address, carol.address, {
          value: dec(100, "ether"),
        });

      // Get the expected debt based on the debt token request (adding fee and liq. reserve on top)
      const expectedDebt = debtTokenRequest
        .add(await troveManager.getBorrowingFee(debtTokenRequest))
        .add(GAS_COMPENSATION);

      const debt_After = await getTroveEntireDebt(alice.address);
      const coll_After = await getTroveEntireColl(alice.address);
      const status_After = await troveManager.getTroveStatus(alice.address);

      // check coll and debt after
      assert.isTrue(coll_After.gt("0"));
      assert.isTrue(debt_After.gt("0"));

      assert.isTrue(debt_After.eq(expectedDebt));

      // check active status
      assert.equal(status_After, 1);
    });

    it("openTrove(): adds Trove owner to TroveOwners array", async () => {
      const TroveOwnersCount_Before = (await troveManager.getTroveOwnersCount()).toString();
      assert.equal(TroveOwnersCount_Before, "0");

      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(15, 17)),
        extraParams: { from: alice },
      });

      const TroveOwnersCount_After = (await troveManager.getTroveOwnersCount()).toString();
      assert.equal(TroveOwnersCount_After, "1");
    });

    it("openTrove(): creates a stake and adds it to total stakes", async () => {
      const aliceStakeBefore = await getTroveStake(alice.address);
      const totalStakesBefore = await troveManager.totalStakes();

      assert.equal(aliceStakeBefore, "0");
      assert.equal(totalStakesBefore, "0");

      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });
      const aliceCollAfter = await getTroveEntireColl(alice.address);
      const aliceStakeAfter = await getTroveStake(alice.address);
      assert.isTrue(aliceCollAfter.gt(toBN("0")));
      assert.isTrue(aliceStakeAfter.eq(aliceCollAfter));

      const totalStakesAfter = await troveManager.totalStakes();

      assert.isTrue(totalStakesAfter.eq(aliceStakeAfter));
    });

    it("openTrove(): inserts Trove to Sorted Troves list", async () => {
      // Check before
      const aliceTroveInList_Before = await sortedTroves.contains(alice.address);
      const listIsEmpty_Before = await sortedTroves.isEmpty();
      assert.equal(aliceTroveInList_Before, false);
      assert.equal(listIsEmpty_Before, true);

      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });

      // check after
      const aliceTroveInList_After = await sortedTroves.contains(alice.address);
      const listIsEmpty_After = await sortedTroves.isEmpty();
      assert.equal(aliceTroveInList_After, true);
      assert.equal(listIsEmpty_After, false);
    });

    it("openTrove(): Increases the activePool FIL and raw ether balance by correct amount", async () => {
      const activePool_FIL_Before = await activePool.getFIL();
      const activePool_RawEther_Before = await web3.eth.getBalance(activePool.address);
      assert.equal(activePool_FIL_Before, 0);
      assert.equal(activePool_RawEther_Before, 0);

      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });
      const aliceCollAfter = await getTroveEntireColl(alice.address);

      const activePool_FIL_After = await activePool.getFIL();
      const activePool_RawEther_After = toBN(await web3.eth.getBalance(activePool.address));
      assert.isTrue(activePool_FIL_After.eq(aliceCollAfter));
      assert.isTrue(activePool_RawEther_After.eq(aliceCollAfter));
    });

    it("openTrove(): records up-to-date initial snapshots of L_FIL and L_Debt", async () => {
      // --- SETUP ---

      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: carol },
      });

      // --- TEST ---

      // price drops to 1FIL:100DebtToken, reducing Carol's ICR below MCR
      await priceFeed.setPrice(dec(100, 18));

      // close Carol's Trove, liquidating her 1 ether and 180DebtToken.
      const liquidationTx = await troveManager.connect(owner).liquidate(carol.address);
      const [liquidatedDebt, liquidatedColl, gasComp] =
        await th.getEmittedLiquidationValues(liquidationTx);

      /* with total stakes = 10 ether, after liquidation, L_FIL should equal 1/10 ether per-ether-staked,
       and L_Debt should equal 18 tokens per-ether-staked. */

      const L_FIL = await troveManager.L_FIL();
      const L_Debt = await troveManager.L_Debt();

      assert.isTrue(L_FIL.gt(toBN("0")));
      assert.isTrue(L_Debt.gt(toBN("0")));

      // Bob opens trove
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: bob },
      });

      // Check Bob's snapshots of L_FIL and L_Debt equal the respective current values
      const bob_rewardSnapshot = await troveManager.rewardSnapshots(bob.address);
      const bob_FILrewardSnapshot = bob_rewardSnapshot[0];
      const bob_DebtRewardSnapshot = bob_rewardSnapshot[1];

      assert.isAtMost(th.getDifference(bob_FILrewardSnapshot, L_FIL), 1000);
      assert.isAtMost(th.getDifference(bob_DebtRewardSnapshot, L_Debt), 1000);
    });

    it("openTrove(): allows a user to open a Trove, then close it, then re-open it", async () => {
      // Open Troves
      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: whale },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });
      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: carol },
      });

      // Check Trove is active
      const alice_Trove_1 = await troveManager.Troves(alice.address);
      const status_1 = alice_Trove_1[3];
      assert.equal(status_1, 1);
      assert.isTrue(await sortedTroves.contains(alice.address));

      // to compensate borrowing fees
      await debtToken.connect(whale).transfer(alice.address, dec(10000, 18));

      // Repay and close Trove
      await borrowerOperations.connect(alice).closeTrove();

      // Check Trove is closed
      const alice_Trove_2 = await troveManager.Troves(alice.address);
      const status_2 = alice_Trove_2[3];
      assert.equal(status_2, 2);
      assert.isFalse(await sortedTroves.contains(alice.address));

      // Re-open Trove
      await openTrove({
        extraDebtTokenAmount: toBN(dec(5000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });

      // Check Trove is re-opened
      const alice_Trove_3 = await troveManager.Troves(alice.address);
      const status_3 = alice_Trove_3[3];
      assert.equal(status_3, 1);
      assert.isTrue(await sortedTroves.contains(alice.address));
    });

    it("openTrove(): increases the Trove's debt by the correct amount", async () => {
      // check before
      const alice_Trove_Before = await troveManager.Troves(alice.address);
      const debt_Before = alice_Trove_Before[0];
      assert.equal(debt_Before, 0);

      await borrowerOperations
        .connect(alice)
        .openTrove(
          th._100pct,
          await getOpenTroveDebtTokenAmount(dec(10000, 18)),
          alice.address,
          alice.address,
          {
            value: dec(100, "ether"),
          },
        );

      // check after
      const alice_Trove_After = await troveManager.Troves(alice.address);
      const debt_After = alice_Trove_After[0];
      th.assertIsApproximatelyEqual(debt_After, dec(10000, 18), 10000);
    });

    it("openTrove(): increases debt in ActivePool by the debt of the trove", async () => {
      const activePool_debt_Before = await activePool.getDebt();
      assert.equal(activePool_debt_Before, 0);

      await openTrove({
        extraDebtTokenAmount: toBN(dec(10000, 18)),
        ICR: toBN(dec(2, 18)),
        extraParams: { from: alice },
      });
      const aliceDebt = await getTroveEntireDebt(alice.address);
      assert.isTrue(aliceDebt.gt(toBN("0")));

      const activePool_debt_After = await activePool.getDebt();
      assert.isTrue(activePool_debt_After.eq(aliceDebt));
    });

    it("openTrove(): increases user DebtToken balance by correct amount", async () => {
      // check before
      const alice_DebtTokenBalance_Before = await debtToken.balanceOf(alice.address);
      assert.equal(alice_DebtTokenBalance_Before, 0);

      await borrowerOperations
        .connect(alice)
        .openTrove(th._100pct, dec(10000, 18), alice.address, alice.address, {
          value: dec(100, "ether"),
        });

      // check after
      const alice_DebtTokenBalance_After = await debtToken.balanceOf(alice.address);
      assert.equal(alice_DebtTokenBalance_After, dec(10000, 18));
    });

    //  --- getNewICRFromTroveChange - (external wrapper in Tester contract calls internal function) ---

    describe("getNewICRFromTroveChange() returns the correct ICR", async () => {
      // 0, 0
      it("collChange = 0, debtChange = 0", async () => {
        price = await priceFeed.getPrice();
        const initialColl = dec(1, "ether");
        const initialDebt = dec(100, 18);
        const collChange = 0;
        const debtChange = 0;

        const newICR = (
          await borrowerOperations.getNewICRFromTroveChange(
            initialColl,
            initialDebt,
            collChange,
            true,
            debtChange,
            true,
            price,
          )
        ).toString();
        assert.equal(newICR, "2000000000000000000");
      });

      // 0, +ve
      it("collChange = 0, debtChange is positive", async () => {
        price = await priceFeed.getPrice();
        const initialColl = dec(1, "ether");
        const initialDebt = dec(100, 18);
        const collChange = 0;
        const debtChange = dec(50, 18);

        const newICR = (
          await borrowerOperations.getNewICRFromTroveChange(
            initialColl,
            initialDebt,
            collChange,
            true,
            debtChange,
            true,
            price,
          )
        ).toString();
        assert.isAtMost(th.getDifference(newICR, "1333333333333333333"), 100);
      });

      // 0, -ve
      it("collChange = 0, debtChange is negative", async () => {
        price = await priceFeed.getPrice();
        const initialColl = dec(1, "ether");
        const initialDebt = dec(100, 18);
        const collChange = 0;
        const debtChange = dec(50, 18);

        const newICR = (
          await borrowerOperations.getNewICRFromTroveChange(
            initialColl,
            initialDebt,
            collChange,
            true,
            debtChange,
            false,
            price,
          )
        ).toString();
        assert.equal(newICR, "4000000000000000000");
      });

      // +ve, 0
      it("collChange is positive, debtChange is 0", async () => {
        price = await priceFeed.getPrice();
        const initialColl = dec(1, "ether");
        const initialDebt = dec(100, 18);
        const collChange = dec(1, "ether");
        const debtChange = 0;

        const newICR = (
          await borrowerOperations.getNewICRFromTroveChange(
            initialColl,
            initialDebt,
            collChange,
            true,
            debtChange,
            true,
            price,
          )
        ).toString();
        assert.equal(newICR, "4000000000000000000");
      });

      // -ve, 0
      it("collChange is negative, debtChange is 0", async () => {
        price = await priceFeed.getPrice();
        const initialColl = dec(1, "ether");
        const initialDebt = dec(100, 18);
        const collChange = dec(5, 17);
        const debtChange = 0;

        const newICR = (
          await borrowerOperations.getNewICRFromTroveChange(
            initialColl,
            initialDebt,
            collChange,
            false,
            debtChange,
            true,
            price,
          )
        ).toString();
        assert.equal(newICR, "1000000000000000000");
      });

      // -ve, -ve
      it("collChange is negative, debtChange is negative", async () => {
        price = await priceFeed.getPrice();
        const initialColl = dec(1, "ether");
        const initialDebt = dec(100, 18);
        const collChange = dec(5, 17);
        const debtChange = dec(50, 18);

        const newICR = (
          await borrowerOperations.getNewICRFromTroveChange(
            initialColl,
            initialDebt,
            collChange,
            false,
            debtChange,
            false,
            price,
          )
        ).toString();
        assert.equal(newICR, "2000000000000000000");
      });

      // +ve, +ve
      it("collChange is positive, debtChange is positive", async () => {
        price = await priceFeed.getPrice();
        const initialColl = dec(1, "ether");
        const initialDebt = dec(100, 18);
        const collChange = dec(1, "ether");
        const debtChange = dec(100, 18);

        const newICR = (
          await borrowerOperations.getNewICRFromTroveChange(
            initialColl,
            initialDebt,
            collChange,
            true,
            debtChange,
            true,
            price,
          )
        ).toString();
        assert.equal(newICR, "2000000000000000000");
      });

      // +ve, -ve
      it("collChange is positive, debtChange is negative", async () => {
        price = await priceFeed.getPrice();
        const initialColl = dec(1, "ether");
        const initialDebt = dec(100, 18);
        const collChange = dec(1, "ether");
        const debtChange = dec(50, 18);

        const newICR = (
          await borrowerOperations.getNewICRFromTroveChange(
            initialColl,
            initialDebt,
            collChange,
            true,
            debtChange,
            false,
            price,
          )
        ).toString();
        assert.equal(newICR, "8000000000000000000");
      });

      // -ve, +ve
      it("collChange is negative, debtChange is positive", async () => {
        price = await priceFeed.getPrice();
        const initialColl = dec(1, "ether");
        const initialDebt = dec(100, 18);
        const collChange = dec(5, 17);
        const debtChange = dec(100, 18);

        const newICR = (
          await borrowerOperations.getNewICRFromTroveChange(
            initialColl,
            initialDebt,
            collChange,
            false,
            debtChange,
            true,
            price,
          )
        ).toString();
        assert.equal(newICR, "500000000000000000");
      });
    });

    // --- getCompositeDebt ---

    it("getCompositeDebt(): returns debt + gas comp", async () => {
      const res1 = await borrowerOperations.getCompositeDebt("0");
      assert.equal(res1, GAS_COMPENSATION.toString());

      const res2 = await borrowerOperations.getCompositeDebt(dec(90, 18));
      th.assertIsApproximatelyEqual(res2, GAS_COMPENSATION.add(toBN(dec(90, 18))));

      const res3 = await borrowerOperations.getCompositeDebt(dec("24423422357345049", 12));
      th.assertIsApproximatelyEqual(res3, GAS_COMPENSATION.add(toBN(dec("24423422357345049", 12))));
    });

    //  --- getNewTCRFromTroveChange  - (external wrapper in Tester contract calls internal function) ---

    describe("getNewTCRFromTroveChange() returns the correct TCR", async () => {
      // 0, 0
      it("collChange = 0, debtChange = 0", async () => {
        // --- SETUP --- Create a protocol instance with an Active Pool and pending rewards (Default Pool)
        const troveColl = toBN(dec(1000, "ether"));
        const troveTotalDebt = toBN(dec(100000, 18));
        const troveDebtTokenAmount = await getOpenTroveDebtTokenAmount(troveTotalDebt);
        await borrowerOperations
          .connect(alice)
          .openTrove(th._100pct, troveDebtTokenAmount, alice.address, alice.address, {
            value: troveColl,
          });
        await borrowerOperations
          .connect(bob)
          .openTrove(th._100pct, troveDebtTokenAmount, bob.address, bob.address, {
            value: troveColl,
          });

        await priceFeed.setPrice(dec(100, 18));

        const liquidationTx = await troveManager.liquidate(bob.address);
        assert.isFalse(await sortedTroves.contains(bob.address));

        const [liquidatedDebt, liquidatedColl, gasComp] =
          await th.getEmittedLiquidationValues(liquidationTx);

        await priceFeed.setPrice(dec(200, 18));
        const price = await priceFeed.getPrice();

        // --- TEST ---
        const collChange = 0;
        const debtChange = 0;
        const newTCR = await borrowerOperations.getNewTCRFromTroveChange(
          collChange,
          true,
          debtChange,
          true,
          price,
        );

        const expectedTCR = troveColl
          .add(liquidatedColl)
          .mul(price)
          .div(troveTotalDebt.add(liquidatedDebt));

        assert.isTrue(newTCR.eq(expectedTCR));
      });

      // 0, +ve
      it("collChange = 0, debtChange is positive", async () => {
        // --- SETUP --- Create a protocol instance with an Active Pool and pending rewards (Default Pool)
        const troveColl = toBN(dec(1000, "ether"));
        const troveTotalDebt = toBN(dec(100000, 18));
        const troveDebtTokenAmount = await getOpenTroveDebtTokenAmount(troveTotalDebt);
        await borrowerOperations
          .connect(alice)
          .openTrove(th._100pct, troveDebtTokenAmount, alice.address, alice.address, {
            value: troveColl,
          });
        await borrowerOperations
          .connect(bob)
          .openTrove(th._100pct, troveDebtTokenAmount, bob.address, bob.address, {
            value: troveColl,
          });

        await priceFeed.setPrice(dec(100, 18));

        const liquidationTx = await troveManager.liquidate(bob.address);
        assert.isFalse(await sortedTroves.contains(bob.address));

        const [liquidatedDebt, liquidatedColl, gasComp] =
          await th.getEmittedLiquidationValues(liquidationTx);

        await priceFeed.setPrice(dec(200, 18));
        const price = await priceFeed.getPrice();

        // --- TEST ---
        const collChange = 0;
        const debtChange = dec(200, 18);
        const newTCR = await borrowerOperations.getNewTCRFromTroveChange(
          collChange,
          true,
          debtChange,
          true,
          price,
        );

        const expectedTCR = troveColl
          .add(liquidatedColl)
          .mul(price)
          .div(troveTotalDebt.add(liquidatedDebt).add(toBN(debtChange)));

        assert.isTrue(newTCR.eq(expectedTCR));
      });

      // 0, -ve
      it("collChange = 0, debtChange is negative", async () => {
        // --- SETUP --- Create a protocol instance with an Active Pool and pending rewards (Default Pool)
        const troveColl = toBN(dec(1000, "ether"));
        const troveTotalDebt = toBN(dec(100000, 18));
        const troveDebtTokenAmount = await getOpenTroveDebtTokenAmount(troveTotalDebt);
        await borrowerOperations
          .connect(alice)
          .openTrove(th._100pct, troveDebtTokenAmount, alice.address, alice.address, {
            value: troveColl,
          });
        await borrowerOperations
          .connect(bob)
          .openTrove(th._100pct, troveDebtTokenAmount, bob.address, bob.address, {
            value: troveColl,
          });

        await priceFeed.setPrice(dec(100, 18));

        const liquidationTx = await troveManager.liquidate(bob.address);
        assert.isFalse(await sortedTroves.contains(bob.address));

        const [liquidatedDebt, liquidatedColl, gasComp] =
          await th.getEmittedLiquidationValues(liquidationTx);

        await priceFeed.setPrice(dec(200, 18));
        const price = await priceFeed.getPrice();
        // --- TEST ---
        const collChange = 0;
        const debtChange = dec(100, 18);
        const newTCR = await borrowerOperations.getNewTCRFromTroveChange(
          collChange,
          true,
          debtChange,
          false,
          price,
        );

        const expectedTCR = troveColl
          .add(liquidatedColl)
          .mul(price)
          .div(troveTotalDebt.add(liquidatedDebt).sub(toBN(dec(100, 18))));

        assert.isTrue(newTCR.eq(expectedTCR));
      });

      // +ve, 0
      it("collChange is positive, debtChange is 0", async () => {
        // --- SETUP --- Create a protocol instance with an Active Pool and pending rewards (Default Pool)
        const troveColl = toBN(dec(1000, "ether"));
        const troveTotalDebt = toBN(dec(100000, 18));
        const troveDebtTokenAmount = await getOpenTroveDebtTokenAmount(troveTotalDebt);
        await borrowerOperations
          .connect(alice)
          .openTrove(th._100pct, troveDebtTokenAmount, alice.address, alice.address, {
            value: troveColl,
          });
        await borrowerOperations
          .connect(bob)
          .openTrove(th._100pct, troveDebtTokenAmount, bob.address, bob.address, {
            value: troveColl,
          });

        await priceFeed.setPrice(dec(100, 18));

        const liquidationTx = await troveManager.liquidate(bob.address);
        assert.isFalse(await sortedTroves.contains(bob.address));

        const [liquidatedDebt, liquidatedColl, gasComp] =
          await th.getEmittedLiquidationValues(liquidationTx);

        await priceFeed.setPrice(dec(200, 18));
        const price = await priceFeed.getPrice();
        // --- TEST ---
        const collChange = dec(2, "ether");
        const debtChange = 0;
        const newTCR = await borrowerOperations.getNewTCRFromTroveChange(
          collChange,
          true,
          debtChange,
          true,
          price,
        );

        const expectedTCR = troveColl
          .add(liquidatedColl)
          .add(toBN(collChange))
          .mul(price)
          .div(troveTotalDebt.add(liquidatedDebt));

        assert.isTrue(newTCR.eq(expectedTCR));
      });

      // -ve, 0
      it("collChange is negative, debtChange is 0", async () => {
        // --- SETUP --- Create a protocol instance with an Active Pool and pending rewards (Default Pool)
        const troveColl = toBN(dec(1000, "ether"));
        const troveTotalDebt = toBN(dec(100000, 18));
        const troveDebtTokenAmount = await getOpenTroveDebtTokenAmount(troveTotalDebt);
        await borrowerOperations
          .connect(alice)
          .openTrove(th._100pct, troveDebtTokenAmount, alice.address, alice.address, {
            value: troveColl,
          });
        await borrowerOperations
          .connect(bob)
          .openTrove(th._100pct, troveDebtTokenAmount, bob.address, bob.address, {
            value: troveColl,
          });

        await priceFeed.setPrice(dec(100, 18));

        const liquidationTx = await troveManager.liquidate(bob.address);
        assert.isFalse(await sortedTroves.contains(bob.address));

        const [liquidatedDebt, liquidatedColl, gasComp] =
          await th.getEmittedLiquidationValues(liquidationTx);

        await priceFeed.setPrice(dec(200, 18));
        const price = await priceFeed.getPrice();

        // --- TEST ---
        const collChange = dec(1, 18);
        const debtChange = 0;
        const newTCR = await borrowerOperations.getNewTCRFromTroveChange(
          collChange,
          false,
          debtChange,
          true,
          price,
        );

        const expectedTCR = troveColl
          .add(liquidatedColl)
          .sub(toBN(dec(1, "ether")))
          .mul(price)
          .div(troveTotalDebt.add(liquidatedDebt));

        assert.isTrue(newTCR.eq(expectedTCR));
      });

      // -ve, -ve
      it("collChange is negative, debtChange is negative", async () => {
        // --- SETUP --- Create a protocol instance with an Active Pool and pending rewards (Default Pool)
        const troveColl = toBN(dec(1000, "ether"));
        const troveTotalDebt = toBN(dec(100000, 18));
        const troveDebtTokenAmount = await getOpenTroveDebtTokenAmount(troveTotalDebt);
        await borrowerOperations
          .connect(alice)
          .openTrove(th._100pct, troveDebtTokenAmount, alice.address, alice.address, {
            value: troveColl,
          });
        await borrowerOperations
          .connect(bob)
          .openTrove(th._100pct, troveDebtTokenAmount, bob.address, bob.address, {
            value: troveColl,
          });

        await priceFeed.setPrice(dec(100, 18));

        const liquidationTx = await troveManager.liquidate(bob.address);
        assert.isFalse(await sortedTroves.contains(bob.address));

        const [liquidatedDebt, liquidatedColl, gasComp] =
          await th.getEmittedLiquidationValues(liquidationTx);

        await priceFeed.setPrice(dec(200, 18));
        const price = await priceFeed.getPrice();

        // --- TEST ---
        const collChange = dec(1, 18);
        const debtChange = dec(100, 18);
        const newTCR = await borrowerOperations.getNewTCRFromTroveChange(
          collChange,
          false,
          debtChange,
          false,
          price,
        );

        const expectedTCR = troveColl
          .add(liquidatedColl)
          .sub(toBN(dec(1, "ether")))
          .mul(price)
          .div(troveTotalDebt.add(liquidatedDebt).sub(toBN(dec(100, 18))));

        assert.isTrue(newTCR.eq(expectedTCR));
      });

      // +ve, +ve
      it("collChange is positive, debtChange is positive", async () => {
        // --- SETUP --- Create a protocol instance with an Active Pool and pending rewards (Default Pool)
        const troveColl = toBN(dec(1000, "ether"));
        const troveTotalDebt = toBN(dec(100000, 18));
        const troveDebtTokenAmount = await getOpenTroveDebtTokenAmount(troveTotalDebt);
        await borrowerOperations
          .connect(alice)
          .openTrove(th._100pct, troveDebtTokenAmount, alice.address, alice.address, {
            value: troveColl,
          });
        await borrowerOperations
          .connect(bob)
          .openTrove(th._100pct, troveDebtTokenAmount, bob.address, bob.address, {
            value: troveColl,
          });

        await priceFeed.setPrice(dec(100, 18));

        const liquidationTx = await troveManager.liquidate(bob.address);
        assert.isFalse(await sortedTroves.contains(bob.address));

        const [liquidatedDebt, liquidatedColl, gasComp] =
          await th.getEmittedLiquidationValues(liquidationTx);

        await priceFeed.setPrice(dec(200, 18));
        const price = await priceFeed.getPrice();

        // --- TEST ---
        const collChange = dec(1, "ether");
        const debtChange = dec(100, 18);
        const newTCR = await borrowerOperations.getNewTCRFromTroveChange(
          collChange,
          true,
          debtChange,
          true,
          price,
        );

        const expectedTCR = troveColl
          .add(liquidatedColl)
          .add(toBN(dec(1, "ether")))
          .mul(price)
          .div(troveTotalDebt.add(liquidatedDebt).add(toBN(dec(100, 18))));

        assert.isTrue(newTCR.eq(expectedTCR));
      });

      // +ve, -ve
      it("collChange is positive, debtChange is negative", async () => {
        // --- SETUP --- Create a protocol instance with an Active Pool and pending rewards (Default Pool)
        const troveColl = toBN(dec(1000, "ether"));
        const troveTotalDebt = toBN(dec(100000, 18));
        const troveDebtTokenAmount = await getOpenTroveDebtTokenAmount(troveTotalDebt);
        await borrowerOperations
          .connect(alice)
          .openTrove(th._100pct, troveDebtTokenAmount, alice.address, alice.address, {
            value: troveColl,
          });
        await borrowerOperations
          .connect(bob)
          .openTrove(th._100pct, troveDebtTokenAmount, bob.address, bob.address, {
            value: troveColl,
          });

        await priceFeed.setPrice(dec(100, 18));

        const liquidationTx = await troveManager.liquidate(bob.address);
        assert.isFalse(await sortedTroves.contains(bob.address));

        const [liquidatedDebt, liquidatedColl, gasComp] =
          await th.getEmittedLiquidationValues(liquidationTx);

        await priceFeed.setPrice(dec(200, 18));
        const price = await priceFeed.getPrice();

        // --- TEST ---
        const collChange = dec(1, "ether");
        const debtChange = dec(100, 18);
        const newTCR = await borrowerOperations.getNewTCRFromTroveChange(
          collChange,
          true,
          debtChange,
          false,
          price,
        );

        const expectedTCR = troveColl
          .add(liquidatedColl)
          .add(toBN(dec(1, "ether")))
          .mul(price)
          .div(troveTotalDebt.add(liquidatedDebt).sub(toBN(dec(100, 18))));

        assert.isTrue(newTCR.eq(expectedTCR));
      });

      // -ve, +ve
      it("collChange is negative, debtChange is positive", async () => {
        // --- SETUP --- Create a protocol instance with an Active Pool and pending rewards (Default Pool)
        const troveColl = toBN(dec(1000, "ether"));
        const troveTotalDebt = toBN(dec(100000, 18));
        const troveDebtTokenAmount = await getOpenTroveDebtTokenAmount(troveTotalDebt);
        await borrowerOperations
          .connect(alice)
          .openTrove(th._100pct, troveDebtTokenAmount, alice.address, alice.address, {
            value: troveColl,
          });
        await borrowerOperations
          .connect(bob)
          .openTrove(th._100pct, troveDebtTokenAmount, bob.address, bob.address, {
            value: troveColl,
          });

        await priceFeed.setPrice(dec(100, 18));

        const liquidationTx = await troveManager.liquidate(bob.address);
        assert.isFalse(await sortedTroves.contains(bob.address));

        const [liquidatedDebt, liquidatedColl, gasComp] =
          await th.getEmittedLiquidationValues(liquidationTx);

        await priceFeed.setPrice(dec(200, 18));
        const price = await priceFeed.getPrice();

        // --- TEST ---
        const collChange = dec(1, 18);
        const debtChange = await getNetBorrowingAmount(dec(200, 18));
        const newTCR = await borrowerOperations.getNewTCRFromTroveChange(
          collChange,
          false,
          debtChange,
          true,
          price,
        );

        const expectedTCR = troveColl
          .add(liquidatedColl)
          .sub(toBN(collChange))
          .mul(price)
          .div(troveTotalDebt.add(liquidatedDebt).add(toBN(debtChange)));

        assert.isTrue(newTCR.eq(expectedTCR));
      });
    });

    if (!withProxy) {
      it("closeTrove(): fails if owner cannot receive FIL", async () => {
        const nonPayableFactory = await deploymentHelper.getFactory("NonPayable");
        const nonPayable = await nonPayableFactory.deploy();

        // we need 2 troves to be able to close 1 and have 1 remaining in the system
        await borrowerOperations
          .connect(alice)
          .openTrove(th._100pct, dec(100000, 18), alice.address, alice.address, {
            value: dec(1000, 18),
          });

        // Alice sends debt token to NonPayable so its debt token balance covers its debt
        await debtToken.connect(alice).transfer(nonPayable.address, dec(10000, 18));

        // open trove from NonPayable proxy contract
        const _100pctHex = "0xde0b6b3a7640000";
        const _1e25Hex = "0xd3c21bcecceda1000000";
        const openTroveData = th.getTransactionData("openTrove(uint256,uint256,address,address)", [
          _100pctHex,
          _1e25Hex,
          "0x0",
          "0x0",
        ]);
        await nonPayable.forward(borrowerOperations.address, openTroveData, {
          value: dec(10000, "ether"),
        });
        assert.equal(
          (await troveManager.getTroveStatus(nonPayable.address)).toString(),
          "1",
          "NonPayable proxy should have a trove",
        );
        assert.isFalse(
          await th.checkRecoveryMode(contracts),
          "System should not be in Recovery Mode",
        );
        // open trove from NonPayable proxy contract
        const closeTroveData = th.getTransactionData("closeTrove()", []);
        await th.assertRevert(
          nonPayable.forward(borrowerOperations.address, closeTroveData),
          "ActivePool: sending FIL failed",
        );
      });
    }
  };

  describe("Without proxy", async () => {
    testCorpus({ withProxy: false });
  });

  // describe('With proxy', async () => {
  //   testCorpus({ withProxy: true })
  // })
});

contract("Reset chain state", async () => {});

/* TODO:

 1) Test SortedList re-ordering by ICR. ICR ratio
 changes with addColl, withdrawColl, withdrawDebtToken, repayDebtToken, etc. Can split them up and put them with
 individual functions, or give ordering it's own 'describe' block.

 2)In security phase:
 -'Negative' tests for all the above functions.
 */
