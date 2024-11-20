const deploymentHelper = require("../utils/deploymentHelpers.js");
const { TestHelper: th, MoneyValues: mv } = require("../utils/testHelpers.js");
const { toBN, dec, ZERO_ADDRESS } = th;

contract("TroveManager - in Recovery Mode - back to normal mode in 1 tx", async () => {
  let owner, alice, bob, carol, whale;

  let contracts;
  let troveManager;
  let stabilityPool;
  let priceFeed;
  let sortedTroves;

  const openTrove = async (params) => th.openTrove(contracts, params);

  before(async () => {
    [owner, alice, bob, carol, whale] = await ethers.getSigners();
  });

  beforeEach(async () => {
    await hre.network.provider.send("hardhat_reset");

    const transactionCount = await owner.getTransactionCount();
    const cpTesterContracts = await deploymentHelper.computeContractAddresses(
      owner.address,
      transactionCount,
      5,
    );
    const cpContracts = await deploymentHelper.computeCoreProtocolContracts(
      owner.address,
      transactionCount + 5,
    );

    // Overwrite contracts with computed tester addresses
    cpContracts.troveManager = cpTesterContracts[2];
    cpContracts.debtToken = cpTesterContracts[4];

    const troveManagerTester = await deploymentHelper.deployTroveManagerTester(
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
    contracts.debtToken = debtTokenTester;

    await deploymentHelper.deployProtocolTokenContracts(cpContracts);

    troveManager = contracts.troveManager;
    stabilityPool = contracts.stabilityPool;
    priceFeed = contracts.priceFeedTestnet;
    sortedTroves = contracts.sortedTroves;
  });

  context("Batch liquidations", () => {
    const setup = async () => {
      const { collateral: A_coll, totalDebt: A_totalDebt } = await openTrove({
        ICR: toBN(dec(296, 16)),
        extraParams: { from: alice },
      });
      const { collateral: B_coll, totalDebt: B_totalDebt } = await openTrove({
        ICR: toBN(dec(280, 16)),
        extraParams: { from: bob },
      });
      const { collateral: C_coll, totalDebt: C_totalDebt } = await openTrove({
        ICR: toBN(dec(150, 16)),
        extraParams: { from: carol },
      });

      const totalLiquidatedDebt = A_totalDebt.add(B_totalDebt).add(C_totalDebt);

      await openTrove({
        ICR: toBN(dec(340, 16)),
        extraDebtTokenAmount: totalLiquidatedDebt,
        extraParams: { from: whale },
      });
      await stabilityPool.connect(whale).provideToSP(totalLiquidatedDebt, ZERO_ADDRESS);

      // Price drops
      await priceFeed.setPrice(dec(100, 18));
      const price = await priceFeed.getPrice();
      const TCR = await th.getTCR(contracts);

      // Check Recovery Mode is active
      assert.isTrue(await th.checkRecoveryMode(contracts));

      // Check troves A, B are in range 110% < ICR < TCR, C is below 100%
      const ICR_A = await troveManager.getCurrentICR(alice.address, price);
      const ICR_B = await troveManager.getCurrentICR(bob.address, price);
      const ICR_C = await troveManager.getCurrentICR(carol.address, price);

      assert.isTrue(ICR_A.gt(mv._MCR) && ICR_A.lt(TCR));
      assert.isTrue(ICR_B.gt(mv._MCR) && ICR_B.lt(TCR));
      assert.isTrue(ICR_C.lt(mv._ICR100));

      return {
        A_coll,
        A_totalDebt,
        B_coll,
        B_totalDebt,
        C_coll,
        C_totalDebt,
        totalLiquidatedDebt,
        price,
      };
    };

    it("First trove only doesn’t get out of Recovery Mode", async () => {
      await setup();
      const tx = await troveManager.batchLiquidateTroves([alice.address]);

      const TCR = await th.getTCR(contracts);
      assert.isTrue(await th.checkRecoveryMode(contracts));
    });

    it("Two troves over MCR are liquidated", async () => {
      await setup();
      const tx = await troveManager.batchLiquidateTroves([
        alice.address,
        bob.address,
        carol.address,
      ]);

      const liquidationEvents = await th.getAllEventsByName(tx, "TroveLiquidated");
      assert.equal(liquidationEvents.length, 3, "Not enough liquidations");

      // Confirm all troves removed
      assert.isFalse(await sortedTroves.contains(alice.address));
      assert.isFalse(await sortedTroves.contains(bob.address));
      assert.isFalse(await sortedTroves.contains(carol.address));

      // Confirm troves have status 'closed by liquidation' (Status enum element idx 3)
      assert.equal((await troveManager.Troves(alice.address))[3], "3");
      assert.equal((await troveManager.Troves(bob.address))[3], "3");
      assert.equal((await troveManager.Troves(carol.address))[3], "3");
    });

    it("Stability Pool profit matches", async () => {
      const { A_coll, A_totalDebt, C_coll, C_totalDebt, totalLiquidatedDebt, price } =
        await setup();

      const spEthBefore = await stabilityPool.getFIL();
      const spDebtTokenBefore = await stabilityPool.getTotalDebtTokenDeposits();

      const tx = await troveManager.batchLiquidateTroves([alice.address, carol.address]);

      // Confirm all troves removed
      assert.isFalse(await sortedTroves.contains(alice.address));
      assert.isFalse(await sortedTroves.contains(carol.address));

      // Confirm troves have status 'closed by liquidation' (Status enum element idx 3)
      assert.equal((await troveManager.Troves(alice.address))[3], "3");
      assert.equal((await troveManager.Troves(carol.address))[3], "3");

      const spEthAfter = await stabilityPool.getFIL();
      const spDebtTokenAfter = await stabilityPool.getTotalDebtTokenDeposits();

      // liquidate collaterals with the gas compensation fee subtracted
      const expectedCollateralLiquidatedA = th.applyLiquidationFee(
        A_totalDebt.mul(mv._MCR).div(price),
      );
      const expectedCollateralLiquidatedC = th.applyLiquidationFee(C_coll);
      // Stability Pool gains
      const expectedGainInDebtToken = expectedCollateralLiquidatedA
        .mul(price)
        .div(mv._1e18BN)
        .sub(A_totalDebt);
      const realGainInDebtToken = spEthAfter
        .sub(spEthBefore)
        .mul(price)
        .div(mv._1e18BN)
        .sub(spDebtTokenBefore.sub(spDebtTokenAfter));

      assert.equal(
        spEthAfter.sub(spEthBefore).toString(),
        expectedCollateralLiquidatedA.toString(),
        "Stability Pool FIL doesn’t match",
      );
      assert.equal(
        spDebtTokenBefore.sub(spDebtTokenAfter).toString(),
        A_totalDebt.toString(),
        "Stability Pool DebtToken doesn’t match",
      );
      assert.equal(
        realGainInDebtToken.toString(),
        expectedGainInDebtToken.toString(),
        "Stability Pool gains don’t match",
      );
    });

    it("A trove over TCR is not liquidated", async () => {
      const { collateral: A_coll, totalDebt: A_totalDebt } = await openTrove({
        ICR: toBN(dec(280, 16)),
        extraParams: { from: alice },
      });
      const { collateral: B_coll, totalDebt: B_totalDebt } = await openTrove({
        ICR: toBN(dec(276, 16)),
        extraParams: { from: bob },
      });
      const { collateral: C_coll, totalDebt: C_totalDebt } = await openTrove({
        ICR: toBN(dec(150, 16)),
        extraParams: { from: carol },
      });

      const totalLiquidatedDebt = A_totalDebt.add(B_totalDebt).add(C_totalDebt);

      await openTrove({
        ICR: toBN(dec(310, 16)),
        extraDebtTokenAmount: totalLiquidatedDebt,
        extraParams: { from: whale },
      });
      await stabilityPool.connect(whale).provideToSP(totalLiquidatedDebt, ZERO_ADDRESS);

      // Price drops
      await priceFeed.setPrice(dec(100, 18));
      const price = await priceFeed.getPrice();
      const TCR = await th.getTCR(contracts);

      // Check Recovery Mode is active
      assert.isTrue(await th.checkRecoveryMode(contracts));

      // Check troves A, B are in range 110% < ICR < TCR, C is below 100%
      const ICR_A = await troveManager.getCurrentICR(alice.address, price);
      const ICR_B = await troveManager.getCurrentICR(bob.address, price);
      const ICR_C = await troveManager.getCurrentICR(carol.address, price);

      assert.isTrue(ICR_A.gt(TCR));
      assert.isTrue(ICR_B.gt(mv._MCR) && ICR_B.lt(TCR));
      assert.isTrue(ICR_C.lt(mv._ICR100));

      const tx = await troveManager.batchLiquidateTroves([bob.address, alice.address]);

      const liquidationEvents = await th.getAllEventsByName(tx, "TroveLiquidated");
      assert.equal(liquidationEvents.length, 1, "Not enough liquidations");

      // Confirm only Bob’s trove removed
      assert.isTrue(await sortedTroves.contains(alice.address));
      assert.isFalse(await sortedTroves.contains(bob.address));
      assert.isTrue(await sortedTroves.contains(carol.address));

      // Confirm troves have status 'closed by liquidation' (Status enum element idx 3)
      assert.equal((await troveManager.Troves(bob.address))[3], "3");
      // Confirm troves have status 'open' (Status enum element idx 1)
      assert.equal((await troveManager.Troves(alice.address))[3], "1");
      assert.equal((await troveManager.Troves(carol.address))[3], "1");
    });
  });

  context("Sequential liquidations", () => {
    const setup = async () => {
      const { collateral: A_coll, totalDebt: A_totalDebt } = await openTrove({
        ICR: toBN(dec(299, 16)),
        extraParams: { from: alice },
      });
      const { collateral: B_coll, totalDebt: B_totalDebt } = await openTrove({
        ICR: toBN(dec(298, 16)),
        extraParams: { from: bob },
      });

      const totalLiquidatedDebt = A_totalDebt.add(B_totalDebt);

      await openTrove({
        ICR: toBN(dec(300, 16)),
        extraDebtTokenAmount: totalLiquidatedDebt,
        extraParams: { from: whale },
      });
      await stabilityPool.connect(whale).provideToSP(totalLiquidatedDebt, ZERO_ADDRESS);

      // Price drops
      await priceFeed.setPrice(dec(100, 18));
      const price = await priceFeed.getPrice();
      const TCR = await th.getTCR(contracts);

      // Check Recovery Mode is active
      assert.isTrue(await th.checkRecoveryMode(contracts));

      // Check troves A, B are in range 110% < ICR < TCR, C is below 100%
      const ICR_A = await troveManager.getCurrentICR(alice.address, price);
      const ICR_B = await troveManager.getCurrentICR(bob.address, price);

      assert.isTrue(ICR_A.gt(mv._MCR) && ICR_A.lt(TCR));
      assert.isTrue(ICR_B.gt(mv._MCR) && ICR_B.lt(TCR));

      return {
        A_coll,
        A_totalDebt,
        B_coll,
        B_totalDebt,
        totalLiquidatedDebt,
        price,
      };
    };

    it("First trove only doesn’t get out of Recovery Mode", async () => {
      await setup();
      const tx = await troveManager.liquidateTroves(1);

      const TCR = await th.getTCR(contracts);
      assert.isTrue(await th.checkRecoveryMode(contracts));
    });

    it("Two troves over MCR are liquidated", async () => {
      await setup();
      const tx = await troveManager.liquidateTroves(10);

      const liquidationEvents = await th.getAllEventsByName(tx, "TroveLiquidated");
      assert.equal(liquidationEvents.length, 2, "Not enough liquidations");

      // Confirm all troves removed
      assert.isFalse(await sortedTroves.contains(alice.address));
      assert.isFalse(await sortedTroves.contains(bob.address));

      // Confirm troves have status 'closed by liquidation' (Status enum element idx 3)
      assert.equal((await troveManager.Troves(alice.address))[3], "3");
      assert.equal((await troveManager.Troves(bob.address))[3], "3");
    });
  });
});
