const deploymentHelper = require("../utils/testDeploymentHelpers.js");
const testHelpers = require("../utils/testHelpers.js");

const th = testHelpers.TestHelper;
const dec = th.dec;
const toBN = th.toBN;

contract("StabilityPool Scale Factor issue tests", async () => {
  let owner, whale, A, B, C, D, E, F, F1, F2, F3;

  let contracts;

  let priceFeed;
  let debtToken;
  let stabilityPool;
  let sortedTroves;
  let troveManager;
  let borrowerOperations;

  const ZERO_ADDRESS = th.ZERO_ADDRESS;

  const getOpenTroveDebtTokenAmount = async (totalDebt) =>
    th.getOpenTroveDebtTokenAmount(contracts, totalDebt);
  const openTrove = async (params) => th.openTrove(contracts, params);
  const getDebtTokenAmountForDesiredDebt = async (desiredDebt) =>
    (await getOpenTroveDebtTokenAmount(dec(desiredDebt, 18))).add(th.toBN(1));

  before(async () => {
    [owner, whale, A, B, C, D, E, F, F1, F2, F3] = await ethers.getSigners();
  });

  describe("Scale Factor issue tests", async () => {
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

      await deploymentHelper.deployProtocolTokenTesterContracts(owner.address, cpContracts);

      contracts.troveManager = troveManagerTester;
      contracts.debtToken = debtTokenTester;

      priceFeed = contracts.priceFeedTestnet;
      debtToken = contracts.debtToken;
      stabilityPool = contracts.stabilityPool;
      sortedTroves = contracts.sortedTroves;
      troveManager = contracts.troveManager;
      stabilityPool = contracts.stabilityPool;
      borrowerOperations = contracts.borrowerOperations;

      await priceFeed.setPrice(dec(200, 18));

      // Register 3 front ends
      const kickbackRate_F1 = toBN(dec(5, 17)); // F1 kicks 50% back to depositor
      const kickbackRate_F2 = toBN(dec(80, 16)); // F2 kicks 80% back to depositor
      const kickbackRate_F3 = toBN(dec(1, 18)); // F2 kicks 100% back to depositor

      await stabilityPool.connect(F1).registerFrontEnd(kickbackRate_F1);
      await stabilityPool.connect(F2).registerFrontEnd(kickbackRate_F2);
      await stabilityPool.connect(F3).registerFrontEnd(kickbackRate_F3);
    });

    it("1. Liquidation succeeds after P would otherwise be reduced to 1", async () => {
      // Whale opens Trove with 100k FIL and sends 50k DebtToken to A
      await borrowerOperations
        .connect(whale)
        .openTrove(
          th._100pct,
          await getOpenTroveDebtTokenAmount(dec(100000, 18)),
          whale.address,
          whale.address,
          {
            value: dec(100000, "ether"),
          },
        );
      await debtToken.connect(whale).transfer(A.address, dec(50000, 18));

      // Open 3 Troves with 2000 DebtToken debt
      for (account of [A, B, C]) {
        await borrowerOperations
          .connect(account)
          .openTrove(
            th._100pct,
            await getDebtTokenAmountForDesiredDebt(2000),
            account.address,
            account.address,
            {
              value: dec(15, "ether"),
            },
          );
        assert.isTrue(
          (await th.getTroveEntireDebt(contracts, account.address)).eq(th.toBN(dec(2000, 18))),
        );
      }

      // A  deposits to SP - i.e. minimum needed to reduce P to 1e9 from a 2000 debt liquidation
      const deposit_0 = th.toBN("2000000000000000002001");
      await stabilityPool.connect(A).provideToSP(deposit_0, ZERO_ADDRESS);

      console.log("P0:");
      const P_0 = await stabilityPool.P();
      console.log(P_0.toString());
      assert.equal(P_0, dec(1, 18));

      // Price drop -> liquidate Trove A -> price rises
      await priceFeed.setPrice(dec(100, 18));
      await troveManager.connect(owner).liquidate(A.address);
      assert.equal(await troveManager.getTroveStatus(A.address), 3); // status: closed by liq
      await priceFeed.setPrice(dec(200, 18));

      // Check P reduced by factor of 1e9
      const P_1 = await stabilityPool.P();
      assert.equal(P_1, dec(1, 9));
      console.log("P1:");
      console.log(P_1.toString());

      // A re-fills SP back up to deposit 0 level, i.e. just enough to reduce P by 1e9 from a 2k debt liq.
      const deposit_1 = deposit_0.sub(await stabilityPool.getTotalDebtTokenDeposits());
      await stabilityPool.connect(A).provideToSP(deposit_1, ZERO_ADDRESS);

      // Price drop -> liquidate Trove B -> price rises
      await priceFeed.setPrice(dec(100, 18));
      await troveManager.connect(owner).liquidate(B.address);
      assert.equal(await troveManager.getTroveStatus(B.address), 3); // status: closed by liq
      await priceFeed.setPrice(dec(200, 18));

      // Check P reduced by factor of 1e9 and re-scaled to preserve the minimum P invariant
      const P_2 = await stabilityPool.P();
      assert.isTrue(P_2.eq(th.toBN(1e9)));
      console.log("P2:");
      console.log(P_2.toString());

      // A re-fills SP to same pre-liq level again
      const deposit_2 = deposit_0.sub(await stabilityPool.getTotalDebtTokenDeposits());
      await stabilityPool.connect(A).provideToSP(deposit_2, ZERO_ADDRESS);

      // Price drop -> liquidate Trove C -> price rises
      await priceFeed.setPrice(dec(100, 18));
      await troveManager.connect(owner).liquidate(C.address);
      assert.equal(await troveManager.getTroveStatus(C.address), 3); // status: closed by liq
      await priceFeed.setPrice(dec(200, 18));

      // The final liquidation succeeds and P remains above the scale boundary.
      const P_3 = await stabilityPool.P();
      assert.isTrue(P_3.gte(th.toBN(1e9)));
    });

    it("2. New deposits can be made after P would otherwise be reduced to 1", async () => {
      // Whale opens Trove with 100k FIL and sends 50k DebtToken to A
      await borrowerOperations
        .connect(whale)
        .openTrove(
          th._100pct,
          await getOpenTroveDebtTokenAmount(dec(100000, 18)),
          whale.address,
          whale.address,
          {
            value: dec(100000, "ether"),
          },
        );
      await debtToken.connect(whale).transfer(A.address, dec(50000, 18));

      // Open 3 Troves with 2000 DebtToken debt
      for (account of [A, B, C]) {
        await borrowerOperations
          .connect(account)
          .openTrove(
            th._100pct,
            await getDebtTokenAmountForDesiredDebt(2000),
            account.address,
            account.address,
            {
              value: dec(15, "ether"),
            },
          );
        assert.isTrue(
          (await th.getTroveEntireDebt(contracts, account.address)).eq(th.toBN(dec(2000, 18))),
        );
      }

      // A  deposits to SP - i.e. minimum needed to reduce P to 1e9 from a 2000 debt liquidation
      const deposit_0 = th.toBN("2000000000000000002001");
      await stabilityPool.connect(A).provideToSP(deposit_0, ZERO_ADDRESS);

      console.log("P0:");
      const P_0 = await stabilityPool.P();
      console.log(P_0.toString());
      assert.equal(P_0, dec(1, 18));

      // Price drop -> liquidate Trove A -> price rises
      await priceFeed.setPrice(dec(100, 18));
      await troveManager.connect(owner).liquidate(A.address);
      assert.equal(await troveManager.getTroveStatus(A.address), 3); // status: closed by liq
      await priceFeed.setPrice(dec(200, 18));

      // Check P reduced by factor of 1e9
      const P_1 = await stabilityPool.P();
      assert.equal(P_1, dec(1, 9));
      console.log("P1:");
      console.log(P_1.toString());

      // A re-fills SP back up to deposit 0 level, i.e. just enough to reduce P by 1e9 from a 2k debt liq.
      const deposit_1 = deposit_0.sub(await stabilityPool.getTotalDebtTokenDeposits());
      await stabilityPool.connect(A).provideToSP(deposit_1, ZERO_ADDRESS);

      // Price drop -> liquidate Trove B -> price rises
      await priceFeed.setPrice(dec(100, 18));
      await troveManager.connect(owner).liquidate(B.address);
      assert.equal(await troveManager.getTroveStatus(B.address), 3); // status: closed by liq
      await priceFeed.setPrice(dec(200, 18));

      // Check P reduced by factor of 1e9 and re-scaled to preserve the minimum P invariant
      const P_2 = await stabilityPool.P();
      assert.equal(P_2, dec(1, 9));
      console.log("P2:");
      console.log(P_2.toString());

      // A re-fills SP to same pre-liq level again
      const deposit_2 = deposit_0.sub(await stabilityPool.getTotalDebtTokenDeposits());
      await stabilityPool.connect(A).provideToSP(deposit_2, ZERO_ADDRESS);

      // Whale gives DebtToken to D,E,F
      const newDeposits = [th.toBN(1), th.toBN(dec(10000, 18)), th.toBN(dec(20000, 18))];
      const newDepositors = [D, E, F];
      const frontEnds = [ZERO_ADDRESS, F1.address, F2.address];

      for (let i = 0; i < 3; i++) {
        await debtToken.connect(whale).transfer(newDepositors[i].address, newDeposits[i]);
        await stabilityPool.connect(newDepositors[i]).provideToSP(newDeposits[i], frontEnds[i]);
        assert.isTrue(
          (await stabilityPool.getCompoundedDebtTokenDeposit(newDepositors[i].address)).eq(
            newDeposits[i],
          ),
        );
      }
    });

    it("3. Liquidation succeeds after P normalization when newProductFactor == 1e9", async () => {
      // Whale opens Trove with 100k FIL and sends 50k DebtToken to A
      await borrowerOperations
        .connect(whale)
        .openTrove(
          th._100pct,
          await getOpenTroveDebtTokenAmount(dec(100000, 18)),
          whale.address,
          whale.address,
          {
            value: dec(100000, "ether"),
          },
        );
      await debtToken.connect(whale).transfer(A.address, dec(50000, 18));

      // Open 3 Troves with 2000 DebtToken debt
      for (account of [A, B, C]) {
        await borrowerOperations
          .connect(account)
          .openTrove(
            th._100pct,
            await getDebtTokenAmountForDesiredDebt(2000),
            account.address,
            account.address,
            {
              value: dec(15, "ether"),
            },
          );
        assert.isTrue(
          (await th.getTroveEntireDebt(contracts, account.address)).eq(th.toBN(dec(2000, 18))),
        );
      }

      // A  deposits to SP - i.e. minimum needed to reduce P to 1e9 from a 2000 debt liquidation
      const deposit_0 = th.toBN("2000000000000000002001");
      await stabilityPool.connect(A).provideToSP(deposit_0, ZERO_ADDRESS);

      console.log("P0:");
      const P_0 = await stabilityPool.P();
      console.log(P_0.toString());
      assert.equal(P_0, dec(1, 18));
      let scale = (await stabilityPool.currentScale()).toString();
      assert.equal(scale, "0");
      console.log("scale:");
      console.log(scale);

      // Price drop -> liquidate Trove A -> price rises
      await priceFeed.setPrice(dec(100, 18));
      await troveManager.connect(owner).liquidate(A.address);
      console.log("LIQ 1");
      assert.equal(await troveManager.getTroveStatus(A.address), 3); // status: closed by liq
      await priceFeed.setPrice(dec(200, 18));

      // Check P reduced by factor of 1e9
      const P_1 = await stabilityPool.P();
      assert.equal(P_1, dec(1, 9));
      console.log("P1:");
      console.log(P_1.toString());
      scale = (await stabilityPool.currentScale()).toString();
      assert.equal(scale, "1");
      console.log("scale:");
      console.log(scale);

      // A re-fills SP back up to deposit 0 level, i.e. just enough to reduce P by 1e9 from a 2k debt liq.
      const deposit_1 = deposit_0.sub(await stabilityPool.getTotalDebtTokenDeposits());
      await stabilityPool.connect(A).provideToSP(deposit_1, ZERO_ADDRESS);

      // Price drop -> liquidate Trove B -> price rises
      await priceFeed.setPrice(dec(100, 18));
      await troveManager.connect(owner).liquidate(B.address);
      console.log("LIQ 2");
      assert.equal(await troveManager.getTroveStatus(B.address), 3); // status: closed by liq
      await priceFeed.setPrice(dec(200, 18));

      // Check P reduced by factor of 1e9 and re-scaled to preserve the minimum P invariant
      const P_2 = await stabilityPool.P();
      assert.isTrue(P_2.eq(th.toBN(1e9)));
      console.log("P2:");
      console.log(P_2.toString());
      scale = (await stabilityPool.currentScale()).toString();
      assert.equal(scale, "3");
      console.log("scale:");
      console.log(scale);

      // A re-fills SP to ~1.000000001x pre-liq level, i.e. to trigger a newProductFactor == 1e9,
      // (and trigger scale change)
      const deposit_2 = deposit_0
        .sub(await stabilityPool.getTotalDebtTokenDeposits())
        .add(th.toBN(dec(2, 12)));
      await stabilityPool.connect(A).provideToSP(deposit_2, ZERO_ADDRESS);

      // Price drop -> liquidate Trove C -> price rises
      await priceFeed.setPrice(dec(100, 18));
      await troveManager.connect(owner).liquidate(C.address);
      console.log("LIQ 3");
      assert.equal(await troveManager.getTroveStatus(C.address), 3); // status: closed by liq
      await priceFeed.setPrice(dec(200, 18));

      // Check P remains at the minimum value after a further scale change.
      const P_3 = await stabilityPool.P();
      assert.isTrue(P_3.eq(th.toBN(1e9)));
      console.log("P_3:");
      console.log(P_3.toString());
      scale = (await stabilityPool.currentScale()).toString();
      assert.equal(scale, "4");
      console.log("scale:");
      console.log(scale);
    });

    it("4. Liquidation succeeds after P normalization when newProductFactor > 1e9", async () => {
      // Whale opens Trove with 100k FIL and sends 50k DebtToken to A
      await borrowerOperations
        .connect(whale)
        .openTrove(
          th._100pct,
          await getOpenTroveDebtTokenAmount(dec(100000, 18)),
          whale.address,
          whale.address,
          {
            value: dec(100000, "ether"),
          },
        );
      await debtToken.connect(whale).transfer(A.address, dec(50000, 18));

      // Open 3 Troves with 2000 DebtToken debt
      for (account of [A, B, C]) {
        await borrowerOperations
          .connect(account)
          .openTrove(
            th._100pct,
            await getDebtTokenAmountForDesiredDebt(2000),
            account.address,
            account.address,
            {
              value: dec(15, "ether"),
            },
          );
        assert.isTrue(
          (await th.getTroveEntireDebt(contracts, account.address)).eq(th.toBN(dec(2000, 18))),
        );
      }

      // A  deposits to SP - i.e. minimum needed to reduce P to 1e9 from a 2000 debt liquidation
      const deposit_0 = th.toBN("2000000000000000002001");
      await stabilityPool.connect(A).provideToSP(deposit_0, ZERO_ADDRESS);

      console.log("P0:");
      const P_0 = await stabilityPool.P();
      console.log(P_0.toString());
      assert.equal(P_0, dec(1, 18));
      let scale = (await stabilityPool.currentScale()).toString();
      assert.equal(scale, "0");
      console.log("scale:");
      console.log(scale);

      // Price drop -> liquidate Trove A -> price rises
      await priceFeed.setPrice(dec(100, 18));
      await troveManager.connect(owner).liquidate(A.address);
      console.log("LIQ 1");
      assert.equal(await troveManager.getTroveStatus(A.address), 3); // status: closed by liq
      await priceFeed.setPrice(dec(200, 18));

      // Check P reduced by factor of 1e9
      const P_1 = await stabilityPool.P();
      assert.equal(P_1, dec(1, 9));
      console.log("P1:");
      console.log(P_1.toString());
      scale = (await stabilityPool.currentScale()).toString();
      assert.equal(scale, "1");
      console.log("scale:");
      console.log(scale);

      // A re-fills SP back up to deposit 0 level, i.e. just enough to reduce P by 1e9 from a 2k debt liq.
      const deposit_1 = deposit_0.sub(await stabilityPool.getTotalDebtTokenDeposits());
      await stabilityPool.connect(A).provideToSP(deposit_1, ZERO_ADDRESS);

      // Price drop -> liquidate Trove B -> price rises
      await priceFeed.setPrice(dec(100, 18));
      await troveManager.connect(owner).liquidate(B.address);
      console.log("LIQ 2");
      assert.equal(await troveManager.getTroveStatus(B.address), 3); // status: closed by liq
      await priceFeed.setPrice(dec(200, 18));

      // Check P reduced by factor of 1e9 and re-scaled to preserve the minimum P invariant
      const P_2 = await stabilityPool.P();
      assert.isTrue(P_2.eq(th.toBN(1e9)));
      console.log("P2:");
      console.log(P_2.toString());
      scale = (await stabilityPool.currentScale()).toString();
      assert.equal(scale, "3");
      console.log("scale:");
      console.log(scale);

      // A re-fills SP to ~2x pre-liq level, i.e. to trigger a newProductFactor > 1e9,
      // and trigger scale change and *increase* raw value of P again.
      const deposit_2 = deposit_0
        .mul(th.toBN(2))
        .sub(await stabilityPool.getTotalDebtTokenDeposits());
      await stabilityPool.connect(A).provideToSP(deposit_2, ZERO_ADDRESS);

      // Price drop -> liquidate Trove C -> price rises
      await priceFeed.setPrice(dec(100, 18));
      await troveManager.connect(owner).liquidate(C.address);
      console.log("LIQ 3");
      assert.equal(await troveManager.getTroveStatus(C.address), 3); // status: closed by liq
      await priceFeed.setPrice(dec(200, 18));

      // Check P tracks the 50% depletion while remaining above the scale boundary.
      const P_3 = await stabilityPool.P();
      assert.isTrue(P_3.eq(th.toBN(dec(5, 17))));
      console.log("P_3:");
      console.log(P_3.toString());
      scale = (await stabilityPool.currentScale()).toString();
      assert.equal(scale, "4");
      console.log("scale:");
      console.log(scale);
    });

    // --- Check depositors have correct stakes after experiencing scale change from depositing when P is tiny  ---

    it("5. Depositors have correct depleted stake after double-scale normalization when newProductFactor == 1e9", async () => {
      // Whale opens Trove with 100k FIL and sends 50k DebtToken to A
      await borrowerOperations
        .connect(whale)
        .openTrove(
          th._100pct,
          await getOpenTroveDebtTokenAmount(dec(100000, 18)),
          whale.address,
          whale.address,
          {
            value: dec(100000, "ether"),
          },
        );
      await debtToken.connect(whale).transfer(A.address, dec(50000, 18));

      // Open 3 Troves with 2000 DebtToken debt
      for (account of [A, B, C]) {
        await borrowerOperations
          .connect(account)
          .openTrove(
            th._100pct,
            await getDebtTokenAmountForDesiredDebt(2000),
            account.address,
            account.address,
            {
              value: dec(15, "ether"),
            },
          );
        assert.isTrue(
          (await th.getTroveEntireDebt(contracts, account.address)).eq(th.toBN(dec(2000, 18))),
        );
      }

      // A  deposits to SP - i.e. minimum needed to reduce P to 1e9 from a 2000 debt liquidation
      const deposit_0 = th.toBN("2000000000000000002001");
      await stabilityPool.connect(A).provideToSP(deposit_0, ZERO_ADDRESS);

      console.log("P0:");
      const P_0 = await stabilityPool.P();
      console.log(P_0.toString());
      assert.equal(P_0, dec(1, 18));
      let scale = (await stabilityPool.currentScale()).toString();
      assert.equal(scale, "0");
      console.log("scale:");
      console.log(scale);

      // Price drop -> liquidate Trove A -> price rises
      await priceFeed.setPrice(dec(100, 18));
      await troveManager.connect(owner).liquidate(A.address);
      console.log("LIQ 1");
      assert.equal(await troveManager.getTroveStatus(A.address), 3); // status: closed by liq
      await priceFeed.setPrice(dec(200, 18));

      // Check P reduced by factor of 1e9
      const P_1 = await stabilityPool.P();
      assert.equal(P_1, dec(1, 9));
      console.log("P1:");
      console.log(P_1.toString());
      scale = (await stabilityPool.currentScale()).toString();
      assert.equal(scale, "1");
      console.log("scale:");
      console.log(scale);

      // A re-fills SP back up to deposit 0 level, i.e. just enough to reduce P by 1e9 from a 2k debt liq.
      const deposit_1 = deposit_0.sub(await stabilityPool.getTotalDebtTokenDeposits());
      await stabilityPool.connect(A).provideToSP(deposit_1, ZERO_ADDRESS);

      // Price drop -> liquidate Trove B -> price rises
      await priceFeed.setPrice(dec(100, 18));
      await troveManager.connect(owner).liquidate(B.address);
      console.log("LIQ 2");
      assert.equal(await troveManager.getTroveStatus(B.address), 3); // status: closed by liq
      await priceFeed.setPrice(dec(200, 18));

      // Check P reduced by factor of 1e9 and re-scaled to preserve the minimum P invariant
      const P_2 = await stabilityPool.P();
      assert.isTrue(P_2.eq(th.toBN(1e9)));
      console.log("P2:");
      console.log(P_2.toString());
      scale = (await stabilityPool.currentScale()).toString();
      assert.equal(scale, "3");
      console.log("scale:");
      console.log(scale);

      // D makes deposit of 1000 DebtToken
      const D_deposit = dec(1, 21);
      await debtToken.connect(whale).transfer(D.address, dec(1, 21));
      await stabilityPool.connect(D).provideToSP(D_deposit, ZERO_ADDRESS);

      // A re-fills SP to ~1.000000001x pre-liq level, i.e. to trigger a newProductFactor == 1e9,
      // (and trigger scale change)
      const deposit_2 = deposit_0
        .sub(await stabilityPool.getTotalDebtTokenDeposits())
        .add(th.toBN(dec(2, 12)));
      await stabilityPool.connect(A).provideToSP(deposit_2, ZERO_ADDRESS);

      // Price drop -> liquidate Trove C -> price rises
      await priceFeed.setPrice(dec(100, 18));
      await troveManager.connect(owner).liquidate(C.address);
      console.log("LIQ 3");
      assert.equal(await troveManager.getTroveStatus(C.address), 3); // status: closed by liq
      await priceFeed.setPrice(dec(200, 18));

      // Check the liquidation succeeds and P remains at the minimum value.
      const P_3 = await stabilityPool.P();
      assert.isTrue(P_3.eq(th.toBN(1e9)));
      console.log("P_3:");
      console.log(P_3.toString());
      scale = (await stabilityPool.currentScale()).toString();
      assert.equal(scale, "4");
      console.log("scale:");
      console.log(scale);

      // Check D's deposit has depleted to a billion'th of their initial deposit. That is, from 1e21 to 1e(21-9) = 1e12
      const D_depletedDeposit = await stabilityPool.getCompoundedDebtTokenDeposit(D.address);
      assert.isTrue(D_depletedDeposit.eq(th.toBN(dec(1, 12))));
      console.log("D_depletedDeposit:");
      console.log(D_depletedDeposit.toString());
    });

    it("6. Depositors have correct depleted stake after double-scale normalization when newProductFactor > 1e9", async () => {
      // Whale opens Trove with 100k FIL and sends 50k DebtToken to A
      await borrowerOperations
        .connect(whale)
        .openTrove(
          th._100pct,
          await getOpenTroveDebtTokenAmount(dec(100000, 18)),
          whale.address,
          whale.address,
          {
            value: dec(100000, "ether"),
          },
        );
      await debtToken.connect(whale).transfer(A.address, dec(50000, 18));

      // Open 3 Troves with 2000 DebtToken debt
      for (account of [A, B, C]) {
        await borrowerOperations
          .connect(account)
          .openTrove(
            th._100pct,
            await getDebtTokenAmountForDesiredDebt(2000),
            account.address,
            account.address,
            {
              value: dec(15, "ether"),
            },
          );
        assert.isTrue(
          (await th.getTroveEntireDebt(contracts, account.address)).eq(th.toBN(dec(2000, 18))),
        );
      }

      // A  deposits to SP - i.e. minimum needed to reduce P to 1e9 from a 2000 debt liquidation
      const deposit_0 = th.toBN("2000000000000000002001");
      await stabilityPool.connect(A).provideToSP(deposit_0, ZERO_ADDRESS);

      console.log("P0:");
      const P_0 = await stabilityPool.P();
      console.log(P_0.toString());
      assert.equal(P_0, dec(1, 18));
      let scale = (await stabilityPool.currentScale()).toString();
      assert.equal(scale, "0");
      console.log("scale:");
      console.log(scale);

      // Price drop -> liquidate Trove A -> price rises
      await priceFeed.setPrice(dec(100, 18));
      await troveManager.connect(owner).liquidate(A.address);
      console.log("LIQ 1");
      assert.equal(await troveManager.getTroveStatus(A.address), 3); // status: closed by liq
      await priceFeed.setPrice(dec(200, 18));

      // Check P reduced by factor of 1e9
      const P_1 = await stabilityPool.P();
      assert.equal(P_1, dec(1, 9));
      console.log("P1:");
      console.log(P_1.toString());
      scale = (await stabilityPool.currentScale()).toString();
      assert.equal(scale, "1");
      console.log("scale:");
      console.log(scale);

      // A re-fills SP back up to deposit 0 level, i.e. just enough to reduce P by 1e9 from a 2k debt liq.
      const deposit_1 = deposit_0.sub(await stabilityPool.getTotalDebtTokenDeposits());
      await stabilityPool.connect(A).provideToSP(deposit_1, ZERO_ADDRESS);

      // Price drop -> liquidate Trove B -> price rises
      await priceFeed.setPrice(dec(100, 18));
      await troveManager.connect(owner).liquidate(B.address);
      console.log("LIQ 2");
      assert.equal(await troveManager.getTroveStatus(B.address), 3); // status: closed by liq
      await priceFeed.setPrice(dec(200, 18));

      // Check P reduced by factor of 1e9 and re-scaled to preserve the minimum P invariant
      const P_2 = await stabilityPool.P();
      assert.isTrue(P_2.eq(th.toBN(1e9)));
      console.log("P2:");
      console.log(P_2.toString());
      scale = (await stabilityPool.currentScale()).toString();
      assert.equal(scale, "3");
      console.log("scale:");
      console.log(scale);

      // D makes deposit of 1000 DebtToken
      const D_deposit = dec(1, 21);
      await debtToken.connect(whale).transfer(D.address, dec(1, 21));
      await stabilityPool.connect(D).provideToSP(D_deposit, ZERO_ADDRESS);

      // A re-fills SP to ~2x pre-liq level, i.e. to trigger a newProductFactor > 1e9,
      // and trigger scale change and *increase* raw value of P again.
      const deposit_2 = deposit_0
        .mul(th.toBN(2))
        .sub(await stabilityPool.getTotalDebtTokenDeposits());
      await stabilityPool.connect(A).provideToSP(deposit_2, ZERO_ADDRESS);

      // Price drop -> liquidate Trove C -> price rises
      await priceFeed.setPrice(dec(100, 18));
      await troveManager.connect(owner).liquidate(C.address);
      console.log("LIQ 3");
      assert.equal(await troveManager.getTroveStatus(C.address), 3); // status: closed by liq
      await priceFeed.setPrice(dec(200, 18));

      // Check P tracks the 50% depletion while remaining above the scale boundary.
      const P_3 = await stabilityPool.P();
      assert.isTrue(P_3.eq(th.toBN(dec(5, 17))));
      console.log("P_3:");
      console.log(P_3.toString());
      scale = (await stabilityPool.currentScale()).toString();
      assert.equal(scale, "4");
      console.log("scale:");
      console.log(scale);

      // Check D's deposit has depleted to 50% their initial deposit. That is, from 1e21 to 5e20.
      const D_depletedDeposit = await stabilityPool.getCompoundedDebtTokenDeposit(D.address);
      assert.isTrue(D_depletedDeposit.eq(th.toBN(dec(5, 20))));
      console.log("D_depletedDeposit:");
      console.log(D_depletedDeposit.toString());
    });
  });
});
