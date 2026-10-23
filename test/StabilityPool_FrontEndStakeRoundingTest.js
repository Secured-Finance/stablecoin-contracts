const deploymentHelper = require("../utils/testDeploymentHelpers.js");
const testHelpers = require("../utils/testHelpers.js");

const th = testHelpers.TestHelper;
const dec = th.dec;
const toBN = th.toBN;
const ZERO_ADDRESS = th.ZERO_ADDRESS;

contract("StabilityPool - front-end stake rounding", async () => {
  let owner;
  let whale;
  let depositor;
  let helper;
  let defaulter_1;
  let defaulter_2;
  let frontEnd;

  let contracts;
  let priceFeed;
  let debtToken;
  let stabilityPool;
  let borrowerOperations;

  const P0 = toBN(dec(1, 18));
  const P1 = toBN("318930084728938849");
  const P2 = toBN("281979778350162457");
  const BASE_DEPOSIT = toBN("95660000000000000000000");
  const DECIMAL_PRECISION = toBN(dec(1, 18));

  const ceilDiv = (numerator, denominator) => numerator.add(denominator.sub(1)).div(denominator);

  const findRoundingDeposit = () => {
    for (let i = 0; i < 100000; i++) {
      const deposit = BASE_DEPOSIT.add(toBN(i.toString()));
      const compoundedAtP1 = deposit.mul(P1).div(P0);
      const compoundedAtP2 = deposit.mul(P2).div(P0);
      const frontEndCompoundedAtP2 = compoundedAtP1.mul(P2).div(P1);

      if (compoundedAtP2.eq(frontEndCompoundedAtP2.add(1))) {
        return { deposit, compoundedAtP1 };
      }
    }

    throw new Error("No rounding drift case found");
  };

  const findHelperDeposit = (deposit, compoundedAtP1) => {
    for (let i = 1; i < 1000; i++) {
      const helperDeposit = toBN(i.toString());
      const helperCompoundedAtP1 = helperDeposit.mul(P1).div(P0);

      if (helperCompoundedAtP1.isZero()) {
        continue;
      }

      const aggregateAtP1 = deposit.add(helperDeposit).mul(P1).div(P0);

      if (aggregateAtP1.eq(compoundedAtP1.add(helperCompoundedAtP1))) {
        return helperDeposit;
      }
    }

    throw new Error("No helper deposit found to reproduce the resnapshot path");
  };

  const getDebtTokenAmountForDesiredTotalDebt = async (desiredTotalDebt) => {
    const borrowingRate = await contracts.troveManager.getBorrowingRateWithDecay();
    const actualDebt = desiredTotalDebt.sub(th.GAS_COMPENSATION);

    return actualDebt.mul(DECIMAL_PRECISION).div(DECIMAL_PRECISION.add(borrowingRate));
  };

  before(async () => {
    [owner, whale, depositor, helper, defaulter_1, defaulter_2, frontEnd] =
      await ethers.getSigners();
  });

  beforeEach(async () => {
    await hre.network.provider.send("hardhat_reset");

    const transactionCount = await owner.getTransactionCount();
    const cpContracts = await deploymentHelper.computeCoreProtocolContracts(
      owner.address,
      transactionCount + 1,
    );

    contracts = await deploymentHelper.deployProtocolCore(
      th.GAS_COMPENSATION,
      th.MIN_NET_DEBT,
      cpContracts,
    );
    await deploymentHelper.deployProtocolTokenContracts(owner.address, cpContracts);

    priceFeed = contracts.priceFeedTestnet;
    debtToken = contracts.debtToken;
    stabilityPool = contracts.stabilityPool;
    borrowerOperations = contracts.borrowerOperations;

    await priceFeed.setPrice(dec(200, 18));
  });

  it("allows withdrawal when rounding leaves the front-end stake 1 wei below the deposit", async () => {
    const { deposit, compoundedAtP1 } = findRoundingDeposit();
    const helperDeposit = findHelperDeposit(deposit, compoundedAtP1);

    await stabilityPool.connect(frontEnd).registerFrontEnd(dec(5, 17));

    const whaleTotalDebt = toBN(dec(500000, 18));
    const whaleDebtTokenAmount = await getDebtTokenAmountForDesiredTotalDebt(whaleTotalDebt);
    await borrowerOperations
      .connect(whale)
      .openTrove(th._100pct, whaleDebtTokenAmount, ZERO_ADDRESS, ZERO_ADDRESS, {
        value: whaleTotalDebt.div(50),
      });

    await debtToken.connect(whale).transfer(depositor.address, deposit);
    await debtToken.connect(whale).transfer(helper.address, helperDeposit);

    await stabilityPool.connect(depositor).provideToSP(deposit, frontEnd.address);
    await stabilityPool.connect(helper).provideToSP(helperDeposit, frontEnd.address);

    const initialTotalDeposits = await stabilityPool.getTotalDebtTokenDeposits();
    const firstLossFactor = DECIMAL_PRECISION.sub(P1);
    const firstOffsetNumerator = firstLossFactor.sub(1).mul(initialTotalDeposits);
    const firstDebtToOffset = ceilDiv(firstOffsetNumerator, DECIMAL_PRECISION);
    const firstCollateral = firstDebtToOffset.div(100);
    const firstDebtTokenAmount = await getDebtTokenAmountForDesiredTotalDebt(firstDebtToOffset);
    const firstHints = await th.getBorrowerOpsListHint(
      contracts,
      firstCollateral,
      firstDebtToOffset,
    );

    await borrowerOperations
      .connect(defaulter_1)
      .openTrove(th._100pct, firstDebtTokenAmount, firstHints.upperHint, firstHints.lowerHint, {
        value: firstCollateral,
      });

    await priceFeed.setPrice(dec(100, 18));
    await contracts.troveManager.connect(owner).liquidate(defaulter_1.address);

    await stabilityPool.connect(helper).withdrawFromSP(helperDeposit);

    const totalDepositsBeforeSecondLiquidation = await stabilityPool.getTotalDebtTokenDeposits();
    const secondFactor = P2.mul(DECIMAL_PRECISION).div(P1);
    const secondLossFactor = DECIMAL_PRECISION.sub(secondFactor);
    const secondOffsetNumerator = secondLossFactor.sub(1).mul(totalDepositsBeforeSecondLiquidation);
    const secondDebtToOffset = ceilDiv(secondOffsetNumerator, DECIMAL_PRECISION);
    const secondCollateral = secondDebtToOffset.div(100);
    const secondDebtTokenAmount = await getDebtTokenAmountForDesiredTotalDebt(secondDebtToOffset);
    const secondHints = await th.getBorrowerOpsListHint(
      contracts,
      secondCollateral,
      secondDebtToOffset,
    );

    await priceFeed.setPrice(dec(200, 18));
    await borrowerOperations
      .connect(defaulter_2)
      .openTrove(th._100pct, secondDebtTokenAmount, secondHints.upperHint, secondHints.lowerHint, {
        value: secondCollateral,
      });

    await priceFeed.setPrice(dec(100, 18));
    await contracts.troveManager.connect(owner).liquidate(defaulter_2.address);

    const compoundedDeposit = await stabilityPool.getCompoundedDebtTokenDeposit(depositor.address);
    const compoundedFrontEndStake = await stabilityPool.getCompoundedFrontEndStake(
      frontEnd.address,
    );

    assert.isTrue(compoundedFrontEndStake.add(1).eq(compoundedDeposit));

    const balanceBefore = await debtToken.balanceOf(depositor.address);
    const totalDepositsBefore = await stabilityPool.getTotalDebtTokenDeposits();

    await stabilityPool.connect(depositor).withdrawFromSP(compoundedDeposit);

    const balanceAfter = await debtToken.balanceOf(depositor.address);
    const totalDepositsAfter = await stabilityPool.getTotalDebtTokenDeposits();
    const depositAfter = await stabilityPool.getCompoundedDebtTokenDeposit(depositor.address);
    const frontEndStakeAfter = await stabilityPool.getCompoundedFrontEndStake(frontEnd.address);

    assert.isTrue(balanceAfter.sub(balanceBefore).eq(compoundedDeposit));
    assert.isTrue(totalDepositsBefore.sub(totalDepositsAfter).eq(compoundedDeposit));
    assert.isTrue(depositAfter.isZero());
    assert.isTrue(frontEndStakeAfter.isZero());
  });
});
