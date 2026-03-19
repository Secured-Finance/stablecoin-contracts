const deploymentHelper = require("../utils/testDeploymentHelpers.js");
const testHelpers = require("../utils/testHelpers.js");

const th = testHelpers.TestHelper;
const timeValues = testHelpers.TimeValues;
const dec = th.dec;
const toBN = th.toBN;

contract("CommunityIssuance - ProtocolTokenSupplyCap Update", async () => {
  let owner, A, B;
  let contracts;
  let stabilityPool;
  let borrowerOperations;
  let protocolToken;
  let communityIssuanceTester;
  let initialProtocolTokenSupplyCap;

  const ZERO_ADDRESS = th.ZERO_ADDRESS;

  before(async () => {
    const signers = await ethers.getSigners();
    [owner, A, B] = signers;
  });

  beforeEach(async () => {
    await hre.network.provider.send("hardhat_reset");

    const transactionCount = await owner.getTransactionCount();
    const cpTesterContracts = await deploymentHelper.computeContractAddresses(
      owner.address,
      transactionCount,
      3,
    );
    const cpContracts = await deploymentHelper.computeCoreProtocolContracts(
      owner.address,
      transactionCount + 3,
    );

    cpContracts.troveManager = cpTesterContracts[2];

    const troveManagerTester = await deploymentHelper.deployTroveManagerTester(
      th.GAS_COMPENSATION,
      th.MIN_NET_DEBT,
      cpContracts,
    );

    contracts = await deploymentHelper.deployProtocolCore(
      th.GAS_COMPENSATION,
      th.MIN_NET_DEBT,
      cpContracts,
    );

    const protocolTokenContracts = await deploymentHelper.deployProtocolTokenTesterContracts(
      owner.address,
      cpContracts,
    );

    initialProtocolTokenSupplyCap = toBN(dec(1000, 18));

    const allocation = [
      {
        address: protocolTokenContracts.communityIssuance.address,
        amount: initialProtocolTokenSupplyCap,
      },
      {
        address: owner.address,
        amount: toBN(dec(2000, 18)),
      },
    ];
    await deploymentHelper.allocateProtocolToken(protocolTokenContracts, allocation);

    contracts.troveManager = troveManagerTester;
    stabilityPool = contracts.stabilityPool;
    borrowerOperations = contracts.borrowerOperations;
    protocolToken = protocolTokenContracts.protocolToken;
    communityIssuanceTester = protocolTokenContracts.communityIssuance;
  });

  it("startNewEmissionEpoch(): Correctly updates ProtocolTokenSupplyCap and allows withdrawals", async () => {
    const increaseAmount = initialProtocolTokenSupplyCap.div(4);

    await borrowerOperations
      .connect(A)
      .openTrove(th._100pct, dec(2000, 18), A.address, A.address, { value: dec(200, "ether") });
    await stabilityPool.connect(A).provideToSP(dec(1000, 18), ZERO_ADDRESS);

    await borrowerOperations
      .connect(B)
      .openTrove(th._100pct, dec(2000, 18), B.address, B.address, { value: dec(200, "ether") });
    await stabilityPool.connect(B).provideToSP(dec(1, 18), ZERO_ADDRESS);

    await th.fastForwardTime(timeValues.SECONDS_IN_ONE_YEAR, web3.currentProvider);

    await stabilityPool.connect(B).withdrawFromSP(0);

    const supplyCapBefore = await communityIssuanceTester.protocolTokenSupplyCap();
    const supplyStartTimeBefore = await communityIssuanceTester.supplyStartTime();
    const issuedOffsetBefore = await communityIssuanceTester.issuedOffset();
    assert.equal(supplyCapBefore.toString(), toBN(dec(1000, 18)).toString());
    assert.notEqual(supplyStartTimeBefore.toString(), "0");
    assert.equal(issuedOffsetBefore.toString(), "0");

    // Ensure User A has significant pending rewards
    const gain = await stabilityPool.getDepositorProtocolTokenGain(A.address);
    assert.isTrue(gain.mul(100).div(supplyCapBefore).add(1).eq(50));

    // Increase Supply Cap
    await protocolToken.approve(communityIssuanceTester.address, increaseAmount);
    await communityIssuanceTester.connect(owner).startNewEmissionEpoch(increaseAmount);

    await th.fastForwardTime(timeValues.SECONDS_IN_ONE_YEAR, web3.currentProvider);

    await stabilityPool.connect(A).withdrawFromSP(0);
    await stabilityPool.connect(B).withdrawFromSP(0);

    // Verify the supply cap was properly updated
    const userABalance = await protocolToken.balanceOf(A.address);
    const userBBalance = await protocolToken.balanceOf(B.address);
    const supplyCapAfter = await communityIssuanceTester.protocolTokenSupplyCap();
    const supplyStartTimeAfter = await communityIssuanceTester.supplyStartTime();
    const issuedOffsetAfter = await communityIssuanceTester.issuedOffset();

    const estimatedIssuedOffsetAfter = initialProtocolTokenSupplyCap.div(2);
    const estimatedSupplyCapAfter = estimatedIssuedOffsetAfter.add(increaseAmount);

    assert.equal(supplyCapAfter.mul(10000).div(estimatedSupplyCapAfter).toString(), "10000");
    assert.isTrue(supplyStartTimeAfter.gt(supplyStartTimeBefore));
    assert.equal(estimatedIssuedOffsetAfter.mul(10000).div(issuedOffsetAfter).toString(), "10000");

    const estimatedUserABalance = supplyCapBefore.div(2).add(supplyCapAfter.div(2));

    assert.equal(
      estimatedUserABalance.mul(10000).div(userABalance.add(userBBalance)).toString(),
      "10000",
    );
  });

  it("startNewEmissionEpoch(): Correctly updates ProtocolTokenSupplyCap with multiple calls", async () => {
    const firstIncreaseAmount = initialProtocolTokenSupplyCap.div(4);
    const secondIncreaseAmount = initialProtocolTokenSupplyCap.div(2);

    await borrowerOperations
      .connect(A)
      .openTrove(th._100pct, dec(2000, 18), A.address, A.address, { value: dec(200, "ether") });
    await stabilityPool.connect(A).provideToSP(dec(1000, 18), ZERO_ADDRESS);

    await borrowerOperations
      .connect(B)
      .openTrove(th._100pct, dec(2000, 18), B.address, B.address, { value: dec(200, "ether") });
    await stabilityPool.connect(B).provideToSP(dec(1, 18), ZERO_ADDRESS);

    await th.fastForwardTime(timeValues.SECONDS_IN_ONE_YEAR, web3.currentProvider);

    await stabilityPool.connect(B).withdrawFromSP(0);

    const supplyCapInitial = await communityIssuanceTester.protocolTokenSupplyCap();
    const supplyStartTimeInitial = await communityIssuanceTester.supplyStartTime();
    const issuedOffsetInitial = await communityIssuanceTester.issuedOffset();
    assert.equal(supplyCapInitial.toString(), toBN(dec(1000, 18)).toString());
    assert.notEqual(supplyStartTimeInitial.toString(), "0");
    assert.equal(issuedOffsetInitial.toString(), "0");

    // First increase
    await protocolToken.approve(communityIssuanceTester.address, firstIncreaseAmount);
    await communityIssuanceTester.connect(owner).startNewEmissionEpoch(firstIncreaseAmount);

    await th.fastForwardTime(timeValues.SECONDS_IN_ONE_YEAR, web3.currentProvider);

    await stabilityPool.connect(B).withdrawFromSP(0);

    const supplyCapAfterFirst = await communityIssuanceTester.protocolTokenSupplyCap();
    const supplyStartTimeAfterFirst = await communityIssuanceTester.supplyStartTime();
    const issuedOffsetAfterFirst = await communityIssuanceTester.issuedOffset();

    const estimatedIssuedOffsetAfterFirst = initialProtocolTokenSupplyCap.div(2);
    const estimatedSupplyCapAfterFirst = estimatedIssuedOffsetAfterFirst.add(firstIncreaseAmount);

    assert.equal(
      supplyCapAfterFirst.mul(10000).div(estimatedSupplyCapAfterFirst).toString(),
      "10000",
    );
    assert.isTrue(supplyStartTimeAfterFirst.gt(supplyStartTimeInitial));
    assert.equal(
      estimatedIssuedOffsetAfterFirst.mul(10000).div(issuedOffsetAfterFirst).toString(),
      "10000",
    );

    // Second increase
    await protocolToken.approve(communityIssuanceTester.address, secondIncreaseAmount);
    await communityIssuanceTester.connect(owner).startNewEmissionEpoch(secondIncreaseAmount);

    await th.fastForwardTime(timeValues.SECONDS_IN_ONE_YEAR, web3.currentProvider);

    await stabilityPool.connect(A).withdrawFromSP(0);
    await stabilityPool.connect(B).withdrawFromSP(0);

    const supplyCapAfterSecond = await communityIssuanceTester.protocolTokenSupplyCap();
    const supplyStartTimeAfterSecond = await communityIssuanceTester.supplyStartTime();
    const issuedOffsetAfterSecond = await communityIssuanceTester.issuedOffset();

    // issuedOffset after second call = totalProtocolTokenIssued at that point
    // which is roughly: issuedOffsetAfterFirst + (supplyCapAfterFirst / 2)
    const estimatedIssuedOffsetAfterSecond = issuedOffsetAfterFirst.add(supplyCapAfterFirst.div(2));
    // Remaining unissued from first epoch + second increase amount
    const remainingAfterFirst = supplyCapAfterFirst.div(2);
    const estimatedSupplyCapAfterSecond = remainingAfterFirst.add(secondIncreaseAmount);

    assert.equal(
      supplyCapAfterSecond.mul(10000).div(estimatedSupplyCapAfterSecond).toString(),
      "10000",
    );
    assert.isTrue(supplyStartTimeAfterSecond.gt(supplyStartTimeAfterFirst));
    assert.equal(
      estimatedIssuedOffsetAfterSecond.mul(10000).div(issuedOffsetAfterSecond).toString(),
      "10000",
    );

    // Verify final balances
    const userABalance = await protocolToken.balanceOf(A.address);
    const userBBalance = await protocolToken.balanceOf(B.address);

    const estimatedUserABalance = supplyCapInitial
      .div(2)
      .add(supplyCapAfterFirst.div(2))
      .add(supplyCapAfterSecond.div(2));

    assert.equal(
      estimatedUserABalance.mul(10000).div(userABalance.add(userBBalance)).toString(),
      "10000",
    );
  });
});
