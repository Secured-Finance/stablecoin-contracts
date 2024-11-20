const deploymentHelper = require("../utils/deploymentHelpers.js");
const testHelpers = require("../utils/testHelpers.js");

const th = testHelpers.TestHelper;
const timeValues = testHelpers.TimeValues;
const dec = th.dec;
const toBN = th.toBN;
const getDifference = th.getDifference;
const assertRevert = th.assertRevert;

const GAS_PRICE = 10000000;

contract("StabilityPool - ProtocolToken supply cap update tests", async () => {
  let owner, A, B;
  let lpRewardsAddress, multisig;

  let contracts;
  let protocolTokenContracts;

  let stabilityPool;
  let protocolToken;
  let communityIssuance;

  let allocation;

  const openTrove = async (params) => th.openTrove(contracts, params);

  before(async () => {
    const signers = await ethers.getSigners();

    [owner, A, B] = signers;
    [lpRewardsAddress, multisig] = signers.slice(998, 1000);
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

    // Overwrite contracts with computed tester addresses
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

    protocolTokenContracts = await deploymentHelper.deployProtocolTokenContracts(cpContracts);

    contracts.troveManager = troveManagerTester;

    stabilityPool = contracts.stabilityPool;
    protocolToken = protocolTokenContracts.protocolToken;
    communityIssuance = protocolTokenContracts.communityIssuance;

    // Check community issuance starts with 32 million ProtocolToken
    const communityProtocolTokenSupply = await protocolToken.balanceOf(communityIssuance.address);
    assert.equal(communityProtocolTokenSupply, "0");

    allocation = [
      { address: multisig.address, amount: toBN(dec(67000000, 18)) },
      { address: lpRewardsAddress.address, amount: toBN(dec(1000000, 18)) },
      {
        address: protocolTokenContracts.communityIssuance.address,
        amount: toBN(dec(32000000, 18)),
      },
    ];
  });

  it("Allocates ProtocolToken immediately after deployment", async () => {
    await deploymentHelper.allocateProtocolToken(protocolTokenContracts, allocation);

    const communityProtocolTokenSupply = toBN(
      await protocolToken.balanceOf(communityIssuance.address),
    );
    assert.isAtMost(
      getDifference(communityProtocolTokenSupply, "32000000000000000000000000"),
      1000,
    );
  });

  it("provideToSP(), no token allocation: depositor does not receive any ProtocolToken rewards", async () => {
    await openTrove({
      extraDebtTokenAmount: toBN(dec(1000, 18)),
      ICR: toBN(dec(2, 18)),
      extraParams: { from: A },
    });
    await openTrove({
      extraDebtTokenAmount: toBN(dec(1000, 18)),
      ICR: toBN(dec(2, 18)),
      extraParams: { from: B },
    });

    assert.equal(await stabilityPool.getDepositorProtocolTokenGain(A.address), "0");

    await stabilityPool.connect(A).provideToSP(dec(1000, 18), th.ZERO_ADDRESS);
    await th.fastForwardTime(timeValues.SECONDS_IN_ONE_YEAR, web3.currentProvider);
    await stabilityPool.connect(B).provideToSP(dec(1000, 18), th.ZERO_ADDRESS);

    const protocolTokenGain = await stabilityPool.getDepositorProtocolTokenGain(A.address);
    assert.equal(protocolTokenGain, "0");
  });

  it("provideToSP(), token allocation before depositing: depositor receives ProtocolToken rewards", async () => {
    await deploymentHelper.allocateProtocolToken(protocolTokenContracts, allocation);

    await openTrove({
      extraDebtTokenAmount: toBN(dec(1000, 18)),
      ICR: toBN(dec(2, 18)),
      extraParams: { from: A },
    });
    await openTrove({
      extraDebtTokenAmount: toBN(dec(1000, 18)),
      ICR: toBN(dec(2, 18)),
      extraParams: { from: B },
    });

    assert.equal(await stabilityPool.getDepositorProtocolTokenGain(A.address), "0");

    await stabilityPool.connect(A).provideToSP(dec(1000, 18), th.ZERO_ADDRESS);
    await th.fastForwardTime(timeValues.SECONDS_IN_ONE_YEAR, web3.currentProvider);
    await stabilityPool.connect(B).provideToSP(dec(1000, 18), th.ZERO_ADDRESS);

    const protocolTokenGain = await stabilityPool.getDepositorProtocolTokenGain(A.address);
    assert.isAtMost(th.getDifference(protocolTokenGain, dec(16000000, 18)), 1e12);
  });

  it("provideToSP(), token allocation after depositing: depositor receives ProtocolToken rewards", async () => {
    await openTrove({
      extraDebtTokenAmount: toBN(dec(1000, 18)),
      ICR: toBN(dec(2, 18)),
      extraParams: { from: A },
    });
    await openTrove({
      extraDebtTokenAmount: toBN(dec(1000, 18)),
      ICR: toBN(dec(2, 18)),
      extraParams: { from: B },
    });

    assert.equal(await stabilityPool.getDepositorProtocolTokenGain(A.address), "0");

    await stabilityPool.connect(A).provideToSP(dec(500, 18), th.ZERO_ADDRESS);
    await th.fastForwardTime(timeValues.SECONDS_IN_ONE_YEAR, web3.currentProvider);
    await stabilityPool.connect(A).provideToSP(dec(500, 18), th.ZERO_ADDRESS);

    assert.equal(await stabilityPool.getDepositorProtocolTokenGain(A.address), "0");

    await deploymentHelper.allocateProtocolToken(protocolTokenContracts, allocation);

    await th.fastForwardTime(timeValues.SECONDS_IN_ONE_YEAR, web3.currentProvider);
    await stabilityPool.connect(B).provideToSP(dec(1000, 18), th.ZERO_ADDRESS);

    const protocolTokenGain = await stabilityPool.getDepositorProtocolTokenGain(A.address);
    assert.isAtMost(th.getDifference(protocolTokenGain, dec(16000000, 18)), 1e12);
  });

  it("provideToSP(), multiple token allocation: depositor receives ProtocolToken rewards", async () => {
    await deploymentHelper.allocateProtocolToken(protocolTokenContracts, allocation);

    await openTrove({
      extraDebtTokenAmount: toBN(dec(1000, 18)),
      ICR: toBN(dec(2, 18)),
      extraParams: { from: A },
    });
    await openTrove({
      extraDebtTokenAmount: toBN(dec(1000, 18)),
      ICR: toBN(dec(2, 18)),
      extraParams: { from: B },
    });

    assert.equal(await stabilityPool.getDepositorProtocolTokenGain(A.address), "0");

    await stabilityPool.connect(A).provideToSP(dec(1000, 18), th.ZERO_ADDRESS);
    await th.fastForwardTime(timeValues.SECONDS_IN_ONE_YEAR, web3.currentProvider);
    await stabilityPool.connect(B).provideToSP(dec(1000, 18), th.ZERO_ADDRESS);

    const protocolTokenGain = await stabilityPool.getDepositorProtocolTokenGain(A.address);
    assert.isAtMost(th.getDifference(protocolTokenGain, dec(16000000, 18)), 1e12);

    await stabilityPool.connect(A).withdrawFromSP(dec(1000, 18));
    await stabilityPool.connect(B).withdrawFromSP(dec(1000, 18));

    const communityIssuanceBalance = await protocolToken.balanceOf(communityIssuance.address);
    const protocolTokenSupplyCapBefore = await communityIssuance.protocolTokenSupplyCap();
    const totalProtocolTokenIssuedBefore = await communityIssuance.totalProtocolTokenIssued();
    const supplyStartTimeBefore = await communityIssuance.supplyStartTime();

    await protocolToken
      .connect(multisig)
      .transfer(communityIssuance.address, toBN(dec(40000000, 18)).sub(communityIssuanceBalance));
    await communityIssuance.updateProtocolTokenSupplyCap();

    const protocolTokenSupplyCapAfter = await communityIssuance.protocolTokenSupplyCap();
    const totalProtocolTokenIssuedAfter = await communityIssuance.totalProtocolTokenIssued();
    const supplyStartTimeAfter = await communityIssuance.supplyStartTime();

    assert.equal(protocolTokenSupplyCapBefore, dec(32000000, 18));
    assert.equal(
      communityIssuanceBalance.add(totalProtocolTokenIssuedBefore),
      protocolTokenSupplyCapBefore.toString(),
    );
    assert.equal(totalProtocolTokenIssuedBefore, protocolTokenGain.toString());
    assert.equal(protocolTokenSupplyCapAfter, dec(40000000, 18));
    assert.equal(totalProtocolTokenIssuedAfter, "0");
    assert.isTrue(supplyStartTimeAfter.gt(supplyStartTimeBefore));
  });

  it("updateProtocolTokenSupplyCap(), reverts if called multiple times without any changes", async () => {
    await deploymentHelper.allocateProtocolToken(protocolTokenContracts, allocation);

    await assertRevert(
      communityIssuance.updateProtocolTokenSupplyCap(),
      "CommunityIssuance: supply cap not changed",
    );
  });

  it("updateProtocolTokenSupplyCap(): reverts if caller is not owner", async () => {
    await assertRevert(
      communityIssuance.connect(A).updateProtocolTokenSupplyCap(),
      "Ownable: caller is not the owner",
    );
  });
});
