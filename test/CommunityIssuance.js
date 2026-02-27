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

    const allocation = [
      {
        address: protocolTokenContracts.communityIssuance.address,
        amount: toBN(dec(1000, 18)),
      },
      {
        address: owner.address,
        amount: toBN(dec(100, 18)),
      },
    ];
    await deploymentHelper.allocateProtocolToken(protocolTokenContracts, allocation);

    contracts.troveManager = troveManagerTester;
    stabilityPool = contracts.stabilityPool;
    borrowerOperations = contracts.borrowerOperations;
    protocolToken = protocolTokenContracts.protocolToken;
    communityIssuanceTester = protocolTokenContracts.communityIssuance;
  });

  it("Correctly updates ProtocolTokenSupplyCap and allows withdrawals", async () => {
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
    assert.equal(supplyCapBefore.toString(), toBN(dec(1000, 18)).toString());

    // Ensure User A has significant pending rewards
    const gain = await stabilityPool.getDepositorProtocolTokenGain(A.address);
    console.log(`User A Pending Gain (Year 1): ${gain.toString()}`);
    assert.isTrue(gain.mul(100).div(supplyCapBefore).add(1).eq(50));

    // Increase Supply Cap
    await protocolToken.approve(communityIssuanceTester.address, 1);
    await communityIssuanceTester.connect(owner).increaseProtocolTokenSupplyCap(1);

    await th.fastForwardTime(timeValues.SECONDS_IN_ONE_YEAR, web3.currentProvider);

    await stabilityPool.connect(A).withdrawFromSP(0);

    // Verify the supply cap was properly updated
    const userABalance = await protocolToken.balanceOf(A.address);
    const supplyCapAfter = await communityIssuanceTester.protocolTokenSupplyCap();
    assert.equal(supplyCapAfter.toString(), toBN(dec(1000, 18)).add(1).toString());
    assert.isTrue(userABalance.mul(100).div(supplyCapAfter).add(1).eq(75));
  });
});
