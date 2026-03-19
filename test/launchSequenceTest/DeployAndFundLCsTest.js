const deploymentHelper = require("../../utils/testDeploymentHelpers.js");
const testHelpers = require("../../utils/testHelpers.js");

const th = testHelpers.TestHelper;
const timeValues = testHelpers.TimeValues;
const { dec, toBN, assertRevert, ZERO_ADDRESS } = th;

contract("Deploying and funding One Year Lockup Contracts", async () => {
  let deployer, A, B, C, D, E, F, G, H, I, J;
  let lpRewardsAddress, multisig;

  let protocolTokenContracts;

  // 1e24 = 1 million tokens with 18 decimal digits
  const protocolTokenEntitlement_A = dec(1, 24);
  const protocolTokenEntitlement_B = dec(2, 24);
  const protocolTokenEntitlement_C = dec(3, 24);
  const protocolTokenEntitlement_D = dec(4, 24);
  const protocolTokenEntitlement_E = dec(5, 24);

  let protocolToken;
  let lockupContractFactory;

  let oneYearFromAllocation;

  before(async () => {
    const signers = await ethers.getSigners();

    [deployer, A, B, C, D, E, F, G, H, I, J] = signers;
    [lpRewardsAddress, multisig] = signers.slice(998, 1000);
  });

  const deploy = async () => {
    await hre.network.provider.send("hardhat_reset");

    const transactionCount = await deployer.getTransactionCount();
    const cpContracts = await deploymentHelper.computeCoreProtocolContracts(
      deployer.address,
      transactionCount + 1,
    );
    await deploymentHelper.deployProtocolCore(th.GAS_COMPENSATION, th.MIN_NET_DEBT, cpContracts);
    protocolTokenContracts = await deploymentHelper.deployProtocolTokenContracts(
      deployer.address,
      cpContracts,
    );

    protocolToken = protocolTokenContracts.protocolToken;
    lockupContractFactory = protocolTokenContracts.lockupContractFactory;
  };

  const allocateProtocolToken = async () => {
    const allocation = [
      { address: multisig.address, amount: toBN(dec(67000000, 18)) },
      { address: lpRewardsAddress.address, amount: toBN(dec(1000000, 18)) },
      {
        address: protocolTokenContracts.communityIssuance.address,
        amount: toBN(dec(32000000, 18)),
      },
    ];
    await deploymentHelper.allocateProtocolToken(protocolTokenContracts, allocation);

    oneYearFromAllocation = await th.getTimeFromAllocation(
      protocolToken,
      timeValues.SECONDS_IN_ONE_YEAR,
    );
  };

  // --- LCs ---

  describe("Deploying LCs", async () => {
    before(async () => {
      await deploy();
      await allocateProtocolToken();
    });

    it("ProtocolToken Deployer can deploy LCs through the Factory", async () => {
      // ProtocolToken deployer deploys LCs
      const LCDeploymentTx_A = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(A.address, oneYearFromAllocation);
      const LCDeploymentTx_B = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(B.address, oneYearFromAllocation);
      const LCDeploymentTx_C = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(C.address, oneYearFromAllocation);

      const receipt_A = await LCDeploymentTx_A.wait();
      const receipt_B = await LCDeploymentTx_B.wait();
      const receipt_C = await LCDeploymentTx_C.wait();

      assert.equal(receipt_A.status, 1);
      assert.equal(receipt_B.status, 1);
      assert.equal(receipt_C.status, 1);
    });

    it("Anyone can deploy LCs through the Factory", async () => {
      // Various EOAs deploy LCs
      const LCDeploymentTx_1 = await lockupContractFactory
        .connect(G)
        .deployLockupContract(A.address, oneYearFromAllocation);
      const LCDeploymentTx_2 = await lockupContractFactory
        .connect(H)
        .deployLockupContract(C.address, oneYearFromAllocation);
      const LCDeploymentTx_3 = await lockupContractFactory
        .connect(H)
        .deployLockupContract(deployer.address, oneYearFromAllocation);
      const LCDeploymentTx_4 = await lockupContractFactory
        .connect(J)
        .deployLockupContract(D.address, oneYearFromAllocation);

      const receipt_1 = await LCDeploymentTx_1.wait();
      const receipt_2 = await LCDeploymentTx_2.wait();
      const receipt_3 = await LCDeploymentTx_3.wait();
      const receipt_4 = await LCDeploymentTx_4.wait();

      assert.equal(receipt_1.status, 1);
      assert.equal(receipt_2.status, 1);
      assert.equal(receipt_3.status, 1);
      assert.equal(receipt_4.status, 1);
    });

    it("ProtocolToken Deployer can deploy LCs directly", async () => {
      const lockupContractFactory = await deploymentHelper.getFactory("LockupContract");

      // ProtocolToken deployer deploys LCs
      const lcTx_A = await lockupContractFactory
        .connect(deployer)
        .deploy(protocolToken.address, A.address, oneYearFromAllocation);

      const lcTx_B = await lockupContractFactory
        .connect(deployer)
        .deploy(protocolToken.address, B.address, oneYearFromAllocation);

      const lcTx_C = await lockupContractFactory
        .connect(deployer)
        .deploy(protocolToken.address, C.address, oneYearFromAllocation);

      const receipt_A = await lcTx_A.deployTransaction.wait();
      const receipt_B = await lcTx_B.deployTransaction.wait();
      const receipt_C = await lcTx_C.deployTransaction.wait();

      // Check deployment succeeded
      assert.equal(receipt_A.status, 1);
      assert.equal(receipt_B.status, 1);
      assert.equal(receipt_C.status, 1);
    });

    it("Anyone can deploy LCs directly", async () => {
      const lockupContractFactory = await deploymentHelper.getFactory("LockupContract");

      // Various EOAs deploy LCs
      const lcTx_A = await lockupContractFactory
        .connect(D)
        .deploy(protocolToken.address, A.address, oneYearFromAllocation);

      const lcTx_B = await lockupContractFactory
        .connect(E)
        .deploy(protocolToken.address, B.address, oneYearFromAllocation);

      const lcTx_C = await lockupContractFactory
        .connect(F)
        .deploy(protocolToken.address, C.address, oneYearFromAllocation);

      const receipt_A = await lcTx_A.deployTransaction.wait();
      const receipt_B = await lcTx_B.deployTransaction.wait();
      const receipt_C = await lcTx_C.deployTransaction.wait();

      // Check deployment succeeded
      assert.equal(receipt_A.status, 1);
      assert.equal(receipt_B.status, 1);
      assert.equal(receipt_C.status, 1);
    });

    it("LC deployment stores the beneficiary's address in the LC", async () => {
      // Deploy 5 LCs
      const deployedLCtx_A = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(A.address, oneYearFromAllocation);
      const deployedLCtx_B = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(B.address, oneYearFromAllocation);
      const deployedLCtx_C = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(C.address, oneYearFromAllocation);
      const deployedLCtx_D = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(D.address, oneYearFromAllocation);
      const deployedLCtx_E = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(E.address, oneYearFromAllocation);

      // Grab contracts from deployment tx events
      const LC_A = await th.getLCFromDeploymentTx(deployedLCtx_A);
      const LC_B = await th.getLCFromDeploymentTx(deployedLCtx_B);
      const LC_C = await th.getLCFromDeploymentTx(deployedLCtx_C);
      const LC_D = await th.getLCFromDeploymentTx(deployedLCtx_D);
      const LC_E = await th.getLCFromDeploymentTx(deployedLCtx_E);

      const storedBeneficiaryAddress_A = await LC_A.beneficiary();
      const storedBeneficiaryAddress_B = await LC_B.beneficiary();
      const storedBeneficiaryAddress_C = await LC_C.beneficiary();
      const storedBeneficiaryAddress_D = await LC_D.beneficiary();
      const storedBeneficiaryAddress_E = await LC_E.beneficiary();

      assert.equal(A.address, storedBeneficiaryAddress_A);
      assert.equal(B.address, storedBeneficiaryAddress_B);
      assert.equal(C.address, storedBeneficiaryAddress_C);
      assert.equal(D.address, storedBeneficiaryAddress_D);
      assert.equal(E.address, storedBeneficiaryAddress_E);
    });

    it("LC deployment through the Factory registers the LC in the Factory", async () => {
      // Deploy 5 LCs
      const deployedLCtx_A = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(A.address, oneYearFromAllocation);
      const deployedLCtx_B = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(B.address, oneYearFromAllocation);
      const deployedLCtx_C = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(C.address, oneYearFromAllocation);
      const deployedLCtx_D = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(D.address, oneYearFromAllocation);
      const deployedLCtx_E = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(E.address, oneYearFromAllocation);

      // Grab contract addresses from deployment tx events
      const LCAddress_A = await th.getLCAddressFromDeploymentTx(deployedLCtx_A);
      const LCAddress_B = await th.getLCAddressFromDeploymentTx(deployedLCtx_B);
      const LCAddress_C = await th.getLCAddressFromDeploymentTx(deployedLCtx_C);
      const LCAddress_D = await th.getLCAddressFromDeploymentTx(deployedLCtx_D);
      const LCAddress_E = await th.getLCAddressFromDeploymentTx(deployedLCtx_E);

      assert.isTrue(await lockupContractFactory.isRegisteredLockup(LCAddress_A));
      assert.isTrue(await lockupContractFactory.isRegisteredLockup(LCAddress_B));
      assert.isTrue(await lockupContractFactory.isRegisteredLockup(LCAddress_C));
      assert.isTrue(await lockupContractFactory.isRegisteredLockup(LCAddress_D));
      assert.isTrue(await lockupContractFactory.isRegisteredLockup(LCAddress_E));
    });

    it("LC deployment through the Factory records the LC contract address and deployer as a k-v pair in the Factory", async () => {
      // Deploy 5 LCs
      const deployedLCtx_A = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(A.address, oneYearFromAllocation);
      const deployedLCtx_B = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(B.address, oneYearFromAllocation);
      const deployedLCtx_C = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(C.address, oneYearFromAllocation);
      const deployedLCtx_D = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(D.address, oneYearFromAllocation);
      const deployedLCtx_E = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(E.address, oneYearFromAllocation);

      // Grab contract addresses from deployment tx events
      const LCAddress_A = await th.getLCAddressFromDeploymentTx(deployedLCtx_A);
      const LCAddress_B = await th.getLCAddressFromDeploymentTx(deployedLCtx_B);
      const LCAddress_C = await th.getLCAddressFromDeploymentTx(deployedLCtx_C);
      const LCAddress_D = await th.getLCAddressFromDeploymentTx(deployedLCtx_D);
      const LCAddress_E = await th.getLCAddressFromDeploymentTx(deployedLCtx_E);

      assert.equal(
        deployer.address,
        await lockupContractFactory.lockupContractToDeployer(LCAddress_A),
      );
      assert.equal(
        deployer.address,
        await lockupContractFactory.lockupContractToDeployer(LCAddress_B),
      );
      assert.equal(
        deployer.address,
        await lockupContractFactory.lockupContractToDeployer(LCAddress_C),
      );
      assert.equal(
        deployer.address,
        await lockupContractFactory.lockupContractToDeployer(LCAddress_D),
      );
      assert.equal(
        deployer.address,
        await lockupContractFactory.lockupContractToDeployer(LCAddress_E),
      );
    });

    it("LC deployment through the Factory sets the unlockTime in the LC", async () => {
      // Deploy 3 LCs through factory
      const deployedLCtx_A = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(A.address, oneYearFromAllocation);
      const deployedLCtx_B = await lockupContractFactory
        .connect(B)
        .deployLockupContract(B.address, "230582305895235");
      const deployedLCtx_C = await lockupContractFactory
        .connect(E)
        .deployLockupContract(C.address, dec(20, 18));

      // Grab contract objects from deployment events
      const LC_A = await th.getLCFromDeploymentTx(deployedLCtx_A);
      const LC_B = await th.getLCFromDeploymentTx(deployedLCtx_B);
      const LC_C = await th.getLCFromDeploymentTx(deployedLCtx_C);

      // Grab contract addresses from deployment tx events
      const unlockTime_A = await LC_A.unlockTime();
      const unlockTime_B = await LC_B.unlockTime();
      const unlockTime_C = await LC_C.unlockTime();

      // Check contracts have expected unlockTimes set
      assert.isTrue(unlockTime_A.eq(oneYearFromAllocation));
      assert.isTrue(unlockTime_B.eq(toBN("230582305895235")));
      assert.isTrue(unlockTime_C.eq(toBN(dec(20, 18))));
    });

    it("Direct deployment of LC sets the unlockTime in the LC", async () => {
      const lockupContractFactory = await deploymentHelper.getFactory("LockupContract");

      // Deploy 3 LCs directly
      const lcTx_A = await lockupContractFactory
        .connect(deployer)
        .deploy(protocolToken.address, A.address, oneYearFromAllocation);
      const lcTx_B = await lockupContractFactory
        .connect(B)
        .deploy(protocolToken.address, B.address, "230582305895235");
      const lcTx_C = await lockupContractFactory
        .connect(E)
        .deploy(protocolToken.address, C.address, dec(20, 18));

      // Grab contract addresses from deployment tx events
      const unlockTime_A = await lcTx_A.unlockTime();
      const unlockTime_B = await lcTx_B.unlockTime();
      const unlockTime_C = await lcTx_C.unlockTime();

      // Check contracts have expected unlockTimes set
      assert.isTrue(unlockTime_A.eq(oneYearFromAllocation));
      assert.isTrue(unlockTime_B.eq(toBN("230582305895235")));
      assert.isTrue(unlockTime_C.eq(toBN(dec(20, 18))));
    });

    it("LC deployment through the Factory reverts when the unlockTime is < 1 year from allocation start¸", async () => {
      const nearlyOneYear = toBN(oneYearFromAllocation).sub(toBN("60")); // 1 minute short of 1 year

      // Deploy 3 LCs through factory
      const LCDeploymentPromise_A = lockupContractFactory
        .connect(deployer)
        .deployLockupContract(A.address, nearlyOneYear);
      const LCDeploymentPromise_B = lockupContractFactory
        .connect(B)
        .deployLockupContract(B.address, "37");
      const LCDeploymentPromise_C = lockupContractFactory
        .connect(E)
        .deployLockupContract(C.address, "43200");

      // Confirm contract deployments revert
      await assertRevert(
        LCDeploymentPromise_A,
        "LockupContract: unlock time must be at least one year after allocation start¸",
      );
      await assertRevert(
        LCDeploymentPromise_B,
        "LockupContract: unlock time must be at least one year after allocation start¸",
      );
      await assertRevert(
        LCDeploymentPromise_C,
        "LockupContract: unlock time must be at least one year after allocation start¸",
      );
    });

    it("Direct deployment of LC reverts when the unlockTime is < 1 year from allocation start¸", async () => {
      const nearlyOneYear = toBN(oneYearFromAllocation).sub(toBN("60")); // 1 minute short of 1 year
      const lockupContractFactory = await deploymentHelper.getFactory("LockupContract");

      // Deploy 3 LCs directly with unlockTime < 1 year from allocation start¸
      const LCDeploymentPromise_A = lockupContractFactory
        .connect(deployer)
        .deploy(protocolToken.address, A.address, nearlyOneYear);
      const LCDeploymentPromise_B = lockupContractFactory
        .connect(B)
        .deploy(protocolToken.address, B.address, "37");
      const LCDeploymentPromise_C = lockupContractFactory
        .connect(E)
        .deploy(protocolToken.address, C.address, "43200");

      // Confirm contract deployments revert
      await assertRevert(
        LCDeploymentPromise_A,
        "LockupContract: unlock time must be at least one year after allocation start¸",
      );
      await assertRevert(
        LCDeploymentPromise_B,
        "LockupContract: unlock time must be at least one year after allocation start¸",
      );
      await assertRevert(
        LCDeploymentPromise_C,
        "LockupContract: unlock time must be at least one year after allocation start¸",
      );
    });

    it("LC deployment through the Factory reverts when the _beneficiary is zero address", async () => {
      const LCDeploymentPromise = lockupContractFactory
        .connect(deployer)
        .deployLockupContract(ZERO_ADDRESS, oneYearFromAllocation);

      await assertRevert(LCDeploymentPromise, "LockupContract: beneficiary cannot be zero address");
    });
  });

  describe("Deploying LCs without token allocation", async () => {
    before(async () => {
      await deploy();
    });

    it("LCs can't be deployed without token allocation", async () => {
      const arbitraryUnlockTime = toBN("1");
      await assertRevert(
        lockupContractFactory
          .connect(deployer)
          .deployLockupContract(A.address, arbitraryUnlockTime),
        "LockupContract: initial allocation has not been triggered",
      );
    });
  });

  describe("Funding LCs", async () => {
    before(async () => {
      await deploy();
      await allocateProtocolToken();
    });

    it("ProtocolToken transfer from ProtocolToken deployer to their deployed LC increases the ProtocolToken balance of the LC", async () => {
      // Deploy 5 LCs
      const deployedLCtx_A = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(A.address, oneYearFromAllocation);
      const deployedLCtx_B = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(B.address, oneYearFromAllocation);
      const deployedLCtx_C = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(C.address, oneYearFromAllocation);
      const deployedLCtx_D = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(D.address, oneYearFromAllocation);
      const deployedLCtx_E = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(E.address, oneYearFromAllocation);

      // Grab contract addresses from deployment tx events
      const LCAddress_A = await th.getLCAddressFromDeploymentTx(deployedLCtx_A);
      const LCAddress_B = await th.getLCAddressFromDeploymentTx(deployedLCtx_B);
      const LCAddress_C = await th.getLCAddressFromDeploymentTx(deployedLCtx_C);
      const LCAddress_D = await th.getLCAddressFromDeploymentTx(deployedLCtx_D);
      const LCAddress_E = await th.getLCAddressFromDeploymentTx(deployedLCtx_E);

      assert.equal(await protocolToken.balanceOf(LCAddress_A), "0");
      assert.equal(await protocolToken.balanceOf(LCAddress_B), "0");
      assert.equal(await protocolToken.balanceOf(LCAddress_C), "0");
      assert.equal(await protocolToken.balanceOf(LCAddress_D), "0");
      assert.equal(await protocolToken.balanceOf(LCAddress_E), "0");

      // Multisig transfers ProtocolToken to each LC
      await protocolToken.connect(multisig).transfer(LCAddress_A, protocolTokenEntitlement_A);
      await protocolToken.connect(multisig).transfer(LCAddress_B, protocolTokenEntitlement_B);
      await protocolToken.connect(multisig).transfer(LCAddress_C, protocolTokenEntitlement_C);
      await protocolToken.connect(multisig).transfer(LCAddress_D, protocolTokenEntitlement_D);
      await protocolToken.connect(multisig).transfer(LCAddress_E, protocolTokenEntitlement_E);

      assert.equal(await protocolToken.balanceOf(LCAddress_A), protocolTokenEntitlement_A);
      assert.equal(await protocolToken.balanceOf(LCAddress_B), protocolTokenEntitlement_B);
      assert.equal(await protocolToken.balanceOf(LCAddress_C), protocolTokenEntitlement_C);
      assert.equal(await protocolToken.balanceOf(LCAddress_D), protocolTokenEntitlement_D);
      assert.equal(await protocolToken.balanceOf(LCAddress_E), protocolTokenEntitlement_E);
    });

    it("ProtocolToken Multisig can transfer ProtocolToken to LCs deployed through the factory by anyone", async () => {
      // Various accts deploy 5 LCs
      const deployedLCtx_A = await lockupContractFactory
        .connect(F)
        .deployLockupContract(A.address, oneYearFromAllocation);
      const deployedLCtx_B = await lockupContractFactory
        .connect(G)
        .deployLockupContract(B.address, oneYearFromAllocation);
      const deployedLCtx_C = await lockupContractFactory
        .connect(H)
        .deployLockupContract(C.address, oneYearFromAllocation);
      const deployedLCtx_D = await lockupContractFactory
        .connect(I)
        .deployLockupContract(D.address, oneYearFromAllocation);
      const deployedLCtx_E = await lockupContractFactory
        .connect(J)
        .deployLockupContract(E.address, oneYearFromAllocation);

      // Grab contract addresses from deployment tx events
      const LCAddress_A = await th.getLCAddressFromDeploymentTx(deployedLCtx_A);
      const LCAddress_B = await th.getLCAddressFromDeploymentTx(deployedLCtx_B);
      const LCAddress_C = await th.getLCAddressFromDeploymentTx(deployedLCtx_C);
      const LCAddress_D = await th.getLCAddressFromDeploymentTx(deployedLCtx_D);
      const LCAddress_E = await th.getLCAddressFromDeploymentTx(deployedLCtx_E);

      assert.equal(await protocolToken.balanceOf(LCAddress_A), "0");
      assert.equal(await protocolToken.balanceOf(LCAddress_B), "0");
      assert.equal(await protocolToken.balanceOf(LCAddress_C), "0");
      assert.equal(await protocolToken.balanceOf(LCAddress_D), "0");
      assert.equal(await protocolToken.balanceOf(LCAddress_E), "0");

      // Multisig transfers ProtocolToken to each LC
      await protocolToken.connect(multisig).transfer(LCAddress_A, dec(1, 18));
      await protocolToken.connect(multisig).transfer(LCAddress_B, dec(2, 18));
      await protocolToken.connect(multisig).transfer(LCAddress_C, dec(3, 18));
      await protocolToken.connect(multisig).transfer(LCAddress_D, dec(4, 18));
      await protocolToken.connect(multisig).transfer(LCAddress_E, dec(5, 18));

      assert.equal(await protocolToken.balanceOf(LCAddress_A), dec(1, 18));
      assert.equal(await protocolToken.balanceOf(LCAddress_B), dec(2, 18));
      assert.equal(await protocolToken.balanceOf(LCAddress_C), dec(3, 18));
      assert.equal(await protocolToken.balanceOf(LCAddress_D), dec(4, 18));
      assert.equal(await protocolToken.balanceOf(LCAddress_E), dec(5, 18));
    });

    // can't transfer ProtocolToken to any LCs that were deployed directly
  });

  describe("Withdrawal attempts on funded, inactive LCs immediately after funding", async () => {
    before(async () => {
      await deploy();
      await allocateProtocolToken();
    });

    it("Beneficiary can't withdraw from their funded LC", async () => {
      // Deploy 3 LCs
      const deployedLCtx_A = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(A.address, oneYearFromAllocation);
      const deployedLCtx_B = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(B.address, oneYearFromAllocation);
      const deployedLCtx_C = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(C.address, oneYearFromAllocation);

      // Grab contract objects from deployment tx events
      const LC_A = await th.getLCFromDeploymentTx(deployedLCtx_A);
      const LC_B = await th.getLCFromDeploymentTx(deployedLCtx_B);
      const LC_C = await th.getLCFromDeploymentTx(deployedLCtx_C);

      // Multisig transfers ProtocolToken to each LC
      await protocolToken.connect(multisig).transfer(LC_A.address, protocolTokenEntitlement_A);
      await protocolToken.connect(multisig).transfer(LC_B.address, protocolTokenEntitlement_B);
      await protocolToken.connect(multisig).transfer(LC_C.address, protocolTokenEntitlement_C);

      assert.equal(await protocolToken.balanceOf(LC_A.address), protocolTokenEntitlement_A);
      assert.equal(await protocolToken.balanceOf(LC_B.address), protocolTokenEntitlement_B);
      assert.equal(await protocolToken.balanceOf(LC_C.address), protocolTokenEntitlement_C);

      const LCs = [LC_A, LC_B, LC_C];

      // Beneficiary attempts to withdraw
      for (LC of LCs) {
        try {
          const beneficiaryAddr = await LC.beneficiary();
          const beneficiary = await ethers.provider.getSigner(beneficiaryAddr);
          const withdrawalAttemptTx = await LC.connect(beneficiary).withdrawProtocolToken();
          assert.isFalse(withdrawalAttemptTx.receipt.status);
        } catch (error) {
          assert.include(error.message, "revert");
        }
      }
    });

    it("ProtocolToken multisig can't withraw from a LC which it funded", async () => {
      // Deploy 3 LCs
      const deployedLCtx_A = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(A.address, oneYearFromAllocation);
      const deployedLCtx_B = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(B.address, oneYearFromAllocation);
      const deployedLCtx_C = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(C.address, oneYearFromAllocation);

      // Grab contract objects from deployment tx events
      const LC_A = await th.getLCFromDeploymentTx(deployedLCtx_A);
      const LC_B = await th.getLCFromDeploymentTx(deployedLCtx_B);
      const LC_C = await th.getLCFromDeploymentTx(deployedLCtx_C);

      // Multisig transfers ProtocolToken to each LC
      await protocolToken.connect(multisig).transfer(LC_A.address, protocolTokenEntitlement_A);
      await protocolToken.connect(multisig).transfer(LC_B.address, protocolTokenEntitlement_B);
      await protocolToken.connect(multisig).transfer(LC_C.address, protocolTokenEntitlement_C);

      assert.equal(await protocolToken.balanceOf(LC_A.address), protocolTokenEntitlement_A);
      assert.equal(await protocolToken.balanceOf(LC_B.address), protocolTokenEntitlement_B);
      assert.equal(await protocolToken.balanceOf(LC_C.address), protocolTokenEntitlement_C);

      const LCs = [LC_A, LC_B, LC_C];

      // ProtocolToken multisig attempts to withdraw from LCs
      for (LC of LCs) {
        try {
          const withdrawalAttemptTx = await LC.connect(multisig).withdrawProtocolToken();
          assert.isFalse(withdrawalAttemptTx.receipt.status);
        } catch (error) {
          assert.include(error.message, "revert");
        }
      }
    });

    it("No one can withraw from a LC", async () => {
      // Deploy 3 LCs
      const deployedLCtx_A = await lockupContractFactory
        .connect(D)
        .deployLockupContract(A.address, protocolTokenEntitlement_A);

      // Grab contract objects from deployment tx events
      const LC_A = await th.getLCFromDeploymentTx(deployedLCtx_A);

      // Deployer transfers ProtocolToken to the LC
      await protocolToken.connect(multisig).transfer(LC_A.address, protocolTokenEntitlement_A);

      assert.equal(await protocolToken.balanceOf(LC_A.address), protocolTokenEntitlement_A);

      // Various EOAs attempt to withdraw from LCs
      try {
        const withdrawalAttemptTx = await LC_A.connect(G).withdrawProtocolToken();
        assert.isFalse(withdrawalAttemptTx.receipt.status);
      } catch (error) {
        assert.include(error.message, "revert");
      }

      try {
        const withdrawalAttemptTx = await LC_A.connect(H).withdrawProtocolToken();
        assert.isFalse(withdrawalAttemptTx.receipt.status);
      } catch (error) {
        assert.include(error.message, "revert");
      }

      try {
        const withdrawalAttemptTx = await LC_A.connect(I).withdrawProtocolToken();
        assert.isFalse(withdrawalAttemptTx.receipt.status);
      } catch (error) {
        assert.include(error.message, "revert");
      }
    });
  });
});
