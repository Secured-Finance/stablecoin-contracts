const deploymentHelper = require("../../utils/testDeploymentHelpers.js");

const { TestHelper: th, TimeValues: timeValues } = require("../../utils/testHelpers.js");
const { dec, toBN, assertRevert } = th;

contract("During the initial lockup period", async () => {
  let deployer,
    teamMember_1,
    teamMember_2,
    teamMember_3,
    investor_1,
    investor_2,
    investor_3,
    A,
    B,
    C,
    D,
    E,
    F,
    G,
    H,
    I;
  let lpRewardsAddress, multisig;

  const SECONDS_IN_ONE_MONTH = timeValues.SECONDS_IN_ONE_MONTH;
  const SECONDS_IN_364_DAYS = timeValues.SECONDS_IN_ONE_DAY * 364;

  let protocolTokenContracts;

  let protocolTokenStaking;
  let protocolToken;
  let lockupContractFactory;

  // LCs for team members on vesting schedules
  let LC_T1;
  let LC_T2;
  let LC_T3;

  // LCs for investors
  let LC_I1;
  let LC_I2;
  let LC_I3;

  // 1e24 = 1 million tokens with 18 decimal digits
  const teamMemberInitialEntitlement_1 = dec(1, 24);
  const teamMemberInitialEntitlement_2 = dec(2, 24);
  const teamMemberInitialEntitlement_3 = dec(3, 24);
  const investorInitialEntitlement_1 = dec(4, 24);
  const investorInitialEntitlement_2 = dec(5, 24);
  const investorInitialEntitlement_3 = dec(6, 24);

  let oneYearFromAllocation;
  let twoYearsFromAllocation;

  before(async () => {
    const signers = await ethers.getSigners();

    [
      deployer,
      teamMember_1,
      teamMember_2,
      teamMember_3,
      investor_1,
      investor_2,
      investor_3,
      A,
      B,
      C,
      D,
      E,
      F,
      G,
      H,
      I,
    ] = signers;
    [lpRewardsAddress, multisig] = signers.slice(998, 1000);

    await hre.network.provider.send("hardhat_reset");

    const transactionCount = await deployer.getTransactionCount();
    const cpContracts = await deploymentHelper.computeCoreProtocolContracts(
      deployer.address,
      transactionCount + 1,
    );
    await deploymentHelper.deployProtocolCore(th.GAS_COMPENSATION, th.MIN_NET_DEBT, cpContracts);
    protocolTokenContracts = await deploymentHelper.deployProtocolTokenTesterContracts(
      deployer.address,
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

    protocolTokenStaking = protocolTokenContracts.protocolTokenStaking;
    protocolToken = protocolTokenContracts.protocolToken;
    lockupContractFactory = protocolTokenContracts.lockupContractFactory;

    oneYearFromAllocation = await th.getTimeFromAllocation(
      protocolToken,
      timeValues.SECONDS_IN_ONE_YEAR,
    );
    const secondsInTwoYears = toBN(timeValues.SECONDS_IN_ONE_YEAR).mul(toBN("2"));
    twoYearsFromAllocation = await th.getTimeFromAllocation(protocolToken, secondsInTwoYears);

    // Deploy 3 LCs for team members on vesting schedules
    const deployedLCtx_T1 = await lockupContractFactory
      .connect(deployer)
      .deployLockupContract(teamMember_1.address, oneYearFromAllocation);
    const deployedLCtx_T2 = await lockupContractFactory
      .connect(deployer)
      .deployLockupContract(teamMember_2.address, oneYearFromAllocation);
    const deployedLCtx_T3 = await lockupContractFactory
      .connect(deployer)
      .deployLockupContract(teamMember_3.address, oneYearFromAllocation);

    // Deploy 3 LCs for investors
    const deployedLCtx_I1 = await lockupContractFactory
      .connect(deployer)
      .deployLockupContract(investor_1.address, oneYearFromAllocation);
    const deployedLCtx_I2 = await lockupContractFactory
      .connect(deployer)
      .deployLockupContract(investor_2.address, oneYearFromAllocation);
    const deployedLCtx_I3 = await lockupContractFactory
      .connect(deployer)
      .deployLockupContract(investor_3.address, oneYearFromAllocation);

    // LCs for team members on vesting schedules
    LC_T1 = await th.getLCFromDeploymentTx(deployedLCtx_T1);
    LC_T2 = await th.getLCFromDeploymentTx(deployedLCtx_T2);
    LC_T3 = await th.getLCFromDeploymentTx(deployedLCtx_T3);

    // LCs for investors
    LC_I1 = await th.getLCFromDeploymentTx(deployedLCtx_I1);
    LC_I2 = await th.getLCFromDeploymentTx(deployedLCtx_I2);
    LC_I3 = await th.getLCFromDeploymentTx(deployedLCtx_I3);

    // Multisig transfers initial ProtocolToken entitlements to LCs
    await protocolToken.connect(multisig).transfer(LC_T1.address, teamMemberInitialEntitlement_1);
    await protocolToken.connect(multisig).transfer(LC_T2.address, teamMemberInitialEntitlement_2);
    await protocolToken.connect(multisig).transfer(LC_T3.address, teamMemberInitialEntitlement_3);

    await protocolToken.connect(multisig).transfer(LC_I1.address, investorInitialEntitlement_1);
    await protocolToken.connect(multisig).transfer(LC_I2.address, investorInitialEntitlement_2);
    await protocolToken.connect(multisig).transfer(LC_I3.address, investorInitialEntitlement_3);

    // Fast forward time 364 days, so that still less than 1 year since launch has passed
    await th.fastForwardTime(SECONDS_IN_364_DAYS, web3.currentProvider);
  });

  describe("Withdrawal Attempts on LCs before unlockTime has passed ", async () => {
    it("Multisig can't withdraw from a funded LC they deployed for another beneficiary through the Factory before the unlockTime", async () => {
      // Check currentTime < unlockTime
      const currentTime = toBN(await th.getLatestBlockTimestamp(web3));
      const unlockTime = await LC_T1.unlockTime();
      assert.isTrue(currentTime.lt(unlockTime));

      // Multisig attempts withdrawal from LC they deployed through the Factory
      try {
        const withdrawalAttempt = await LC_T1.connect(multisig).withdrawProtocolToken();
        assert.isFalse(withdrawalAttempt.receipt.status);
      } catch (error) {
        assert.include(error.message, "LockupContract: caller is not the beneficiary");
      }
    });

    it("Multisig can't withdraw from a funded LC that someone else deployed before the unlockTime", async () => {
      // Account D deploys a new LC via the Factory
      const deployedLCtx_B = await lockupContractFactory
        .connect(D)
        .deployLockupContract(B.address, oneYearFromAllocation);
      const LC_B = await th.getLCFromDeploymentTx(deployedLCtx_B);

      //ProtocolToken multisig fund the newly deployed LCs
      await protocolToken.connect(multisig).transfer(LC_B.address, dec(2, 18));

      // Check currentTime < unlockTime
      const currentTime = toBN(await th.getLatestBlockTimestamp(web3));
      const unlockTime = await LC_B.unlockTime();
      assert.isTrue(currentTime.lt(unlockTime));

      // Multisig attempts withdrawal from LCs
      try {
        const withdrawalAttempt_B = await LC_B.connect(multisig).withdrawProtocolToken();
        const receipt_B = await withdrawalAttempt_B.wait();
        assert.equal(receipt_B.status, 1);
      } catch (error) {
        assert.include(error.message, "LockupContract: caller is not the beneficiary");
      }
    });

    it("Beneficiary can't withdraw from their funded LC before the unlockTime", async () => {
      // Account D deploys a new LC via the Factory
      const deployedLCtx_B = await lockupContractFactory
        .connect(D)
        .deployLockupContract(B.address, oneYearFromAllocation);
      const LC_B = await th.getLCFromDeploymentTx(deployedLCtx_B);

      // Multisig funds contracts
      await protocolToken.connect(multisig).transfer(LC_B.address, dec(2, 18));

      // Check currentTime < unlockTime
      const currentTime = toBN(await th.getLatestBlockTimestamp(web3));
      const unlockTime = await LC_B.unlockTime();
      assert.isTrue(currentTime.lt(unlockTime));

      /* Beneficiaries of all LCS - team, investor, and newly created LCs - 
      attempt to withdraw from their respective funded contracts */
      const LCs = [LC_T1, LC_T2, LC_T3, LC_I1, LC_I2, LC_T3, LC_B];

      for (LC of LCs) {
        try {
          const beneficiaryAddr = await LC.beneficiary();
          const beneficiary = await ethers.provider.getSigner(beneficiaryAddr);
          const withdrawalAttempt = await LC.connect(beneficiary).withdrawProtocolToken();
          const receipt = await withdrawalAttempt.wait();
          assert.equal(receipt.status, 1);
        } catch (error) {
          assert.include(error.message, "LockupContract: The lockup duration must have passed");
        }
      }
    });

    it("No one can withdraw from a beneficiary's funded LC before the unlockTime", async () => {
      // Account D deploys a new LC via the Factory
      const deployedLCtx_B = await lockupContractFactory
        .connect(D)
        .deployLockupContract(B.address, oneYearFromAllocation);
      const LC_B = await th.getLCFromDeploymentTx(deployedLCtx_B);

      // Multisig funds contract
      await protocolToken.connect(multisig).transfer(LC_B.address, dec(2, 18));

      // Check currentTime < unlockTime
      const currentTime = toBN(await th.getLatestBlockTimestamp(web3));
      const unlockTime = await LC_B.unlockTime();
      assert.isTrue(currentTime.lt(unlockTime));

      const variousEOAs = [teamMember_2, deployer, multisig, investor_1, A, C, D, E];

      // Several EOAs attempt to withdraw from LC deployed by D
      for (const account of variousEOAs) {
        try {
          const withdrawalAttempt = await LC_B.connect(account).withdrawProtocolToken();
          const receipt = await withdrawalAttempt.wait();
          assert.equal(receipt.status, 1);
        } catch (error) {
          assert.include(error.message, "LockupContract: caller is not the beneficiary");
        }
      }

      // Several EOAs attempt to withdraw from LC_T1 deployed by ProtocolToken deployer
      for (const account of variousEOAs) {
        try {
          const withdrawalAttempt = await LC_T1.connect(account).withdrawProtocolToken();
          const receipt = await withdrawalAttempt.wait();
          assert.equal(receipt.status, 1);
        } catch (error) {
          assert.include(error.message, "LockupContract: caller is not the beneficiary");
        }
      }
    });
  });

  describe("ProtocolToken transfer during first year after ProtocolToken deployment", async () => {
    it("Anyone can transfer ProtocolToken to LCs deployed by anyone through the Factory", async () => {
      // Start D, E, F with some ProtocolToken
      await protocolToken.unprotectedMint(D.address, dec(1, 24));
      await protocolToken.unprotectedMint(E.address, dec(2, 24));
      await protocolToken.unprotectedMint(F.address, dec(3, 24));

      // H, I, and Deployer deploy lockup contracts with A, B, C as beneficiaries, respectively
      const deployedLCtx_A = await lockupContractFactory
        .connect(H)
        .deployLockupContract(A.address, oneYearFromAllocation);
      const deployedLCtx_B = await lockupContractFactory
        .connect(I)
        .deployLockupContract(B.address, oneYearFromAllocation);
      const deployedLCtx_C = await lockupContractFactory
        .connect(multisig)
        .deployLockupContract(C.address, oneYearFromAllocation);

      // Grab contract addresses from deployment tx events
      const LCAddress_A = await th.getLCAddressFromDeploymentTx(deployedLCtx_A);
      const LCAddress_B = await th.getLCAddressFromDeploymentTx(deployedLCtx_B);
      const LCAddress_C = await th.getLCAddressFromDeploymentTx(deployedLCtx_C);

      // Check balances of LCs are 0
      assert.equal(await protocolToken.balanceOf(LCAddress_A), "0");
      assert.equal(await protocolToken.balanceOf(LCAddress_B), "0");
      assert.equal(await protocolToken.balanceOf(LCAddress_C), "0");

      // D, E, F transfer ProtocolToken to LCs
      await protocolToken.connect(D).transfer(LCAddress_A, dec(1, 24));
      await protocolToken.connect(E).transfer(LCAddress_B, dec(2, 24));
      await protocolToken.connect(F).transfer(LCAddress_C, dec(3, 24));

      // Check balances of LCs has increased
      assert.equal(await protocolToken.balanceOf(LCAddress_A), dec(1, 24));
      assert.equal(await protocolToken.balanceOf(LCAddress_B), dec(2, 24));
      assert.equal(await protocolToken.balanceOf(LCAddress_C), dec(3, 24));
    });

    it("Anyone can transfer ProtocolToken to LCs deployed by anyone directly", async () => {
      // Start D, E, F with some ProtocolToken
      await protocolToken.unprotectedMint(D.address, dec(1, 24));
      await protocolToken.unprotectedMint(E.address, dec(2, 24));
      await protocolToken.unprotectedMint(F.address, dec(3, 24));

      const _lockupContractFactory = await deploymentHelper.getFactory("LockupContract");

      // H, I, LiqAG deploy lockup contracts with A, B, C as beneficiaries, respectively
      const LC_A = await _lockupContractFactory
        .connect(H)
        .deploy(protocolToken.address, A.address, oneYearFromAllocation);
      const LC_B = await _lockupContractFactory
        .connect(I)
        .deploy(protocolToken.address, B.address, oneYearFromAllocation);
      const LC_C = await _lockupContractFactory
        .connect(multisig)
        .deploy(protocolToken.address, C.address, oneYearFromAllocation);

      // Check balances of LCs are 0
      assert.equal(await protocolToken.balanceOf(LC_A.address), "0");
      assert.equal(await protocolToken.balanceOf(LC_B.address), "0");
      assert.equal(await protocolToken.balanceOf(LC_C.address), "0");

      // D, E, F transfer ProtocolToken to LCs
      await protocolToken.connect(D).transfer(LC_A.address, dec(1, 24));
      await protocolToken.connect(E).transfer(LC_B.address, dec(2, 24));
      await protocolToken.connect(F).transfer(LC_C.address, dec(3, 24));

      // Check balances of LCs has increased
      assert.equal(await protocolToken.balanceOf(LC_A.address), dec(1, 24));
      assert.equal(await protocolToken.balanceOf(LC_B.address), dec(2, 24));
      assert.equal(await protocolToken.balanceOf(LC_C.address), dec(3, 24));
    });

    it("Anyone can transfer to an EOA", async () => {
      // Start D, E, F with some ProtocolToken
      await protocolToken.unprotectedMint(D.address, dec(1, 24));
      await protocolToken.unprotectedMint(E.address, dec(2, 24));
      await protocolToken.unprotectedMint(F.address, dec(3, 24));

      // ProtocolToken holders transfer to other transfer to EOAs
      const protocolTokenTransferTx_1 = await protocolToken
        .connect(D)
        .transfer(A.address, dec(1, 18));
      const protocolTokenTransferTx_2 = await protocolToken
        .connect(E)
        .transfer(B.address, dec(1, 18));
      const protocolTokenTransferTx_3 = await protocolToken
        .connect(F)
        .transfer(multisig.address, dec(1, 18));

      const receipt_1 = await protocolTokenTransferTx_1.wait();
      const receipt_2 = await protocolTokenTransferTx_2.wait();
      const receipt_3 = await protocolTokenTransferTx_3.wait();

      assert.equal(receipt_1.status, 1);
      assert.equal(receipt_2.status, 1);
      assert.equal(receipt_3.status, 1);
    });

    it("Anyone can approve any EOA or to spend their ProtocolToken", async () => {
      // EOAs approve EOAs to spend ProtocolToken
      const protocolTokenApproveTx_1 = await protocolToken
        .connect(F)
        .approve(A.address, dec(1, 18));
      const protocolTokenApproveTx_2 = await protocolToken
        .connect(G)
        .approve(B.address, dec(1, 18));
      const receipt_1 = await protocolTokenApproveTx_1.wait();
      const receipt_2 = await protocolTokenApproveTx_2.wait();

      assert.equal(receipt_1.status, 1);
      assert.equal(receipt_2.status, 1);
    });

    it("Anyone can be the sender in a transferFrom() call", async () => {
      // Fund A, B
      await protocolToken.unprotectedMint(A.address, dec(1, 18));
      await protocolToken.unprotectedMint(B.address, dec(1, 18));

      // A, B approve F, G
      await protocolToken.connect(A).approve(F.address, dec(1, 18));
      await protocolToken.connect(B).approve(G.address, dec(1, 18));

      const protocolTokenTransferFromTx_1 = await protocolToken
        .connect(F)
        .transferFrom(A.address, F.address, dec(1, 18));
      const protocolTokenTransferFromTx_2 = await protocolToken
        .connect(G)
        .transferFrom(B.address, C.address, dec(1, 18));
      const receipt_1 = await protocolTokenTransferFromTx_1.wait();
      const receipt_2 = await protocolTokenTransferFromTx_2.wait();

      assert.equal(receipt_1.status, 1);
      assert.equal(receipt_2.status, 1);
    });

    it("Anyone (other than deployer) can stake their ProtocolToken in the staking contract", async () => {
      // Fund F
      await protocolToken.unprotectedMint(F.address, dec(1, 18));

      const ProtocolTokenStakingTx_1 = await protocolTokenStaking.connect(F).stake(dec(1, 18));
      const receipt = await ProtocolTokenStakingTx_1.wait();

      assert.equal(receipt.status, 1);
    });
  });
  // --- LCF ---

  describe("Lockup Contract Factory negative tests", async () => {
    it("deployLockupContract(): reverts when ProtocolToken token address is wrong", async () => {
      // Fund F
      await protocolToken.unprotectedMint(F.address, dec(20, 24));

      // deploy new LCF
      const nonPayableFactory = await deploymentHelper.getFactory("NonPayable");
      const lockupContractFactoryFactory =
        await deploymentHelper.getFactory("LockupContractFactory");
      const dumbContract = await nonPayableFactory.deploy();
      const lcfNew = await deploymentHelper.deployProxy(lockupContractFactoryFactory, [
        dumbContract.address,
      ]);

      // Check ProtocolToken address not registered
      const registeredProtocolTokenAddr = await lcfNew.protocolTokenAddress();
      assert.equal(registeredProtocolTokenAddr, dumbContract.address);

      const tx = lcfNew.connect(F).deployLockupContract(A.address, oneYearFromAllocation);
      await assertRevert(tx);
    });
  });

  // --- LCs ---
  describe("Transferring ProtocolToken to LCs", async () => {
    it("Multisig can transfer ProtocolToken (vesting) to lockup contracts they deployed", async () => {
      const initialProtocolTokenBalanceOfLC_T1 = await protocolToken.balanceOf(LC_T1.address);
      const initialProtocolTokenBalanceOfLC_T2 = await protocolToken.balanceOf(LC_T2.address);
      const initialProtocolTokenBalanceOfLC_T3 = await protocolToken.balanceOf(LC_T3.address);

      // Check initial LC balances == entitlements
      assert.equal(initialProtocolTokenBalanceOfLC_T1, teamMemberInitialEntitlement_1);
      assert.equal(initialProtocolTokenBalanceOfLC_T2, teamMemberInitialEntitlement_2);
      assert.equal(initialProtocolTokenBalanceOfLC_T3, teamMemberInitialEntitlement_3);

      // One month passes
      await th.fastForwardTime(SECONDS_IN_ONE_MONTH, web3.currentProvider);

      // Multisig transfers vesting amount
      await protocolToken.connect(multisig).transfer(LC_T1.address, dec(1, 24));
      await protocolToken.connect(multisig).transfer(LC_T2.address, dec(1, 24));
      await protocolToken.connect(multisig).transfer(LC_T3.address, dec(1, 24));

      // Get new LC ProtocolToken balances
      const protocolTokenBalanceOfLC_T1_1 = await protocolToken.balanceOf(LC_T1.address);
      const protocolTokenBalanceOfLC_T2_1 = await protocolToken.balanceOf(LC_T2.address);
      const protocolTokenBalanceOfLC_T3_1 = await protocolToken.balanceOf(LC_T3.address);

      // // Check team member LC balances have increased
      assert.isTrue(
        protocolTokenBalanceOfLC_T1_1.eq(
          th.toBN(initialProtocolTokenBalanceOfLC_T1).add(th.toBN(dec(1, 24))),
        ),
      );
      assert.isTrue(
        protocolTokenBalanceOfLC_T2_1.eq(
          th.toBN(initialProtocolTokenBalanceOfLC_T2).add(th.toBN(dec(1, 24))),
        ),
      );
      assert.isTrue(
        protocolTokenBalanceOfLC_T3_1.eq(
          th.toBN(initialProtocolTokenBalanceOfLC_T3).add(th.toBN(dec(1, 24))),
        ),
      );

      // Another month passes
      await th.fastForwardTime(SECONDS_IN_ONE_MONTH, web3.currentProvider);

      // Multisig transfers vesting amount
      await protocolToken.connect(multisig).transfer(LC_T1.address, dec(1, 24));
      await protocolToken.connect(multisig).transfer(LC_T2.address, dec(1, 24));
      await protocolToken.connect(multisig).transfer(LC_T3.address, dec(1, 24));

      // Get new LC ProtocolToken balances
      const protocolTokenBalanceOfLC_T1_2 = await protocolToken.balanceOf(LC_T1.address);
      const protocolTokenBalanceOfLC_T2_2 = await protocolToken.balanceOf(LC_T2.address);
      const protocolTokenBalanceOfLC_T3_2 = await protocolToken.balanceOf(LC_T3.address);

      // Check team member LC balances have increased again
      assert.isTrue(
        protocolTokenBalanceOfLC_T1_2.eq(protocolTokenBalanceOfLC_T1_1.add(th.toBN(dec(1, 24)))),
      );
      assert.isTrue(
        protocolTokenBalanceOfLC_T2_2.eq(protocolTokenBalanceOfLC_T2_1.add(th.toBN(dec(1, 24)))),
      );
      assert.isTrue(
        protocolTokenBalanceOfLC_T3_2.eq(protocolTokenBalanceOfLC_T3_1.add(th.toBN(dec(1, 24)))),
      );
    });

    it("Multisig can transfer ProtocolToken to lockup contracts deployed by anyone", async () => {
      // A, B, C each deploy a lockup contract with themself as beneficiary
      const deployedLCtx_A = await lockupContractFactory
        .connect(A)
        .deployLockupContract(A.address, twoYearsFromAllocation);
      const deployedLCtx_B = await lockupContractFactory
        .connect(B)
        .deployLockupContract(B.address, twoYearsFromAllocation);
      const deployedLCtx_C = await lockupContractFactory
        .connect(C)
        .deployLockupContract(C.address, twoYearsFromAllocation);

      // LCs for team members on vesting schedules
      const LC_A = await th.getLCFromDeploymentTx(deployedLCtx_A);
      const LC_B = await th.getLCFromDeploymentTx(deployedLCtx_B);
      const LC_C = await th.getLCFromDeploymentTx(deployedLCtx_C);

      // Check balances of LCs are 0
      assert.equal(await protocolToken.balanceOf(LC_A.address), "0");
      assert.equal(await protocolToken.balanceOf(LC_B.address), "0");
      assert.equal(await protocolToken.balanceOf(LC_C.address), "0");

      // One month passes
      await th.fastForwardTime(SECONDS_IN_ONE_MONTH, web3.currentProvider);

      // Multisig transfers ProtocolToken to LCs deployed by other accounts
      await protocolToken.connect(multisig).transfer(LC_A.address, dec(1, 24));
      await protocolToken.connect(multisig).transfer(LC_B.address, dec(2, 24));
      await protocolToken.connect(multisig).transfer(LC_C.address, dec(3, 24));

      // Check balances of LCs have increased
      assert.equal(await protocolToken.balanceOf(LC_A.address), dec(1, 24));
      assert.equal(await protocolToken.balanceOf(LC_B.address), dec(2, 24));
      assert.equal(await protocolToken.balanceOf(LC_C.address), dec(3, 24));
    });
  });

  describe("Deploying new LCs", async () => {
    it("ProtocolToken Deployer can deploy LCs through the Factory", async () => {
      // ProtocolToken deployer deploys LCs
      const lcDeploymentTx_A = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(A.address, oneYearFromAllocation);
      const lcDeploymentTx_B = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(B.address, twoYearsFromAllocation);
      const lcDeploymentTx_C = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(C.address, "9595995999999900000023423234");

      const receipt_A = await lcDeploymentTx_A.wait();
      const receipt_B = await lcDeploymentTx_B.wait();
      const receipt_C = await lcDeploymentTx_C.wait();

      assert.equal(receipt_A.status, 1);
      assert.equal(receipt_B.status, 1);
      assert.equal(receipt_C.status, 1);
    });

    it("Multisig can deploy LCs through the Factory", async () => {
      // ProtocolToken deployer deploys LCs
      const lcDeploymentTx_A = await lockupContractFactory
        .connect(multisig)
        .deployLockupContract(A.address, oneYearFromAllocation);
      const lcDeploymentTx_B = await lockupContractFactory
        .connect(multisig)
        .deployLockupContract(B.address, twoYearsFromAllocation);
      const lcDeploymentTx_C = await lockupContractFactory
        .connect(multisig)
        .deployLockupContract(C.address, "9595995999999900000023423234");

      const receipt_A = await lcDeploymentTx_A.wait();
      const receipt_B = await lcDeploymentTx_B.wait();
      const receipt_C = await lcDeploymentTx_C.wait();

      assert.equal(receipt_A.status, 1);
      assert.equal(receipt_B.status, 1);
      assert.equal(receipt_C.status, 1);
    });

    it("Anyone can deploy LCs through the Factory", async () => {
      // Various EOAs deploy LCs
      const lcDeploymentTx_1 = await lockupContractFactory
        .connect(teamMember_1)
        .deployLockupContract(A.address, oneYearFromAllocation);
      const lcDeploymentTx_2 = await lockupContractFactory
        .connect(investor_2)
        .deployLockupContract(C.address, twoYearsFromAllocation);
      const lcDeploymentTx_3 = await lockupContractFactory
        .connect(A)
        .deployLockupContract(deployer.address, "9595995999999900000023423234");
      const lcDeploymentTx_4 = await lockupContractFactory
        .connect(B)
        .deployLockupContract(D.address, twoYearsFromAllocation);

      const receipt_1 = await lcDeploymentTx_1.wait();
      const receipt_2 = await lcDeploymentTx_2.wait();
      const receipt_3 = await lcDeploymentTx_3.wait();
      const receipt_4 = await lcDeploymentTx_4.wait();

      assert.equal(receipt_1.status, 1);
      assert.equal(receipt_2.status, 1);
      assert.equal(receipt_3.status, 1);
      assert.equal(receipt_4.status, 1);
    });

    it("ProtocolToken Deployer can deploy LCs directly", async () => {
      // ProtocolToken deployer deploys LCs
      const _lockupContractFactory = await deploymentHelper.getFactory("LockupContract");

      const lcTx_A = await _lockupContractFactory
        .connect(deployer)
        .deploy(protocolToken.address, A.address, oneYearFromAllocation);
      const lcTx_B = await _lockupContractFactory
        .connect(deployer)
        .deploy(protocolToken.address, B.address, twoYearsFromAllocation);
      const lcTx_C = await _lockupContractFactory
        .connect(deployer)
        .deploy(protocolToken.address, C.address, twoYearsFromAllocation);

      const receipt_A = await lcTx_A.deployTransaction.wait();
      const receipt_B = await lcTx_B.deployTransaction.wait();
      const receipt_C = await lcTx_C.deployTransaction.wait();

      // Check deployment succeeded
      assert.equal(receipt_A.status, 1);
      assert.equal(receipt_B.status, 1);
      assert.equal(receipt_C.status, 1);
    });

    it("Multisig can deploy LCs directly", async () => {
      // ProtocolToken deployer deploys LCs
      const _lockupContractFactory = await deploymentHelper.getFactory("LockupContract");

      const lcTx_A = await _lockupContractFactory
        .connect(multisig)
        .deploy(protocolToken.address, A.address, oneYearFromAllocation);
      const lcTx_B = await _lockupContractFactory
        .connect(multisig)
        .deploy(protocolToken.address, B.address, twoYearsFromAllocation);
      const lcTx_C = await _lockupContractFactory
        .connect(multisig)
        .deploy(protocolToken.address, C.address, twoYearsFromAllocation);

      const receipt_A = await lcTx_A.deployTransaction.wait();
      const receipt_B = await lcTx_B.deployTransaction.wait();
      const receipt_C = await lcTx_C.deployTransaction.wait();

      // Check deployment succeeded
      assert.equal(receipt_A.status, 1);
      assert.equal(receipt_B.status, 1);
      assert.equal(receipt_C.status, 1);
    });

    it("Anyone can deploy LCs directly", async () => {
      // Various EOAs deploy LCs
      const _lockupContractFactory = await deploymentHelper.getFactory("LockupContract");

      const lcTx_A = await _lockupContractFactory
        .connect(D)
        .deploy(protocolToken.address, A.address, oneYearFromAllocation);
      const lcTx_B = await _lockupContractFactory
        .connect(E)
        .deploy(protocolToken.address, B.address, twoYearsFromAllocation);
      const lcTx_C = await _lockupContractFactory
        .connect(F)
        .deploy(protocolToken.address, C.address, twoYearsFromAllocation);

      const receipt_A = await lcTx_A.deployTransaction.wait();
      const receipt_B = await lcTx_B.deployTransaction.wait();
      const receipt_C = await lcTx_C.deployTransaction.wait();

      // Check deployment succeeded
      assert.equal(receipt_A.status, 1);
      assert.equal(receipt_B.status, 1);
      assert.equal(receipt_C.status, 1);
    });

    it("Anyone can deploy LCs with unlockTime = one year from deployment, directly and through factory", async () => {
      // Deploy directly
      const _lockupContractFactory = await deploymentHelper.getFactory("LockupContract");

      const lcTx_1 = await _lockupContractFactory
        .connect(D)
        .deploy(protocolToken.address, A.address, oneYearFromAllocation);
      const lcTx_2 = await _lockupContractFactory
        .connect(deployer)
        .deploy(protocolToken.address, B.address, oneYearFromAllocation);
      const lcTx_3 = await _lockupContractFactory
        .connect(multisig)
        .deploy(protocolToken.address, C.address, oneYearFromAllocation);

      // Deploy through factory
      const lcTx_4 = await lockupContractFactory
        .connect(E)
        .deployLockupContract(A.address, oneYearFromAllocation);
      const lcTx_5 = await lockupContractFactory
        .connect(deployer)
        .deployLockupContract(C.address, twoYearsFromAllocation);
      const lcTx_6 = await lockupContractFactory
        .connect(multisig)
        .deployLockupContract(D.address, twoYearsFromAllocation);

      const receipt_1 = await lcTx_1.deployTransaction.wait();
      const receipt_2 = await lcTx_2.deployTransaction.wait();
      const receipt_3 = await lcTx_3.deployTransaction.wait();
      const receipt_4 = await lcTx_4.wait();
      const receipt_5 = await lcTx_5.wait();
      const receipt_6 = await lcTx_6.wait();

      // Check deployments succeeded
      assert.equal(receipt_1.status, 1);
      assert.equal(receipt_2.status, 1);
      assert.equal(receipt_3.status, 1);
      assert.equal(receipt_4.status, 1);
      assert.equal(receipt_5.status, 1);
      assert.equal(receipt_6.status, 1);
    });

    it("Anyone can deploy LCs with unlockTime > one year from deployment, directly and through factory", async () => {
      const justOverOneYear = oneYearFromAllocation.add(toBN("1"));
      const _17YearsFromDeployment = oneYearFromAllocation.add(
        toBN(timeValues.SECONDS_IN_ONE_YEAR).mul(toBN("2")),
      );

      // Deploy directly
      const _lockupContractFactory = await deploymentHelper.getFactory("LockupContract");

      const lcTx_1 = await _lockupContractFactory
        .connect(D)
        .deploy(protocolToken.address, A.address, twoYearsFromAllocation);
      const lcTx_2 = await _lockupContractFactory
        .connect(multisig)
        .deploy(protocolToken.address, B.address, justOverOneYear);
      const lcTx_3 = await _lockupContractFactory
        .connect(E)
        .deploy(protocolToken.address, E.address, _17YearsFromDeployment);

      // Deploy through factory
      const lcTx_4 = await lockupContractFactory
        .connect(E)
        .deployLockupContract(A.address, oneYearFromAllocation);
      const lcTx_5 = await lockupContractFactory
        .connect(multisig)
        .deployLockupContract(C.address, twoYearsFromAllocation);
      const lcTx_6 = await lockupContractFactory
        .connect(teamMember_2)
        .deployLockupContract(D.address, twoYearsFromAllocation);

      const receipt_1 = await lcTx_1.deployTransaction.wait();
      const receipt_2 = await lcTx_2.deployTransaction.wait();
      const receipt_3 = await lcTx_3.deployTransaction.wait();
      const receipt_4 = await lcTx_4.wait();
      const receipt_5 = await lcTx_5.wait();
      const receipt_6 = await lcTx_6.wait();

      // Check deployments succeeded
      assert.equal(receipt_1.status, 1);
      assert.equal(receipt_2.status, 1);
      assert.equal(receipt_3.status, 1);
      assert.equal(receipt_4.status, 1);
      assert.equal(receipt_5.status, 1);
      assert.equal(receipt_6.status, 1);
    });

    it("No one can deploy LCs with unlockTime < one year from deployment, directly or through factory", async () => {
      const justUnderOneYear = oneYearFromAllocation.sub(toBN("1"));

      // Attempt to deploy directly
      const _lockupContractFactory = await deploymentHelper.getFactory("LockupContract");

      const directDeploymentTxPromise_1 = _lockupContractFactory
        .connect(D)
        .deploy(protocolToken.address, A.address, justUnderOneYear);
      const directDeploymentTxPromise_2 = _lockupContractFactory
        .connect(multisig)
        .deploy(protocolToken.address, B.address, "43200");
      const directDeploymentTxPromise_3 = _lockupContractFactory
        .connect(E)
        .deploy(protocolToken.address, E.address, "354534");

      // Attempt to deploy through factory
      const factoryDploymentTxPromise_1 = lockupContractFactory
        .connect(E)
        .deployLockupContract(A.address, justUnderOneYear);
      const factoryDploymentTxPromise_2 = lockupContractFactory
        .connect(multisig)
        .deployLockupContract(C.address, "43200");
      const factoryDploymentTxPromise_3 = lockupContractFactory
        .connect(teamMember_2)
        .deployLockupContract(D.address, "354534");

      // Check deployments reverted
      await assertRevert(
        directDeploymentTxPromise_1,
        "LockupContract: unlock time must be at least one year after allocation start¸",
      );
      await assertRevert(
        directDeploymentTxPromise_2,
        "LockupContract: unlock time must be at least one year after allocation start¸",
      );
      await assertRevert(
        directDeploymentTxPromise_3,
        "LockupContract: unlock time must be at least one year after allocation start¸",
      );
      await assertRevert(
        factoryDploymentTxPromise_1,
        "LockupContract: unlock time must be at least one year after allocation start¸",
      );
      await assertRevert(
        factoryDploymentTxPromise_2,
        "LockupContract: unlock time must be at least one year after allocation start¸",
      );
      await assertRevert(
        factoryDploymentTxPromise_3,
        "LockupContract: unlock time must be at least one year after allocation start¸",
      );
    });
  });
});
