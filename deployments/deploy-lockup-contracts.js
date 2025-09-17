const { TestHelper: th, TimeValues: timeVals } = require("../utils/testHelpers.js");
const HardhatDeploymentHelper = require("../utils/hardhatDeploymentHelpers.js");
const hre = require("hardhat");

async function main(configParams) {
  const date = new Date();
  console.log(date.toUTCString());
  const deployerWallet = (await ethers.getSigners())[0];
  const mdh = new HardhatDeploymentHelper(configParams, deployerWallet);
  const deploymentState = mdh.loadPreviousDeployment();

  const [protocolToken, communityIssuance, lockupContractFactory] = await Promise.all(
    ["ProtocolToken", "CommunityIssuance", "LockupContractFactory"].map(async (name) => {
      const factory = await ethers.getContractFactory(name, deployerWallet);
      const deploymentKey = name.charAt(0).toLocaleLowerCase() + name.slice(1);
      return new ethers.Contract(
        deploymentState[deploymentKey].address,
        factory.interface,
        deployerWallet,
      );
    }),
  );

  const supplyStartTime = await communityIssuance.supplyStartTime();
  const oneYearFromDeployment = (Number(supplyStartTime) + timeVals.SECONDS_IN_ONE_YEAR).toString();

  // Deploy LockupContracts - one for each beneficiary
  const lockupContracts = {};

  for (const [investor, investorAddr] of Object.entries(configParams.beneficiaries)) {
    const lockupContractEthersFactory = await ethers.getContractFactory(
      "LockupContract",
      deployerWallet,
    );
    if (deploymentState[investor] && deploymentState[investor].address) {
      console.log(
        `Using previously deployed ${investor} lockup contract at address ${deploymentState[investor].address}`,
      );
      lockupContracts[investor] = new ethers.Contract(
        deploymentState[investor].address,
        lockupContractEthersFactory.interface,
        deployerWallet,
      );
    } else {
      const txReceipt = await mdh.sendAndWaitForTransaction(
        lockupContractFactory.deployLockupContract(investorAddr, oneYearFromDeployment),
      );

      const address = txReceipt.events.find(
        (e) => e.event === "LockupContractDeployedThroughFactory",
      ).args._lockupContractAddress;

      lockupContracts[investor] = new ethers.Contract(
        address,
        lockupContractEthersFactory.interface,
        deployerWallet,
      );

      deploymentState[investor] = {
        address: address,
        txHash: txReceipt.transactionHash,
      };

      mdh.saveDeployment(deploymentState);
    }
  }

  // --- Lockup Contracts ---
  console.log("LOCKUP CONTRACT CHECKS");
  // Check lockup contracts exist for each beneficiary with correct unlock time
  for (const investor of Object.keys(lockupContracts)) {
    const lockupContract = lockupContracts[investor];
    // check LC references correct ProtocolToken
    const storedProtocolTokenAddr = await lockupContract.protocolToken();
    assert.equal(protocolToken.address, storedProtocolTokenAddr);
    // Check contract has stored correct beneficary
    const onChainBeneficiary = await lockupContract.beneficiary();
    assert.equal(
      configParams.beneficiaries[investor].toLowerCase(),
      onChainBeneficiary.toLowerCase(),
    );
    // Check correct unlock time (1 yr from deployment)
    const unlockTime = await lockupContract.unlockTime();
    assert.equal(oneYearFromDeployment, unlockTime.toString());

    console.table({
      beneficiary: investor,
      "lockupContract addr": lockupContract.address,
      "stored ProtocolToken addr": storedProtocolTokenAddr,
      "beneficiary addr": configParams.beneficiaries[investor],
      "on-chain beneficiary addr": onChainBeneficiary,
      unlockTime: unlockTime.toNumber(),
    });
  }
}

const inputFile = require(
  `./inputs/${hre.network.name === "localhost" ? "testnet" : hre.network.name}.js`,
);

main(inputFile)
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
