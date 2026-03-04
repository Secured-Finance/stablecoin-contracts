const { TimeValues: timeVals } = require("../utils/testHelpers.js");
const hre = require("hardhat");
const { EthersAdapter } = require("@safe-global/protocol-kit");

const HardhatDeploymentHelper = require("../utils/hardhatDeploymentHelpers.js");
const { MultisigProposal } = require("../utils/multisig.js");

async function main(configParams) {
  const date = new Date();
  console.log(date.toUTCString());
  const deployerWallet = (await ethers.getSigners())[0];
  const mdh = new HardhatDeploymentHelper(configParams, deployerWallet);
  const deploymentState = mdh.loadPreviousDeployment();
  const multisig = configParams.walletAddrs.MULTISIG;

  const [protocolToken, communityIssuance] = await Promise.all(
    ["ProtocolToken", "CommunityIssuance"].map(async (name) => {
      const factory = await ethers.getContractFactory(name, deployerWallet);
      const deploymentKey = name.charAt(0).toLocaleLowerCase() + name.slice(1);
      return new ethers.Contract(
        deploymentState[deploymentKey].address,
        factory.interface,
        deployerWallet,
      );
    }),
  );

  const protocolTokenIncreaseAmount = process.env.PROTOCOL_TOKEN_INCREASE_AMOUNT;

  if (!protocolTokenIncreaseAmount) {
    console.error("Error: PROTOCOL_TOKEN_INCREASE_AMOUNT environment variable is required.");
    return;
  }

  const amountToIncrease = ethers.utils.parseUnits(protocolTokenIncreaseAmount, 18);
  console.log(
    `Increasing protocol token supply cap by: ${protocolTokenIncreaseAmount} tokens (${amountToIncrease} wei)`,
  );

  const owner = await communityIssuance.owner();

  if (owner === multisig) {
    const adapter = new EthersAdapter({
      ethers: ethers,
      signerOrProvider: deployerWallet,
    });
    const proposal = await MultisigProposal.create(adapter, multisig);

    await proposal.add(
      protocolToken.address,
      protocolToken.interface.encodeFunctionData("approve", [
        communityIssuance.address,
        amountToIncrease,
      ]),
    );

    await proposal.add(
      communityIssuance.address,
      communityIssuance.interface.encodeFunctionData("increaseProtocolTokenSupplyCap", [
        amountToIncrease,
      ]),
    );

    await proposal.submit();
  } else {
    // Approve the CommunityIssuance contract to transfer tokens from the deployer
    await mdh.sendAndWaitForTransaction(
      protocolToken.approve(communityIssuance.address, amountToIncrease),
    );
    console.log(`Approved CommunityIssuance to transfer ${protocolTokenIncreaseAmount} tokens`);

    await mdh.sendAndWaitForTransaction(
      communityIssuance.increaseProtocolTokenSupplyCap(amountToIncrease),
    );

    let supplyStartTime = await communityIssuance.supplyStartTime();
    console.log(`Supply start time: ${supplyStartTime}`);

    const protocolTokenSupplyCap = await communityIssuance.protocolTokenSupplyCap();
    console.log(
      `New protocol token supply cap: ${ethers.utils.formatUnits(protocolTokenSupplyCap, 18)}`,
    );

    const oneYearFromDeployment = (
      Number(supplyStartTime) + timeVals.SECONDS_IN_ONE_YEAR
    ).toString();
    console.log(`Time oneYearFromDeployment: ${oneYearFromDeployment}`);
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
