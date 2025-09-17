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

  const newProtocolTokenSupplyCap = await protocolToken.balanceOf(communityIssuance.address);
  const protocolTokenSupplyCap = await communityIssuance.protocolTokenSupplyCap();

  if (newProtocolTokenSupplyCap.eq(protocolTokenSupplyCap)) {
    console.log("Protocol token supply cap has not changed.");
    return;
  }

  const owner = await communityIssuance.owner();

  if (owner === multisig) {
    const adapter = new EthersAdapter({
      ethers: ethers,
      signerOrProvider: deployerWallet,
    });
    const proposal = await MultisigProposal.create(adapter, multisig);

    await proposal.add(
      communityIssuance.address,
      communityIssuance.interface.encodeFunctionData("updateProtocolTokenSupplyCap", []),
    );

    await proposal.submit();
  } else {
    await mdh.sendAndWaitForTransaction(communityIssuance.updateProtocolTokenSupplyCap());

    let supplyStartTime = await communityIssuance.supplyStartTime();
    console.log(`supply start time: ${supplyStartTime}`);

    const oneYearFromDeployment = (
      Number(supplyStartTime) + timeVals.SECONDS_IN_ONE_YEAR
    ).toString();
    console.log(`time oneYearFromDeployment: ${oneYearFromDeployment}`);
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
