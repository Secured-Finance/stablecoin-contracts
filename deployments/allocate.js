const { TestHelper: th, TimeValues: timeVals } = require("../utils/testHelpers.js");
const { dec, toBN } = th;
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

  const factory = await ethers.getContractFactory("ProtocolToken", deployerWallet);
  const protocolToken = await new ethers.Contract(
    deploymentState["protocolToken"].address,
    factory.interface,
    deployerWallet,
  );

  // Allocate tokens to the admin, community issuance, and uni pool
  const account = configParams.walletAddrs.FOUNDATION;
  const amount = configParams.allocationAmounts.FOUNDATION;

  const convertFromFullAmount = (amount) =>
    toBN(amount).div(dec(1, 18)).toNumber().toLocaleString();

  console.log("Token allocation:");
  console.table({
    admin: { address: account, amount: convertFromFullAmount(amount) },
  });

  const owner = await protocolToken.owner();

  if (owner === multisig) {
    const adapter = new EthersAdapter({
      ethers: ethers,
      signerOrProvider: deployerWallet,
    });
    const proposal = await MultisigProposal.create(adapter, multisig);

    await proposal.add(
      protocolToken.address,
      protocolToken.interface.encodeFunctionData("triggerInitialAllocation", [[account], [amount]]),
    );

    await proposal.submit();
  } else {
    await mdh.sendAndWaitForTransaction(
      protocolToken.triggerInitialAllocation([account], [amount]),
    );
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
