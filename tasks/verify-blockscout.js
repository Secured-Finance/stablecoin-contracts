const { readFileSync } = require("fs");
const { task } = require("hardhat/config");
const HardhatDeploymentHelper = require("../utils/hardhatDeploymentHelpers.js");
const axios = require("axios");
const FormData = require("form-data");

const API_URLS = {
  mainnet: "https://filecoin.blockscout.com/api",
  testnet: "https://filecoin-testnet.blockscout.com/api",
};

const verifyContract = async (
  network,
  contractAddress,
  sourceCode,
  contractName,
  compilerVersion,
  runs,
) => {
  const apiUrl = API_URLS[network];

  // Use Etherscan-compatible API format
  const params = new URLSearchParams({
    module: "contract",
    action: "verifysourcecode",
    contractaddress: contractAddress,
    sourceCode: sourceCode,
    codeformat: "solidity-single-file",
    contractname: contractName,
    compilerversion: compilerVersion,
    optimizationUsed: "1",
    runs,
    evmversion: "default",
  });

  const opts = {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  };

  try {
    const res = await axios.post(apiUrl, params.toString(), opts);

    if (res.data.status === "1") {
      console.log("Verified:", contractName, "at", contractAddress);
    } else if (res.data.result && res.data.result.includes("Smart-contract already verified")) {
      console.log("Contract already verified:", contractName, "at", contractAddress);
    } else {
      console.log("Verification response:", res.data);
    }
  } catch (error) {
    if (error.response?.data?.result?.includes("Smart-contract already verified")) {
      console.log("Contract already verified:", contractName, "at", contractAddress);
    } else {
      console.error(
        "Error verifying contract:",
        contractName,
        error.response?.data || error.message,
      );
      throw error;
    }
  }
};

task("verify-blockscout", "Verify and register contracts on Blockscout").setAction(
  async (_, hre) => {
    const { ethers, network, upgrades } = hre;
    const networkName = network.name === "localhost" ? "testnet" : network.name;
    const configParams = require(`../deployments/inputs/${networkName}.js`);
    const deployer = (await ethers.getSigners())[0];
    const mdh = new HardhatDeploymentHelper(configParams, deployer);
    const deploymentState = mdh.loadPreviousDeployment();

    const filePaths = [
      "Dependencies/PythCaller.sol",
      "Dependencies/TellorCaller.sol",
      "ActivePool.sol",
      "BorrowerOperations.sol",
      "CollSurplusPool.sol",
      "DebtToken.sol",
      "DefaultPool.sol",
      "GasPool.sol",
      "HintHelpers.sol",
      "MultiTroveGetter.sol",
      "PriceFeed.sol",
      "SortedTroves.sol",
      "StabilityPool.sol",
      "TroveManager.sol",
      "LPRewards/Unipool.sol",
      "ProtocolToken/CommunityIssuance.sol",
      "ProtocolToken/LockupContractFactory.sol",
      "ProtocolToken/ProtocolToken.sol",
      "ProtocolToken/ProtocolTokenStaking.sol",
    ];

    for (const filePath of filePaths) {
      const fileName = filePath.split("/").pop().replace(".sol", "");
      const deploymentKey = fileName.charAt(0).toLocaleLowerCase() + fileName.slice(1);
      let contractAddress = deploymentState[deploymentKey].address;

      const content = await hre.run("flatten:get-flattened-sources", {
        files: [`./contracts/${filePath}`],
      });
      const isUpgradeable = content.includes("Upgradeable");

      if (isUpgradeable) {
        const proxyContractAddress = contractAddress;
        contractAddress = await upgrades.erc1967.getImplementationAddress(proxyContractAddress);

        // Verify implementation contract
        await verifyContract(
          networkName,
          contractAddress,
          content,
          fileName,
          "v0.7.6+commit.7338295f",
          100,
        );

        // Verify proxy contract
        const proxyContent = readFileSync(
          `./tasks/utils/flattened/TransparentUpgradeableProxy.sol`,
          "utf8",
        );

        await verifyContract(
          networkName,
          proxyContractAddress,
          proxyContent,
          "TransparentUpgradeableProxy",
          "v0.8.9+commit.e5eed63a",
          200,
        );
      } else {
        // Verify non-upgradeable contract
        await verifyContract(
          networkName,
          contractAddress,
          content,
          fileName,
          "v0.7.6+commit.7338295f",
          100,
        );
      }
    }
  },
);
