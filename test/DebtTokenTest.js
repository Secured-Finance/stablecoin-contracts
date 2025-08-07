const deploymentHelper = require("../utils/testDeploymentHelpers.js");
const testHelpers = require("../utils/testHelpers.js");
const { accountsList } = require("../accountsList.js");

const { keccak256 } = require("@ethersproject/keccak256");
const { defaultAbiCoder } = require("@ethersproject/abi");
const { toUtf8Bytes } = require("@ethersproject/strings");
const { pack } = require("@ethersproject/solidity");
const { hexlify } = require("@ethersproject/bytes");
const { ecsign } = require("ethereumjs-util");

const { toBN, assertRevert, dec, ZERO_ADDRESS, GAS_COMPENSATION, MIN_NET_DEBT } =
  testHelpers.TestHelper;

const sign = (digest, privateKey) => {
  return ecsign(Buffer.from(digest.slice(2), "hex"), Buffer.from(privateKey.slice(2), "hex"));
};

const PERMIT_TYPEHASH = keccak256(
  toUtf8Bytes("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
);

// Gets the EIP712 domain separator
const getDomainSeparator = (name, contractAddress, chainId, version) => {
  return keccak256(
    defaultAbiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "uint256", "address"],
      [
        keccak256(
          toUtf8Bytes(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
          ),
        ),
        keccak256(toUtf8Bytes(name)),
        keccak256(toUtf8Bytes(version)),
        parseInt(chainId),
        contractAddress.toLowerCase(),
      ],
    ),
  );
};

// Returns the EIP712 hash which should be signed by the user
// in order to make a call to `permit`
const getPermitDigest = (
  name,
  address,
  chainId,
  version,
  owner,
  spender,
  value,
  nonce,
  deadline,
) => {
  const DOMAIN_SEPARATOR = getDomainSeparator(name, address, chainId, version);
  return keccak256(
    pack(
      ["bytes1", "bytes1", "bytes32", "bytes32"],
      [
        "0x19",
        "0x01",
        DOMAIN_SEPARATOR,
        keccak256(
          defaultAbiCoder.encode(
            ["bytes32", "address", "address", "uint256", "uint256", "uint256"],
            [PERMIT_TYPEHASH, owner, spender, value, nonce, deadline],
          ),
        ),
      ],
    ),
  );
};

contract("DebtToken", async () => {
  let signers;
  let owner, alice, bob, carol, dennis;

  let approve;

  const ownerPrivateKey = accountsList[0].privateKey;

  let chainId;
  let debtTokenOriginal;
  let debtTokenTester;
  let stabilityPool;
  let troveManager;
  let borrowerOperations;

  let contracts;
  let protocolTokenContracts;

  let tokenName;
  let tokenVersion;

  before(async () => {
    // [owner, alice, bob, carol, dennis] = await ethers.getSigners();
    signers = await ethers.getSigners();
    [owner, alice, bob, carol, dennis] = await signers.splice(0, 5);
    // owner = signers.shift();

    approve = {
      owner: owner,
      spender: alice,
      value: 1,
    };
  });

  const testCorpus = ({ withProxy = false }) => {
    before(async () => {
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
      cpContracts.debtToken = cpTesterContracts[2];

      debtTokenTester = await deploymentHelper.deployDebtTokenTester(cpContracts);

      contracts = await deploymentHelper.deployProtocolCore(
        GAS_COMPENSATION,
        MIN_NET_DEBT,
        cpContracts,
      );

      contracts.debtToken = debtTokenTester;

      protocolTokenContracts = await deploymentHelper.deployProtocolTokenTesterContracts(
        owner.address,
        cpContracts,
      );

      debtTokenOriginal = contracts.debtToken;
      debtTokenTester = contracts.debtToken;
      // for some reason this doesn’t work with coverage network
      //chainId = await web3.eth.getChainId()
      chainId = await debtTokenOriginal.getChainId();

      stabilityPool = contracts.stabilityPool;
      troveManager = contracts.stabilityPool;
      borrowerOperations = contracts.borrowerOperations;

      tokenVersion = await debtTokenOriginal.version();
      tokenName = await debtTokenOriginal.name();
    });

    beforeEach(async () => {
      if (withProxy) {
        const users = [alice, bob, carol, dennis];
        await deploymentHelper.deployProxyScripts(contracts, protocolTokenContracts, owner, users);

        debtTokenTester = contracts.debtToken;
        stabilityPool = contracts.stabilityPool;
        troveManager = contracts.stabilityPool;
        borrowerOperations = contracts.borrowerOperations;

        // mint some tokens
        await debtTokenOriginal.unprotectedMint(
          debtTokenTester.getProxyAddressFromUser(alice.address),
          150,
        );
        await debtTokenOriginal.unprotectedMint(
          debtTokenTester.getProxyAddressFromUser(bob.address),
          100,
        );
        await debtTokenOriginal.unprotectedMint(
          debtTokenTester.getProxyAddressFromUser(carol.address),
          50,
        );
      } else {
        await debtTokenOriginal.unprotectedMint(alice.address, 150);
        await debtTokenOriginal.unprotectedMint(bob.address, 100);
        await debtTokenOriginal.unprotectedMint(carol.address, 50);
      }
    });

    afterEach(async () => {
      [alice, bob, carol, dennis] = signers.splice(0, 4);

      approve = {
        owner: owner,
        spender: alice,
        value: 1,
      };
    });

    it("totalSupply(): gets the total supply", async () => {
      const total = (await debtTokenTester.totalSupply()).toString();
      assert.equal(total, "300"); // 300
    });

    it("balanceOf(): gets the balance of the account", async () => {
      const aliceBalance = (await debtTokenTester.balanceOf(alice.address)).toNumber();
      const bobBalance = (await debtTokenTester.balanceOf(bob.address)).toNumber();
      const carolBalance = (await debtTokenTester.balanceOf(carol.address)).toNumber();

      assert.equal(aliceBalance, 150);
      assert.equal(bobBalance, 100);
      assert.equal(carolBalance, 50);
    });

    it("name(): returns the token's name", async () => {
      const name = await debtTokenTester.name();
      assert.equal(name, "USD for Filecoin Community");
    });

    it("symbol(): returns the token's symbol", async () => {
      const symbol = await debtTokenTester.symbol();
      assert.equal(symbol, "USDFC");
    });

    it("decimal(): returns the number of decimal digits used", async () => {
      const decimals = await debtTokenTester.decimals();
      assert.equal(decimals, "18");
    });

    it("allowance(): returns an account's spending allowance for another account's balance", async () => {
      await debtTokenTester.connect(bob).approve(alice.address, 100);

      const allowance_A = await debtTokenTester.allowance(bob.address, alice.address);
      const allowance_D = await debtTokenTester.allowance(bob.address, dennis.address);

      assert.equal(allowance_A, 100);
      assert.equal(allowance_D, "0");
    });

    it("approve(): approves an account to spend the specified amount", async () => {
      const allowance_A_before = await debtTokenTester.allowance(bob.address, alice.address);
      assert.equal(allowance_A_before, "0");

      await debtTokenTester.connect(bob).approve(alice.address, 100);

      const allowance_A_after = await debtTokenTester.allowance(bob.address, alice.address);
      assert.equal(allowance_A_after, 100);
    });

    if (!withProxy) {
      it("approve(): reverts when spender param is address(0)", async () => {
        const txPromise = debtTokenTester.connect(bob).approve(ZERO_ADDRESS, 100);
        await assertRevert(txPromise, "ERC20: approve to the zero address");
      });

      it("approve(): reverts when owner param is address(0)", async () => {
        const txPromise = debtTokenTester
          .connect(bob)
          .callInternalApprove(ZERO_ADDRESS, alice.address, dec(1000, 18));
        await assertRevert(txPromise, "ERC20: approve from the zero address");
      });
    }

    it("transferFrom(): successfully transfers from an account which is it approved to transfer from", async () => {
      const allowance_A_0 = await debtTokenTester.allowance(bob.address, alice.address);
      assert.equal(allowance_A_0, "0");

      await debtTokenTester.connect(bob).approve(alice.address, 50);

      // Check A's allowance of Bob's funds has increased
      const allowance_A_1 = await debtTokenTester.allowance(bob.address, alice.address);
      assert.equal(allowance_A_1, 50);

      assert.equal(await debtTokenTester.balanceOf(carol.address), 50);

      // Alice transfers from bob to Carol, using up her allowance
      await debtTokenTester.connect(alice).transferFrom(bob.address, carol.address, 50);
      assert.equal(await debtTokenTester.balanceOf(carol.address), 100);

      // Check A's allowance of Bob's funds has decreased
      const allowance_A_2 = await debtTokenTester.allowance(bob.address, alice.address);
      assert.equal(allowance_A_2, "0");

      // Check bob's balance has decreased
      assert.equal(await debtTokenTester.balanceOf(bob.address), 50);

      // Alice tries to transfer more tokens from bob's account to carol than she's allowed
      const txPromise = debtTokenTester.connect(alice).transferFrom(bob.address, carol.address, 50);
      await assertRevert(txPromise);
    });

    it("transfer(): increases the recipient's balance by the correct amount", async () => {
      assert.equal(await debtTokenTester.balanceOf(alice.address), 150);

      await debtTokenTester.connect(bob).transfer(alice.address, 37);

      assert.equal(await debtTokenTester.balanceOf(alice.address), 187);
    });

    it("transfer(): reverts if amount exceeds sender's balance", async () => {
      assert.equal(await debtTokenTester.balanceOf(bob.address), 100);

      const txPromise = debtTokenTester.connect(bob).transfer(alice.address, 101);
      await assertRevert(txPromise);
    });

    it("transfer(): transferring to a blacklisted address reverts", async () => {
      await assertRevert(debtTokenTester.connect(alice).transfer(debtTokenTester.address, 1));
      await assertRevert(debtTokenTester.connect(alice).transfer(ZERO_ADDRESS, 1));
      await assertRevert(debtTokenTester.connect(alice).transfer(troveManager.address, 1));
      await assertRevert(debtTokenTester.connect(alice).transfer(stabilityPool.address, 1));
      await assertRevert(debtTokenTester.connect(alice).transfer(borrowerOperations.address, 1));
    });

    if (!withProxy) {
      it("mint(): issues correct amount of tokens to the given address", async () => {
        const alice_balanceBefore = await debtTokenTester.balanceOf(alice.address);
        assert.equal(alice_balanceBefore, 150);

        await debtTokenTester.unprotectedMint(alice.address, 100);

        const alice_BalanceAfter = await debtTokenTester.balanceOf(alice.address);
        assert.equal(alice_BalanceAfter, 250);
      });

      it("burn(): burns correct amount of tokens from the given address", async () => {
        const alice_balanceBefore = await debtTokenTester.balanceOf(alice.address);
        assert.equal(alice_balanceBefore, 150);

        await debtTokenTester.unprotectedBurn(alice.address, 70);

        const alice_BalanceAfter = await debtTokenTester.balanceOf(alice.address);
        assert.equal(alice_BalanceAfter, 80);
      });

      // TODO: Rewrite this test - it should check the actual debtTokenTester's balance.
      it("sendToPool(): changes balances of Stability pool and user by the correct amounts", async () => {
        const stabilityPool_BalanceBefore = await debtTokenTester.balanceOf(stabilityPool.address);
        const bob_BalanceBefore = await debtTokenTester.balanceOf(bob.address);
        assert.equal(stabilityPool_BalanceBefore, 0);
        assert.equal(bob_BalanceBefore, 100);

        await debtTokenTester.unprotectedSendToPool(bob.address, stabilityPool.address, 75);

        const stabilityPool_BalanceAfter = await debtTokenTester.balanceOf(stabilityPool.address);
        const bob_BalanceAfter = await debtTokenTester.balanceOf(bob.address);
        assert.equal(stabilityPool_BalanceAfter, 75);
        assert.equal(bob_BalanceAfter, 25);
      });

      it("returnFromPool(): changes balances of Stability pool and user by the correct amounts", async () => {
        /// --- SETUP --- give pool 100 DebtToken
        await debtTokenTester.unprotectedMint(stabilityPool.address, 100);

        /// --- TEST ---
        const stabilityPool_BalanceBefore = await debtTokenTester.balanceOf(stabilityPool.address);
        const bob_BalanceBefore = await debtTokenTester.balanceOf(bob.address);

        assert.equal(bob_BalanceBefore, 100);

        await debtTokenTester.unprotectedReturnFromPool(stabilityPool.address, bob.address, 75);

        const stabilityPool_BalanceAfter = await debtTokenTester.balanceOf(stabilityPool.address);
        const bob_BalanceAfter = await debtTokenTester.balanceOf(bob.address);

        assert.equal(stabilityPool_BalanceBefore.sub(stabilityPool_BalanceAfter), 75);
        assert.equal(bob_BalanceAfter, 175);
      });
    }

    it("transfer(): transferring to a blacklisted address reverts", async () => {
      await assertRevert(debtTokenTester.connect(alice).transfer(debtTokenTester.address, 1));
      await assertRevert(debtTokenTester.connect(alice).transfer(ZERO_ADDRESS, 1));
      await assertRevert(debtTokenTester.connect(alice).transfer(troveManager.address, 1));
      await assertRevert(debtTokenTester.connect(alice).transfer(stabilityPool.address, 1));
      await assertRevert(debtTokenTester.connect(alice).transfer(borrowerOperations.address, 1));
    });

    // EIP2612 tests

    if (!withProxy) {
      it("version(): returns the token contract's version", async () => {
        const version = await debtTokenTester.version();
        assert.equal(version, "1");
      });

      it("Initializes PERMIT_TYPEHASH correctly", async () => {
        assert.equal(await debtTokenTester.permitTypeHash(), PERMIT_TYPEHASH);
      });

      it("Initializes DOMAIN_SEPARATOR correctly", async () => {
        assert.equal(
          await debtTokenTester.domainSeparator(),
          getDomainSeparator(tokenName, debtTokenTester.address, chainId, tokenVersion),
        );
      });

      it("Initial nonce for a given address is 0", async function () {
        assert.equal(toBN(await debtTokenTester.nonces(alice.address)).toString(), "0");
      });

      // Create the approval tx data

      const buildPermitTx = async (deadline) => {
        const nonce = (await debtTokenTester.nonces(approve.owner.address)).toString();

        // Get the EIP712 digest
        const digest = getPermitDigest(
          tokenName,
          debtTokenTester.address,
          chainId,
          tokenVersion,
          approve.owner.address,
          approve.spender.address,
          approve.value,
          nonce,
          deadline,
        );

        const { v, r, s } = sign(digest, ownerPrivateKey);

        const tx = debtTokenTester.permit(
          approve.owner.address,
          approve.spender.address,
          approve.value,
          deadline,
          v,
          hexlify(r),
          hexlify(s),
        );

        return { v, r, s, tx };
      };

      it("permits and emits an Approval event (replay protected)", async () => {
        const deadline = 100000000000000;

        // Approve it
        const { v, r, s, tx } = await buildPermitTx(deadline);
        const receipt = await (await tx).wait();
        const event = receipt.events[0];

        // Check that approval was successful
        assert.equal(event.event, "Approval");
        assert.equal(await debtTokenTester.nonces(approve.owner.address), 1);
        assert.equal(
          await debtTokenTester.allowance(approve.owner.address, approve.spender.address),
          approve.value,
        );

        // Check that we can not use re-use the same signature, since the user's nonce has been incremented (replay protection)
        await assertRevert(
          debtTokenTester.permit(
            approve.owner.address,
            approve.spender.address,
            approve.value,
            deadline,
            v,
            r,
            s,
          ),
          "EIP2612: invalid signature",
        );

        // Check that the zero address fails
        await assertRevert(
          debtTokenTester.permit(
            "0x0000000000000000000000000000000000000000",
            approve.spender.address,
            approve.value,
            deadline,
            "0x99",
            r,
            s,
          ),
          "EIP712: invalid signature",
        );
      });

      it("permits(): fails with expired deadline", async () => {
        const deadline = 1;

        const { v, r, s, tx } = await buildPermitTx(deadline);
        await assertRevert(tx, "EIP2612: expired deadline");
      });

      it("permits(): fails with the wrong signature", async () => {
        const deadline = 100000000000000;

        const { v, r, s } = await buildPermitTx(deadline);

        const tx = debtTokenTester.permit(
          carol.address,
          approve.spender.address,
          approve.value,
          deadline,
          v,
          hexlify(r),
          hexlify(s),
        );

        await assertRevert(tx, "EIP2612: invalid signature");
      });
    }
  };
  describe("Basic token functions, without Proxy", async () => {
    testCorpus({ withProxy: false });
  });

  describe("Basic token functions, with Proxy", async () => {
    testCorpus({ withProxy: true });
  });
});

contract("Reset chain state", async () => {});
