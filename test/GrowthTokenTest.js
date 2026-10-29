const deploymentHelper = require("../utils/testDeploymentHelpers.js");
const testHelpers = require("../utils/testHelpers.js");
const { accountsList } = require("../accountsList.js");

const { keccak256 } = require("@ethersproject/keccak256");
const { defaultAbiCoder } = require("@ethersproject/abi");
const { toUtf8Bytes } = require("@ethersproject/strings");
const { pack } = require("@ethersproject/solidity");
const { hexlify, hexZeroPad } = require("@ethersproject/bytes");
const { ecsign } = require("ethereumjs-util");

const th = testHelpers.TestHelper;
const toBN = th.toBN;
const dec = th.dec;

const ZERO_ADDRESS = th.ZERO_ADDRESS;
const assertRevert = th.assertRevert;

contract("ProtocolToken", async () => {
  let signers;
  let owner, A, B, C, D;
  let lpRewardsAddress, multisig;
  let approve;

  const ownerPrivateKey = accountsList[0].privateKey;

  let protocolTokenTester;
  let protocolTokenStaking;

  let tokenName;
  let tokenVersion;
  let chainId;

  const sign = (digest, privateKey) => {
    return ecsign(Buffer.from(digest.slice(2), "hex"), Buffer.from(privateKey.slice(2), "hex"));
  };

  const PERMIT_TYPEHASH = keccak256(
    toUtf8Bytes(
      "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)",
    ),
  );
  const SECP256K1_N = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
  const SECP256K1_HALF_N = "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0";

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

  const mintToABC = async () => {
    // mint some tokens
    await protocolTokenTester.unprotectedMint(A.address, dec(150, 18));
    await protocolTokenTester.unprotectedMint(B.address, dec(100, 18));
    await protocolTokenTester.unprotectedMint(C.address, dec(50, 18));
  };

  const buildPermitSignature = async (deadline) => {
    const nonce = (await protocolTokenTester.nonces(approve.owner.address)).toString();

    // Get the EIP712 digest
    const digest = getPermitDigest(
      tokenName,
      protocolTokenTester.address,
      chainId,
      tokenVersion,
      approve.owner.address,
      approve.spender.address,
      approve.value,
      nonce,
      deadline,
    );

    const { v, r, s } = sign(digest, ownerPrivateKey);

    return { v, r, s };
  };

  const buildPermitTx = async (deadline) => {
    const { v, r, s } = await buildPermitSignature(deadline);

    const tx = protocolTokenTester.permit(
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

  before(async () => {
    signers = await ethers.getSigners();

    owner = signers.shift();
    [lpRewardsAddress, multisig] = signers.slice(998, 1000);

    await hre.network.provider.send("hardhat_reset");

    const transactionCount = await owner.getTransactionCount();
    const cpContracts = await deploymentHelper.computeCoreProtocolContracts(
      owner.address,
      transactionCount + 1,
    );

    await deploymentHelper.deployProtocolCore(th.GAS_COMPENSATION, th.MIN_NET_DEBT, cpContracts);
    const protocolTokenContracts = await deploymentHelper.deployProtocolTokenTesterContracts(
      owner.address,
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
    protocolTokenTester = protocolTokenContracts.protocolToken;

    tokenName = await protocolTokenTester.name();
    tokenVersion = await protocolTokenTester.version();
    chainId = await protocolTokenTester.getChainId();
  });

  beforeEach(async () => {
    [A, B, C, D] = signers.splice(0, 4);

    approve = {
      owner,
      spender: A,
      value: 1,
    };
  });

  it("totalSupply(): gets the total supply", async () => {
    const total = (await protocolTokenTester.totalSupply()).toString();

    assert.equal(total, dec(100, 24));
  });

  it("balanceOf(): gets the balance of the account", async () => {
    await mintToABC();

    const A_Balance = await protocolTokenTester.balanceOf(A.address);
    const B_Balance = await protocolTokenTester.balanceOf(B.address);
    const C_Balance = await protocolTokenTester.balanceOf(C.address);

    assert.equal(A_Balance, dec(150, 18));
    assert.equal(B_Balance, dec(100, 18));
    assert.equal(C_Balance, dec(50, 18));
  });

  it("name(): returns the token's name", async () => {
    const name = await protocolTokenTester.name();
    assert.equal(name, "SFC");
  });

  it("symbol(): returns the token's symbol", async () => {
    const symbol = await protocolTokenTester.symbol();
    assert.equal(symbol, "SFC");
  });

  it("version(): returns the token contract's version", async () => {
    const version = await protocolTokenTester.version();
    assert.equal(version, "1");
  });

  it("decimal(): returns the number of decimal digits used", async () => {
    const decimals = await protocolTokenTester.decimals();
    assert.equal(decimals, "18");
  });

  it("allowance(): returns an account's spending allowance for another account's balance", async () => {
    await mintToABC();

    await protocolTokenTester.connect(B).approve(A.address, dec(100, 18));

    const allowance_A = await protocolTokenTester.allowance(B.address, A.address);
    const allowance_D = await protocolTokenTester.allowance(B.address, D.address);

    assert.equal(allowance_A, dec(100, 18));
    assert.equal(allowance_D, "0");
  });

  it("approve(): approves an account to spend the specified ammount", async () => {
    await mintToABC();

    const allowance_A_before = await protocolTokenTester.allowance(B.address, A.address);
    assert.equal(allowance_A_before, "0");

    await protocolTokenTester.connect(B).approve(A.address, dec(100, 18));

    const allowance_A_after = await protocolTokenTester.allowance(B.address, A.address);
    assert.equal(allowance_A_after, dec(100, 18));
  });

  it("approve(): reverts when spender param is address(0)", async () => {
    await mintToABC();

    const txPromise = protocolTokenTester.connect(B).approve(ZERO_ADDRESS, dec(100, 18));
    await assertRevert(txPromise);
  });

  it("approve(): reverts when owner param is address(0)", async () => {
    await mintToABC();

    const txPromise = protocolTokenTester
      .connect(B)
      .callInternalApprove(ZERO_ADDRESS, A.address, dec(100, 18));
    await assertRevert(txPromise);
  });

  it("transferFrom(): successfully transfers from an account which it is approved to transfer from", async () => {
    await mintToABC();

    const allowance_A_0 = await protocolTokenTester.allowance(B.address, A.address);
    assert.equal(allowance_A_0, "0");

    await protocolTokenTester.connect(B).approve(A.address, dec(50, 18));

    // Check A's allowance of B's funds has increased
    const allowance_A_1 = await protocolTokenTester.allowance(B.address, A.address);
    assert.equal(allowance_A_1, dec(50, 18));

    assert.equal(await protocolTokenTester.balanceOf(C.address), dec(50, 18));

    // A transfers from B to C, using up her allowance
    await protocolTokenTester.connect(A).transferFrom(B.address, C.address, dec(50, 18));
    assert.equal(await protocolTokenTester.balanceOf(C.address), dec(100, 18));

    // Check A's allowance of B's funds has decreased
    const allowance_A_2 = await protocolTokenTester.allowance(B.address, A.address);
    assert.equal(allowance_A_2, "0");

    // Check B's balance has decreased
    assert.equal(await protocolTokenTester.balanceOf(B.address), dec(50, 18));

    // A tries to transfer more tokens from B's account to C than she's allowed
    const txPromise = protocolTokenTester
      .connect(A)
      .transferFrom(B.address, C.address, dec(50, 18));
    await assertRevert(txPromise);
  });

  it("transfer(): increases the recipient's balance by the correct amount", async () => {
    await mintToABC();

    assert.equal(await protocolTokenTester.balanceOf(A.address), dec(150, 18));

    await protocolTokenTester.connect(B).transfer(A.address, dec(37, 18));

    assert.equal(await protocolTokenTester.balanceOf(A.address), dec(187, 18));
  });

  it("transfer(): reverts when amount exceeds sender's balance", async () => {
    await mintToABC();

    assert.equal(await protocolTokenTester.balanceOf(B.address), dec(100, 18));

    const txPromise = protocolTokenTester.connect(B).transfer(A.address, dec(101, 18));
    await assertRevert(txPromise);
  });

  it("transfer(): transfer to a blacklisted address reverts", async () => {
    await mintToABC();

    await assertRevert(protocolTokenTester.connect(A).transfer(protocolTokenTester.address, 1));
    await assertRevert(protocolTokenTester.connect(A).transfer(ZERO_ADDRESS, 1));
    await assertRevert(protocolTokenTester.connect(A).transfer(protocolTokenStaking.address, 1));
  });

  it("transfer(): transfer to or from the zero-address reverts", async () => {
    await mintToABC();

    const txPromiseFromZero = protocolTokenTester
      .connect(B)
      .callInternalTransfer(ZERO_ADDRESS, A.address, dec(100, 18));
    const txPromiseToZero = protocolTokenTester
      .connect(B)
      .callInternalTransfer(A.address, ZERO_ADDRESS, dec(100, 18));
    await assertRevert(txPromiseFromZero);
    await assertRevert(txPromiseToZero);
  });

  it("mint(): issues correct amount of tokens to the given address", async () => {
    const A_balanceBefore = await protocolTokenTester.balanceOf(A.address);
    assert.equal(A_balanceBefore, "0");

    await protocolTokenTester.unprotectedMint(A.address, dec(100, 18));

    const A_BalanceAfter = await protocolTokenTester.balanceOf(A.address);
    assert.equal(A_BalanceAfter, dec(100, 18));
  });

  it("mint(): reverts when beneficiary is address(0)", async () => {
    const tx = protocolTokenTester.unprotectedMint(ZERO_ADDRESS, 100);
    await assertRevert(tx);
  });

  it("sendToProtocolTokenStaking(): changes balances of ProtocolTokenStaking and calling account by the correct amounts", async () => {
    // mint some tokens to A
    await protocolTokenTester.unprotectedMint(A.address, dec(150, 18));

    // Check caller and ProtocolTokenStaking balance before
    const A_BalanceBefore = await protocolTokenTester.balanceOf(A.address);
    assert.equal(A_BalanceBefore, dec(150, 18));
    const protocolTokenStakingBalanceBefore = await protocolTokenTester.balanceOf(
      protocolTokenStaking.address,
    );
    assert.equal(protocolTokenStakingBalanceBefore, "0");

    await protocolTokenTester.unprotectedSendToProtocolTokenStaking(A.address, dec(37, 18));

    // Check caller and ProtocolTokenStaking balance before
    const A_BalanceAfter = await protocolTokenTester.balanceOf(A.address);
    assert.equal(A_BalanceAfter, dec(113, 18));
    const protocolTokenStakingBalanceAfter = await protocolTokenTester.balanceOf(
      protocolTokenStaking.address,
    );
    assert.equal(protocolTokenStakingBalanceAfter, dec(37, 18));
  });

  // EIP2612 tests

  it("Initializes PERMIT_TYPEHASH correctly", async () => {
    assert.equal(await protocolTokenTester.permitTypeHash(), PERMIT_TYPEHASH);
  });

  it("Initializes DOMAIN_SEPARATOR correctly", async () => {
    assert.equal(
      await protocolTokenTester.domainSeparator(),
      getDomainSeparator(tokenName, protocolTokenTester.address, chainId, tokenVersion),
    );
  });

  it("Initial nonce for a given address is 0", async function () {
    assert.equal(toBN(await protocolTokenTester.nonces(A.address)).toString(), "0");
  });

  it("permit(): permits and emits an Approval event (replay protected)", async () => {
    const deadline = 100000000000000;

    // Approve it
    const { v, r, s, tx } = await buildPermitTx(deadline);
    const receipt = await (await tx).wait();
    const event = receipt.events[0];

    // Check that approval was successful
    assert.equal(event.event, "Approval");
    assert.equal(await protocolTokenTester.nonces(approve.owner.address), 1);
    assert.equal(
      await protocolTokenTester.allowance(approve.owner.address, approve.spender.address),
      approve.value,
    );

    // Check that we can not use re-use the same signature, since the user's nonce has been incremented (replay protection)
    await assertRevert(
      protocolTokenTester.permit(
        approve.owner.address,
        approve.spender.address,
        approve.value,
        deadline,
        v,
        r,
        s,
      ),
      "ProtocolToken: invalid signature",
    );

    // Check that the zero address fails
    await assertRevert(
      protocolTokenTester.permit(
        "0x0000000000000000000000000000000000000000",
        approve.spender.address,
        approve.value,
        deadline,
        v,
        r,
        s,
      ),
      "ProtocolToken: invalid signature",
    );
  });

  it("permit(): rejects malleable high-s signatures", async () => {
    const deadline = 100000000000000;
    const nonceBefore = await protocolTokenTester.nonces(approve.owner.address);
    const allowanceBefore = await protocolTokenTester.allowance(
      approve.owner.address,
      approve.spender.address,
    );
    const { v, r, s } = await buildPermitSignature(deadline);
    const lowS = ethers.BigNumber.from(hexlify(s));
    const highS = ethers.BigNumber.from(SECP256K1_N).sub(lowS);
    const highV = v === 27 ? 28 : 27;

    assert.isTrue(lowS.lte(ethers.BigNumber.from(SECP256K1_HALF_N)));
    assert.isTrue(highS.gt(ethers.BigNumber.from(SECP256K1_HALF_N)));

    let reverted = false;
    try {
      const tx = await protocolTokenTester.permit(
        approve.owner.address,
        approve.spender.address,
        approve.value,
        deadline,
        highV,
        hexlify(r),
        hexZeroPad(highS.toHexString(), 32),
      );
      await tx.wait();
    } catch (error) {
      reverted = true;
      assert.include(error.message, "ECDSA: invalid signature 's' value");
    }

    assert.isTrue(reverted, "Expected the high-s signature to be rejected");
    assert.equal(
      (await protocolTokenTester.nonces(approve.owner.address)).toString(),
      nonceBefore.toString(),
    );
    assert.equal(
      (
        await protocolTokenTester.allowance(approve.owner.address, approve.spender.address)
      ).toString(),
      allowanceBefore.toString(),
    );
  });

  it("permit(): fails with expired deadline", async () => {
    const deadline = 1;

    const { v, r, s, tx } = await buildPermitTx(deadline);
    await assertRevert(tx, "ProtocolToken: expired deadline");
  });

  it("permit(): fails with the wrong signature", async () => {
    const deadline = 100000000000000;

    const { v, r, s } = await buildPermitSignature(deadline);

    const tx = protocolTokenTester.permit(
      C.address,
      approve.spender.address,
      approve.value, // Carol is passed as spender param, rather than Bob
      deadline,
      v,
      hexlify(r),
      hexlify(s),
    );

    await assertRevert(tx, "ProtocolToken: invalid signature");
  });
});
