const deploymentHelper = require("../utils/deploymentHelpers.js");
const testHelpers = require("../utils/testHelpers.js");

const { keccak256 } = require("@ethersproject/keccak256");
const { defaultAbiCoder } = require("@ethersproject/abi");
const { toUtf8Bytes } = require("@ethersproject/strings");
const { pack } = require("@ethersproject/solidity");
const { hexlify } = require("@ethersproject/bytes");
const { ecsign } = require("ethereumjs-util");

// the second account our hardhatenv creates (for EOA A) from `hardhatAccountsList2k.js`

const th = testHelpers.TestHelper;
const toBN = th.toBN;
const dec = th.dec;
const getDifference = th.getDifference;
const timeValues = testHelpers.TimeValues;

const ZERO_ADDRESS = th.ZERO_ADDRESS;
const assertRevert = th.assertRevert;

contract("ProtocolToken", async (accounts) => {
  const [owner, A, B, C, D] = accounts;

  const [bountyAddress, lpRewardsAddress, multisig] = accounts.slice(997, 1000);

  // Create the approval tx data, for use in permit()
  const approve = {
    owner: A,
    spender: B,
    value: 1,
  };

  const A_PrivateKey = "0xeaa445c85f7b438dEd6e831d06a4eD0CEBDc2f8527f84Fcda6EBB5fCfAd4C0e9";

  let contracts;
  let protocolTokenTester;
  let protocolTokenStaking;
  let communityIssuance;

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
    await protocolTokenTester.unprotectedMint(A, dec(150, 18));
    await protocolTokenTester.unprotectedMint(B, dec(100, 18));
    await protocolTokenTester.unprotectedMint(C, dec(50, 18));
  };

  const buildPermitTx = async (deadline) => {
    const nonce = (await protocolTokenTester.nonces(approve.owner)).toString();

    // Get the EIP712 digest
    const digest = getPermitDigest(
      tokenName,
      protocolTokenTester.address,
      chainId,
      tokenVersion,
      approve.owner,
      approve.spender,
      approve.value,
      nonce,
      deadline,
    );

    const { v, r, s } = sign(digest, A_PrivateKey);

    const tx = protocolTokenTester.permit(
      approve.owner,
      approve.spender,
      approve.value,
      deadline,
      v,
      hexlify(r),
      hexlify(s),
    );

    return { v, r, s, tx };
  };

  beforeEach(async () => {
    contracts = await deploymentHelper.deployProtocolCore(th.GAS_COMPENSATION, th.MIN_NET_DEBT);
    const protocolTokenContracts = await deploymentHelper.deployProtocolTokenTesterContractsHardhat(
      bountyAddress,
      lpRewardsAddress,
      multisig,
    );

    protocolTokenStaking = protocolTokenContracts.protocolTokenStaking;
    protocolTokenTester = protocolTokenContracts.protocolToken;
    communityIssuance = protocolTokenContracts.communityIssuance;

    tokenName = await protocolTokenTester.name();
    tokenVersion = await protocolTokenTester.version();
    chainId = await protocolTokenTester.getChainId();

    await deploymentHelper.connectProtocolTokenContracts(protocolTokenContracts);
    await deploymentHelper.connectCoreContracts(contracts, protocolTokenContracts);
    await deploymentHelper.connectProtocolTokenContractsToCore(protocolTokenContracts, contracts);
  });

  it("balanceOf(): gets the balance of the account", async () => {
    await mintToABC();

    const A_Balance = await protocolTokenTester.balanceOf(A);
    const B_Balance = await protocolTokenTester.balanceOf(B);
    const C_Balance = await protocolTokenTester.balanceOf(C);

    assert.equal(A_Balance, dec(150, 18));
    assert.equal(B_Balance, dec(100, 18));
    assert.equal(C_Balance, dec(50, 18));
  });

  it("totalSupply(): gets the total supply", async () => {
    const total = (await protocolTokenTester.totalSupply()).toString();

    assert.equal(total, dec(100, 24));
  });

  it("name(): returns the token's name", async () => {
    const name = await protocolTokenTester.name();
    assert.equal(name, "SCR");
  });

  it("symbol(): returns the token's symbol", async () => {
    const symbol = await protocolTokenTester.symbol();
    assert.equal(symbol, "SCR");
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

    await protocolTokenTester.approve(A, dec(100, 18), { from: B });

    const allowance_A = await protocolTokenTester.allowance(B, A);
    const allowance_D = await protocolTokenTester.allowance(B, D);

    assert.equal(allowance_A, dec(100, 18));
    assert.equal(allowance_D, "0");
  });

  it("approve(): approves an account to spend the specified ammount", async () => {
    await mintToABC();

    const allowance_A_before = await protocolTokenTester.allowance(B, A);
    assert.equal(allowance_A_before, "0");

    await protocolTokenTester.approve(A, dec(100, 18), { from: B });

    const allowance_A_after = await protocolTokenTester.allowance(B, A);
    assert.equal(allowance_A_after, dec(100, 18));
  });

  it("approve(): reverts when spender param is address(0)", async () => {
    await mintToABC();

    const txPromise = protocolTokenTester.approve(ZERO_ADDRESS, dec(100, 18), { from: B });
    await assertRevert(txPromise);
  });

  it("approve(): reverts when owner param is address(0)", async () => {
    await mintToABC();

    const txPromise = protocolTokenTester.callInternalApprove(ZERO_ADDRESS, A, dec(100, 18), {
      from: B,
    });
    await assertRevert(txPromise);
  });

  it("transferFrom(): successfully transfers from an account which it is approved to transfer from", async () => {
    await mintToABC();

    const allowance_A_0 = await protocolTokenTester.allowance(B, A);
    assert.equal(allowance_A_0, "0");

    await protocolTokenTester.approve(A, dec(50, 18), { from: B });

    // Check A's allowance of B's funds has increased
    const allowance_A_1 = await protocolTokenTester.allowance(B, A);
    assert.equal(allowance_A_1, dec(50, 18));

    assert.equal(await protocolTokenTester.balanceOf(C), dec(50, 18));

    // A transfers from B to C, using up her allowance
    await protocolTokenTester.transferFrom(B, C, dec(50, 18), { from: A });
    assert.equal(await protocolTokenTester.balanceOf(C), dec(100, 18));

    // Check A's allowance of B's funds has decreased
    const allowance_A_2 = await protocolTokenTester.allowance(B, A);
    assert.equal(allowance_A_2, "0");

    // Check B's balance has decreased
    assert.equal(await protocolTokenTester.balanceOf(B), dec(50, 18));

    // A tries to transfer more tokens from B's account to C than she's allowed
    const txPromise = protocolTokenTester.transferFrom(B, C, dec(50, 18), { from: A });
    await assertRevert(txPromise);
  });

  it("transfer(): increases the recipient's balance by the correct amount", async () => {
    await mintToABC();

    assert.equal(await protocolTokenTester.balanceOf(A), dec(150, 18));

    await protocolTokenTester.transfer(A, dec(37, 18), { from: B });

    assert.equal(await protocolTokenTester.balanceOf(A), dec(187, 18));
  });

  it("transfer(): reverts when amount exceeds sender's balance", async () => {
    await mintToABC();

    assert.equal(await protocolTokenTester.balanceOf(B), dec(100, 18));

    const txPromise = protocolTokenTester.transfer(A, dec(101, 18), { from: B });
    await assertRevert(txPromise);
  });

  it("transfer(): transfer to a blacklisted address reverts", async () => {
    await mintToABC();

    await assertRevert(protocolTokenTester.transfer(protocolTokenTester.address, 1, { from: A }));
    await assertRevert(protocolTokenTester.transfer(ZERO_ADDRESS, 1, { from: A }));
    await assertRevert(protocolTokenTester.transfer(communityIssuance.address, 1, { from: A }));
    await assertRevert(protocolTokenTester.transfer(protocolTokenStaking.address, 1, { from: A }));
  });

  it("transfer(): transfer to or from the zero-address reverts", async () => {
    await mintToABC();

    const txPromiseFromZero = protocolTokenTester.callInternalTransfer(
      ZERO_ADDRESS,
      A,
      dec(100, 18),
      {
        from: B,
      },
    );
    const txPromiseToZero = protocolTokenTester.callInternalTransfer(
      A,
      ZERO_ADDRESS,
      dec(100, 18),
      {
        from: B,
      },
    );
    await assertRevert(txPromiseFromZero);
    await assertRevert(txPromiseToZero);
  });

  it("mint(): issues correct amount of tokens to the given address", async () => {
    const A_balanceBefore = await protocolTokenTester.balanceOf(A);
    assert.equal(A_balanceBefore, "0");

    await protocolTokenTester.unprotectedMint(A, dec(100, 18));

    const A_BalanceAfter = await protocolTokenTester.balanceOf(A);
    assert.equal(A_BalanceAfter, dec(100, 18));
  });

  it("mint(): reverts when beneficiary is address(0)", async () => {
    const tx = protocolTokenTester.unprotectedMint(ZERO_ADDRESS, 100);
    await assertRevert(tx);
  });

  it("increaseAllowance(): increases an account's allowance by the correct amount", async () => {
    const allowance_A_Before = await protocolTokenTester.allowance(B, A);
    assert.equal(allowance_A_Before, "0");

    await protocolTokenTester.increaseAllowance(A, dec(100, 18), { from: B });

    const allowance_A_After = await protocolTokenTester.allowance(B, A);
    assert.equal(allowance_A_After, dec(100, 18));
  });

  it("decreaseAllowance(): decreases an account's allowance by the correct amount", async () => {
    await protocolTokenTester.increaseAllowance(A, dec(100, 18), { from: B });

    const A_allowance = await protocolTokenTester.allowance(B, A);
    assert.equal(A_allowance, dec(100, 18));

    await protocolTokenTester.decreaseAllowance(A, dec(100, 18), { from: B });

    const A_allowanceAfterDecrease = await protocolTokenTester.allowance(B, A);
    assert.equal(A_allowanceAfterDecrease, "0");
  });

  it("sendToProtocolTokenStaking(): changes balances of ProtocolTokenStaking and calling account by the correct amounts", async () => {
    // mint some tokens to A
    await protocolTokenTester.unprotectedMint(A, dec(150, 18));

    // Check caller and ProtocolTokenStaking balance before
    const A_BalanceBefore = await protocolTokenTester.balanceOf(A);
    assert.equal(A_BalanceBefore, dec(150, 18));
    const protocolTokenStakingBalanceBefore = await protocolTokenTester.balanceOf(
      protocolTokenStaking.address,
    );
    assert.equal(protocolTokenStakingBalanceBefore, "0");

    await protocolTokenTester.unprotectedSendToProtocolTokenStaking(A, dec(37, 18));

    // Check caller and ProtocolTokenStaking balance before
    const A_BalanceAfter = await protocolTokenTester.balanceOf(A);
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
    assert.equal(toBN(await protocolTokenTester.nonces(A)).toString(), "0");
  });

  it("permit(): permits and emits an Approval event (replay protected)", async () => {
    const deadline = 100000000000000;

    // Approve it
    const { v, r, s, tx } = await buildPermitTx(deadline);
    const receipt = await tx;
    const event = receipt.logs[0];

    // Check that approval was successful
    assert.equal(event.event, "Approval");
    assert.equal(await protocolTokenTester.nonces(approve.owner), 1);
    assert.equal(
      await protocolTokenTester.allowance(approve.owner, approve.spender),
      approve.value,
    );

    // Check that we can not use re-use the same signature, since the user's nonce has been incremented (replay protection)
    await assertRevert(
      protocolTokenTester.permit(approve.owner, approve.spender, approve.value, deadline, v, r, s),
      "ProtocolToken: invalid signature",
    );

    // Check that the zero address fails
    await assertRevert(
      protocolTokenTester.permit(
        "0x0000000000000000000000000000000000000000",
        approve.spender,
        approve.value,
        deadline,
        "0x99",
        r,
        s,
      ),
      "ProtocolToken: invalid signature",
    );
  });

  it("permit(): fails with expired deadline", async () => {
    const deadline = 1;

    const { v, r, s, tx } = await buildPermitTx(deadline);
    await assertRevert(tx, "ProtocolToken: expired deadline");
  });

  it("permit(): fails with the wrong signature", async () => {
    const deadline = 100000000000000;

    const { v, r, s } = await buildPermitTx(deadline);

    const tx = protocolTokenTester.permit(
      C,
      approve.spender,
      approve.value, // Carol is passed as spender param, rather than Bob
      deadline,
      v,
      hexlify(r),
      hexlify(s),
    );

    await assertRevert(tx, "ProtocolToken: invalid signature");
  });
});
