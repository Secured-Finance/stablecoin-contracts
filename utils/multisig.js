const { default: SafeApiKit } = require("@safe-global/api-kit");
const { default: Safe } = require("@safe-global/protocol-kit");
const { utils } = require("ethers");

const PRIVATE_CONSTRUCTOR_SYMBOL = Symbol("private");

class MultisigProposal {
  #safeAddress;
  #txServiceUrl;
  #signer;
  #safeService;
  #safeSdk;
  #safeTransactions;

  constructor(symbol) {
    // Prevents outside initialization to ensure the class is always initialized via the static create method
    if (symbol !== PRIVATE_CONSTRUCTOR_SYMBOL) {
      throw new Error("Not allowed to initialize from outside");
    }
  }

  static async create(adapter, safeAddress) {
    const proposal = new MultisigProposal(PRIVATE_CONSTRUCTOR_SYMBOL);
    await proposal.#init(adapter, safeAddress);
    return proposal;
  }

  async #init(adapter, safeAddress) {
    if (!process.env.SAFE_API_URL) {
      throw Error("SAFE_API_URL is not set");
    }

    const signer = await adapter.getSignerAddress();
    if (!signer) {
      throw Error("Signer address is not found");
    }

    this.#safeAddress = safeAddress;
    this.#txServiceUrl = process.env.SAFE_API_URL;
    this.#signer = signer;
    this.#safeService = new SafeApiKit({
      ethAdapter: adapter,
      txServiceUrl: this.#txServiceUrl,
    });

    this.#safeSdk = await Safe.create({
      ethAdapter: adapter,
      safeAddress: this.#safeAddress,
    });
    this.#safeTransactions = [];
  }

  async add(to, data) {
    this.#safeTransactions.push({
      to,
      data,
      value: "0",
      operation: 0, // Call operation
    });
  }

  async submit() {
    if (this.#safeTransactions.length === 0) {
      console.warn("Skipped proposal submission due to no update");
      return;
    }

    const safeTransaction = await this.#safeSdk.createTransaction({
      safeTransactionData: this.#safeTransactions,
      onlyCalls: true,
    });

    const safeTxHash = await this.#safeSdk.getTransactionHash(safeTransaction);
    const senderSignature = await this.#safeSdk.signTransactionHash(safeTxHash);

    await this.#safeService.proposeTransaction({
      safeAddress: this.#safeAddress,
      safeTransactionData: safeTransaction.data,
      safeTxHash,
      senderAddress: utils.getAddress(this.#signer),
      senderSignature: senderSignature.data,
    });

    const tx = await this.#safeService.getTransaction(safeTxHash);

    console.log(`Submitted proposals at ${tx.safeTxHash}`);
  }
}

module.exports = { MultisigProposal };
