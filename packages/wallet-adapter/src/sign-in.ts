import {
  assertOffchainMessageV1Equal,
  getAddressDecoder,
  getOffchainMessageV1Decoder,
  signatureBytes,
  verifyOffchainMessageEnvelope,
  type Address,
  type OffchainMessageBytes,
} from '@solana/kit';
import type {
  SolanaSignInInput,
  SolanaSignInOutput,
} from '@solana/wallet-standard-features';
import {
  deriveSignInMessageText,
  verifySignIn as verifyPlainSignIn,
} from '@solana/wallet-standard-util';

/**
 * Verifies a Sign In With Solana output against the input that produced it, whether the wallet
 * signed the plain message text or wrapped it in a version 1 off-chain message.
 *
 * The signed message must reproduce every field of the input, name the connected account, and
 * carry a valid signature from that account, whose `address` must be the address of its
 * `publicKey`. When `input.address` is set, the wallet must have signed in with that account.
 * Malformed output resolves to `false` rather than throwing.
 */
export async function verifySignIn(
  input: SolanaSignInInput,
  output: SolanaSignInOutput,
): Promise<boolean> {
  // Wallet output is untrusted, so any malformed shape resolves to `false` instead of throwing.
  try {
    const address = getSignInAddress(output);
    if (!address) return false;
    if (input.address && input.address !== address) return false;
    if (output.signedMessageFormat?.kind !== 'offchainMessage') {
      // Bind the signed text to the account whose key produced the signature.
      return verifyPlainSignIn({...input, address}, output);
    }
    if (output.signedMessageFormat.messageVersion !== 1) return false;
    const content = output.signedMessage as unknown as OffchainMessageBytes;
    const message = getOffchainMessageV1Decoder().decode(content);
    const text = deriveSignInMessageText(
      {...input, address},
      {...output, signedMessage: new TextEncoder().encode(message.content)},
    );
    if (!text) return false;
    assertOffchainMessageV1Equal(message, {
      ...message,
      content: text,
      requiredSignatories: [{address}],
    });
    await verifyOffchainMessageEnvelope({
      content,
      signatures: {[address]: signatureBytes(output.signature)},
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Returns the output's account address when the output has the shape of a single ed25519
 * signature over a message by that account, and `account.address` is the address of
 * `account.publicKey`; otherwise `null`.
 */
function getSignInAddress(output: SolanaSignInOutput): Address | null {
  const {account, signature, signedMessage} = output;
  if (
    !isBytes(signature, 64) ||
    !isBytes(signedMessage) ||
    !isBytes(account?.publicKey, 32)
  ) {
    return null;
  }
  const address = getAddressDecoder().decode(account.publicKey);
  return account.address === address ? address : null;
}

// Checks the tag rather than `instanceof` so byte arrays from another realm (an iframe or an
// extension context) still count.
function isBytes(value: unknown, length?: number): value is Uint8Array {
  return (
    Object.prototype.toString.call(value) === '[object Uint8Array]' &&
    (length === undefined || (value as Uint8Array).length === length)
  );
}
