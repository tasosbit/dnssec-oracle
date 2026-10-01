import { Application, assert, bytes, Contract, GlobalState, readonly, uint64 } from '@algorandfoundation/algorand-typescript'
import { abiCall, abimethod } from '@algorandfoundation/algorand-typescript/arc4'
import type { DnssecOracle } from '../dnssec_oracle/contract.algo'
import { attestationHasRecord, attestationUsable, readAttestation, txtRdata } from '../dnssec_oracle/reader.algo'

/**
 * Example consumer: reads the oracle's attestation boxes directly, through the reference reader
 * (`hasTxt`), or asks the oracle's `hasRecord` by inner call (`hasTxtByCall`).
 */
export class AttestationConsumer extends Contract {
  /** The oracle, pinned at create: an app the caller names could hold forged boxes. */
  oracle = GlobalState<Application>({ key: 'oracle' })

  @abimethod({ onCreate: 'require' })
  public createApplication(oracle: Application): void {
    this.oracle.value = oracle
  }

  /**
   * Whether `name` (wire format) has a usable TXT record holding exactly `text`.
   * @param maxAge Oldest acceptable inception, in seconds before now
   * @param minKeyBits Weakest acceptable key on the chain
   * @param zones The signer's zone up to the TLD (wire format), for the chain walk
   */
  @readonly
  public hasTxt(name: bytes, text: bytes, maxAge: uint64, minKeyBits: uint64, zones: bytes[]): boolean {
    assert(text.length <= 255, 'text over 255 bytes')
    const oracle = this.oracle.value
    const [value, exists] = readAttestation(oracle, name)
    return exists && attestationUsable(oracle, value, maxAge, minKeyBits, zones) && attestationHasRecord(value, txtRdata(text))
  }

  /**
   * `hasTxt` through the oracle's `hasRecord`, which walks the chain itself. Same box
   * references, plus one inner call's fee. The pin still matters: an app the caller names
   * could return anything.
   */
  @readonly
  public hasTxtByCall(name: bytes, text: bytes, maxAge: uint64, minKeyBits: uint64, zones: bytes[]): boolean {
    assert(text.length <= 255, 'text over 255 bytes')
    return abiCall<typeof DnssecOracle.prototype.hasRecord>({
      appId: this.oracle.value,
      args: [name, txtRdata(text), maxAge, minKeyBits, zones],
    }).returnValue
  }
}
