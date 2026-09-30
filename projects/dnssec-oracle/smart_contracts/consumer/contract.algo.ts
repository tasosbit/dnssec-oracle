import { Application, assert, bytes, Contract, GlobalState, readonly, uint64 } from '@algorandfoundation/algorand-typescript'
import { abimethod } from '@algorandfoundation/algorand-typescript/arc4'
import { attestationHasRecord, attestationUsable, readAttestation, txtRdata } from '../dnssec_oracle/reader.algo'

/** Example consumer: reads the oracle's attestation boxes directly, through the reference reader. */
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
   */
  @readonly
  public hasTxt(name: bytes, text: bytes, maxAge: uint64, minKeyBits: uint64): boolean {
    assert(text.length <= 255, 'text over 255 bytes')
    const oracle = this.oracle.value
    const [value, exists] = readAttestation(oracle, name)
    return exists && attestationUsable(oracle, value, maxAge, minKeyBits) && attestationHasRecord(value, txtRdata(text))
  }
}
