import { compile, Contract, itxn, OnCompleteAction, uint64 } from '@algorandfoundation/algorand-typescript'
import { abimethod } from '@algorandfoundation/algorand-typescript/arc4'
import { MbrManager } from '@d13co/puya-ts-utils/mbrManager'

export class EmptyContract extends Contract {}

/**
 * Op-up layer. It sits above the library's MbrManager, which extends Contract directly.
 * The contract never sizes its own budget: the SDK probes by simulation and prepends
 * `increaseBudget(n)` when a group is short.
 */
export abstract class BaseContract extends MbrManager {
  /**
   * Buy 700 opcodes per inner call with `itxns` no-op inner app calls.
   * @param itxns Number of no-op itxns to perform
   */
  @abimethod({ validateEncoding: 'unsafe-disabled' })
  public increaseBudget(itxns: uint64) {
    const empty = compile(EmptyContract)
    for (let i: uint64 = 0; i < itxns; i++) {
      itxn
        .applicationCall({
          approvalProgram: empty.clearStateProgram, // intentionally the clear state program: a bare "return 1"
          clearStateProgram: empty.clearStateProgram,
          onCompletion: OnCompleteAction.DeleteApplication,
        })
        .submit()
    }
  }
}
