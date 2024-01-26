import Foundation
import HdWalletKit
import HsCryptoKit
import HsExtensions

public protocol ISigner {
    func sign( message: Data ) -> Data
    func schnorrSign(message: Data, publicKey: Data) -> Data
    var publicKey : Data { get }
}

class EcdsaInputApiSigner {
    enum SignError: Error {
        case noPreviousOutput
        case noPreviousOutputAddress
        case unMatchedSigner
    }

    let network: INetwork

    let signer: ISigner

    init( signer : ISigner, network: INetwork  ) {
        self.signer = signer
        self.network = network
    }
}

extension EcdsaInputApiSigner: IInputSigner {
    func sigScriptData(transaction: Transaction, inputsToSign: [InputToSign], outputs: [Output], index: Int) throws -> [Data] {
        let input = inputsToSign[index]
        let previousOutput = input.previousOutput
        let pubKey = input.previousOutputPublicKey
        let publicKey = pubKey.raw
        
        let signer = self.signer
        if signer.publicKey != pubKey.raw  {
            throw SignError.unMatchedSigner
        }

        let witness = previousOutput.scriptType == .p2wpkh || previousOutput.scriptType == .p2wpkhSh

        var serializedTransaction = try TransactionSerializer.serializedForSignature(transaction: transaction, inputsToSign: inputsToSign, outputs: outputs, inputIndex: index, forked: witness || network.sigHash.forked)
        serializedTransaction += UInt32(network.sigHash.value)
        let signatureHash = Crypto.doubleSha256(serializedTransaction)

        let signature = signer.sign(message: signatureHash) + Data([network.sigHash.value])

        switch previousOutput.scriptType {
            case .p2pk: return [signature]
            default: return [signature, publicKey]
        }

    }
}
