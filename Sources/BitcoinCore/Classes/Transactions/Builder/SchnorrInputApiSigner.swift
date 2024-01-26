import Foundation
import HdWalletKit
import HsCryptoKit
import HsExtensions

class SchnorrInputApiSigner {
    enum SignError: Error {
        case noPreviousOutput
        case noPreviousOutputAddress
        case unMatchedSigner
    }


    let signer : ISigner

    init( signer : ISigner ) {
        self.signer = signer
    }
}

extension SchnorrInputApiSigner: IInputSigner {
    func sigScriptData(transaction: Transaction, inputsToSign: [InputToSign], outputs: [Output], index: Int) throws -> [Data] {
        let input = inputsToSign[index]
        let pubKey = input.previousOutputPublicKey


        let signer = self.signer
        if signer.publicKey != pubKey.raw  {
            throw SignError.unMatchedSigner
        }

        let serializedTransaction = try TransactionSerializer.serializedForTaprootSignature(transaction: transaction, inputsToSign: inputsToSign, outputs: outputs, inputIndex: index)

        let signatureHash = try SchnorrHelper.hashTweak(data: serializedTransaction, tag: "TapSighash")
//        let signature = try SchnorrHelper.sign(data: signatureHash, privateKey: privateKeyData, publicKey: pubKey.raw)
        let signature = try signer.schnorrSign(message: signatureHash, publicKey: pubKey.raw)

        return [signature]
    }
}
