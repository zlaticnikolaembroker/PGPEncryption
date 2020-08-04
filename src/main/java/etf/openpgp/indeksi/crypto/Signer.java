package etf.openpgp.indeksi.crypto;

import etf.openpgp.indeksi.crypto.models.Key;
import etf.openpgp.indeksi.front.InfoScreen;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.Iterator;

public class Signer {

    private static final int BUFFER_SIZE = 1 << 16;

    private final KeyRings keyRings;

    public Signer(KeyRings keyRings) {
        this.keyRings = keyRings;
    }

    public void signFile(OutputStream out, String filePath, Key signingKey, String passphrase, boolean radix64) throws PGPException,
            NoSuchProviderException, NoSuchAlgorithmException, IOException, SignatureException {
        if (radix64) {
            out = new ArmoredOutputStream(out);
        }

        PGPSecretKey secretKey = keyRings.getSigningKey(signingKey.getUserId(), signingKey.getKeyId());
        PBESecretKeyDecryptor secretKeyDecryptor = new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase.toCharArray());
        PGPPrivateKey privateKey = secretKey.extractPrivateKey(secretKeyDecryptor);
        PGPSignatureGenerator pgpSignatureGenerator = new PGPSignatureGenerator(secretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1, "BC");
        pgpSignatureGenerator.initSign(PGPSignature.BINARY_DOCUMENT, privateKey);
        Iterator<String> userIDs = secretKey.getPublicKey().getUserIDs();
        if (userIDs.hasNext()) {
            PGPSignatureSubpacketGenerator signatureSubpacketGenerator = new PGPSignatureSubpacketGenerator();
            signatureSubpacketGenerator.setSignerUserID(false, userIDs.next());
            pgpSignatureGenerator.setHashedSubpackets(signatureSubpacketGenerator.generate());
        }

        BCPGOutputStream bcpgOutputStream = new BCPGOutputStream(out);
        FileInputStream fileInputStream = new FileInputStream(filePath);
        int len;
        byte[] buffer = new byte[BUFFER_SIZE];
        while ((len = fileInputStream.read(buffer)) > 0) {
            pgpSignatureGenerator.update(buffer, 0, len);
        }

        PGPSignature signature = pgpSignatureGenerator.generate();
        signature.encode(bcpgOutputStream);
        bcpgOutputStream.close();
        out.close();
        InfoScreen successScreen = new InfoScreen("File successfully sygned", "File successfully sygned");
        successScreen.showAndWait();
    }

}
