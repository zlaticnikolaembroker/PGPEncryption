package etf.openpgp.indeksi.crypto;

import etf.openpgp.indeksi.crypto.models.Key;
import etf.openpgp.indeksi.front.InfoScreen;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

public class Encryptor {

    private static final int BUFFER_SIZE = 1 << 16; // 64k

    private final KeyRings keyRings;

    public Encryptor(KeyRings keyRings) {
        this.keyRings = keyRings;
    }

    public void encryptFile(OutputStream out, String filePath, List<Key> recipients, Key signingKey,
                            String signPassphrase, boolean integrityCheck, boolean shouldBeCompressed) throws IOException, PGPException,
            NoSuchProviderException, NoSuchAlgorithmException, SignatureException {
        out = new ArmoredOutputStream(out);
        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(PGPEncryptedData.TRIPLE_DES,
                integrityCheck, new SecureRandom(), "BC");
        for (Key key : recipients) {
            try {
                PGPPublicKey publicKey = keyRings.getEncryptionKey(key.getUserId(), key.getKeyId());
                if (publicKey != null) {
                    encryptedDataGenerator.addMethod(publicKey);
                }
            } catch (PGPException | NoSuchProviderException e) {
                InfoScreen successScreen = new InfoScreen("Something went wrong.", e.getMessage());
                successScreen.showAndWait();
                e.printStackTrace();
            }
        }
        OutputStream encryptedOut = encryptedDataGenerator.open(out, new byte[BUFFER_SIZE]);

        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
        if (shouldBeCompressed) {
            encryptedOut = compressedDataGenerator.open(encryptedOut);    
        }
        

        PGPSignatureGenerator signatureGenerator = null;
        if (signingKey != null) {
            PGPSecretKey secretKey = keyRings.getSigningKey(signingKey.getUserId(), signingKey.getKeyId());
            PBESecretKeyDecryptor keyDecryptor = new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(signPassphrase.toCharArray());
            PGPPrivateKey pgpPrivateKey = secretKey.extractPrivateKey(keyDecryptor);
            signatureGenerator = new PGPSignatureGenerator(secretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1, "BC");
            signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivateKey);
            Iterator<String> userIDs = secretKey.getUserIDs();
            if (userIDs.hasNext()) {
                PGPSignatureSubpacketGenerator signatureSubpacketGenerator = new PGPSignatureSubpacketGenerator();
                signatureSubpacketGenerator.setSignerUserID(false, userIDs.next());
                signatureGenerator.setHashedSubpackets(signatureSubpacketGenerator.generate());
            }
            signatureGenerator.generateOnePassVersion(false).encode(encryptedOut);
        }

        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        OutputStream literalOut = literalDataGenerator.open(encryptedOut, PGPLiteralDataGenerator.BINARY, filePath,
                new Date(), new byte[BUFFER_SIZE]);

        FileInputStream fileInputStream = new FileInputStream(filePath);
        byte[] buffer = new byte[BUFFER_SIZE];
        int len;
        while ((len = fileInputStream.read(buffer)) > 0) {
            literalOut.write(buffer, 0, len);
            if (signatureGenerator != null) {
                signatureGenerator.update(buffer, 0, len);
            }
        }
        literalOut.close();
        literalDataGenerator.close();
        if (signatureGenerator != null) {
            signatureGenerator.generate().encode(encryptedOut);
        }
        compressedDataGenerator.close();
        encryptedOut.close();
        encryptedOut.close();
        encryptedDataGenerator.close();
        fileInputStream.close();
        out.close();
        InfoScreen successScreen = new InfoScreen("File successfully encrypted", "File successfully encrypted");
        successScreen.showAndWait();
    }

}
