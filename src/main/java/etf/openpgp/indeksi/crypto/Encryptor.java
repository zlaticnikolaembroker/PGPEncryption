package etf.openpgp.indeksi.crypto;

import etf.openpgp.indeksi.crypto.models.Key;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.List;

public class Encryptor {

    private static final int BUFFER_SIZE = 1 << 16; // 64k

    private final KeyRings keyRings;

    public Encryptor(KeyRings keyRings) {
        this.keyRings = keyRings;
    }

    public void encryptFile(OutputStream out, String filePath, List<Key> recipients, Key signingKey,
                            String signPassphrase, boolean integrityCheck) throws IOException, PGPException {
        out = new ArmoredOutputStream(out);
        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(PGPEncryptedData.TRIPLE_DES, integrityCheck, new SecureRandom(), "BC");
        for (Key key : recipients) {
            try {
                PGPPublicKey publicKey = keyRings.getEncryptionKey(key.getUserId(), key.getKeyId());
                if (publicKey != null) {
                    encryptedDataGenerator.addMethod(publicKey);
                }
            } catch (PGPException | NoSuchProviderException e) {
                e.printStackTrace();
            }
        }
        OutputStream encryptedOut = encryptedDataGenerator.open(out, new byte[BUFFER_SIZE]);

        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
        OutputStream compressedOut = compressedDataGenerator.open(encryptedOut);

        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        OutputStream literalOut = literalDataGenerator.open(compressedOut, PGPLiteralDataGenerator.BINARY, filePath, new Date(), new byte[BUFFER_SIZE]);

        FileInputStream fileInputStream = new FileInputStream(filePath);
        byte[] buffer = new byte[BUFFER_SIZE];
        int len;
        while ((len = fileInputStream.read(buffer)) > 0) {
            literalOut.write(buffer, 0, len);
        }
        literalOut.close();
        literalDataGenerator.close();
        compressedOut.close();
        compressedDataGenerator.close();
        encryptedOut.close();
        encryptedDataGenerator.close();
        fileInputStream.close();
        out.close();
    }

}
