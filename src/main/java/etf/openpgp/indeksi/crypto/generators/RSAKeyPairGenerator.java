package etf.openpgp.indeksi.crypto.generators;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Date;

public class RSAKeyPairGenerator implements KeyPairGenerator {

    @Override
    public PGPKeyPair generateSignKeyPair(int keySize) {
        try {
            KeyPair keyPair = generateKeyPair(keySize);
            return keyPair != null ? new PGPKeyPair(PGPPublicKey.RSA_SIGN, keyPair, new Date(), "BC") : null;
        } catch (PGPException | NoSuchProviderException e) {
            return null;
        }
    }

    @Override
    public PGPKeyPair generateEncryptKeyPair(int keySize) {
        try {
            KeyPair keyPair = generateKeyPair(keySize);
            return keyPair != null ? new PGPKeyPair(PGPPublicKey.RSA_ENCRYPT, keyPair, new Date(), "BC") : null;
        } catch (PGPException | NoSuchProviderException e) {
            return null;
        }
    }

    private KeyPair generateKeyPair(int keySize) {
        try {
            java.security.KeyPairGenerator kpg = initialize(keySize);
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            return null;
        }
    }

    private java.security.KeyPairGenerator initialize(int keySize) throws NoSuchProviderException, NoSuchAlgorithmException {
        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(keySize);

        return kpg;
    }
}
