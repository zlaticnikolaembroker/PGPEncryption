package etf.openpgp.indeksi.crypto.generators;

import org.bouncycastle.openpgp.PGPKeyPair;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public interface KeyPairGenerator {

    PGPKeyPair generateSignKeyPair(int keySize) throws NoSuchProviderException, NoSuchAlgorithmException;
    PGPKeyPair generateEncryptKeyPair(int keySize);

}
