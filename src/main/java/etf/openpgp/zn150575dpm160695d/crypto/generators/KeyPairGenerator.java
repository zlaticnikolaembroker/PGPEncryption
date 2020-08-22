package etf.openpgp.zn150575dpm160695d.crypto.generators;

import org.bouncycastle.openpgp.PGPKeyPair;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public interface KeyPairGenerator {

    PGPKeyPair generateSignKeyPair(int keySize) throws NoSuchProviderException, NoSuchAlgorithmException;
    PGPKeyPair generateEncryptKeyPair(int keySize);

}
