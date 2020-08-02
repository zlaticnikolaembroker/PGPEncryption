package etf.openpgp.indeksi.crypto;

import etf.openpgp.indeksi.crypto.generators.KeyPairGenerator;
import etf.openpgp.indeksi.crypto.models.Key;
import etf.openpgp.indeksi.front.SuccessScreen;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

/**
 * Klasa zaduzena za rad sa keyringovima. Sadrzi metode za generisanje novog para kljuceva, uvoz postojeceg kljuca
 * i izvoz kljuceva. Cuva informacije o svim postojecim javnim i tajnim kljucevima.
 *
 * @author Proka
 */
public class KeyRings {

    private static final String SECRET_KEYRING_FILE_LOCATION = "secret.keyring";
    private static final String PUBLIC_KEYRING_FILE_LOCATION = "public.keyring";

    private KeyPairGenerator keyPairGenerator;

    private static final File publicRingFile = new File(PUBLIC_KEYRING_FILE_LOCATION);
    private static final File secretRingFile = new File(SECRET_KEYRING_FILE_LOCATION);

    private static PGPPublicKeyRingCollection publicKeyRings;
    private static PGPSecretKeyRingCollection secretKeyRings;
    

    public KeyRings(KeyPairGenerator keyPairGenerator) {
        if (publicRingFile.exists()) {
            try (InputStream publicIn = new FileInputStream(publicRingFile)) {
                publicKeyRings = new PGPPublicKeyRingCollection(publicIn);
            } catch (IOException | PGPException ex) {
                ex.printStackTrace();
            }
        } else {
            try {
                publicKeyRings = new PGPPublicKeyRingCollection(Collections.EMPTY_LIST);
            } catch (IOException | PGPException ex) {
                ex.printStackTrace();
            }
        }

        if (secretRingFile.exists()) {
            try (InputStream secretIn = new FileInputStream(secretRingFile)) {
                secretKeyRings = new PGPSecretKeyRingCollection(secretIn);
            } catch (IOException | PGPException ex) {
                ex.printStackTrace();
            }
        } else {
            try {
                secretKeyRings = new PGPSecretKeyRingCollection(Collections.EMPTY_LIST);
            } catch (IOException | PGPException ex) {
                ex.printStackTrace();
            }
        }
        this.keyPairGenerator = keyPairGenerator;
    }

    /**
     * Metoda zaduzena za generisanje para kljuceva. Kreira par kljuceva, njihov prsten i dodaje ih u kolekciju prstenova.
     * @param keySizeSign velicina kljuca za potpisivanje
     * @param keySizeEncrypt velicina kljuca za enkripciju
     * @param encryptionAlgorithm algoritam za enkripciju
     * @param userID id korisnika kom pripada par kljuceva
     * @param password lozinka za dekripciju para kljuceva
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws PGPException
     *
     */
    public void generateNewKeyPair(int keySizeSign, int keySizeEncrypt, int encryptionAlgorithm,
                                          String userID, String password) throws PGPException, NoSuchProviderException, NoSuchAlgorithmException {

        // kreiramo par kljuceva za potpisivanje
        PGPKeyPair pgpKeyPairSign = keyPairGenerator.generateSignKeyPair(keySizeSign);

        // kreiramo par kljuceva za enkripciju
        PGPKeyPair pgpKeyPairEncrypt = keyPairGenerator.generateEncryptKeyPair(keySizeEncrypt);

        // kreiramo novi keyring za generisani par

        PGPKeyRingGenerator keyRingGenerator = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION,
                pgpKeyPairSign, userID, encryptionAlgorithm, password.toCharArray(),true, null,
                null, new SecureRandom(), "BC");
        keyRingGenerator.addSubKey(pgpKeyPairEncrypt);

        // dodajemo javni keyring u kolekciju
        publicKeyRings = PGPPublicKeyRingCollection.addPublicKeyRing(publicKeyRings, keyRingGenerator.generatePublicKeyRing());
        // dodajemo tajni keyring u kolekciju
        secretKeyRings = PGPSecretKeyRingCollection.addSecretKeyRing(secretKeyRings, keyRingGenerator.generateSecretKeyRing());

        // upisujemo izmene u fajlove
        savePublicKeyRing();
        saveSecretKeyRing();
    }


    public void importKeyPair(InputStream is) {
        try {
            PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(PGPUtil.getDecoderStream(is), new BcKeyFingerprintCalculator());
            Object o;
            while ((o = pgpObjectFactory.nextObject()) !=null) {
                if (o instanceof PGPSecretKeyRing) {
                    importSecretKeyRing((PGPSecretKeyRing) o);
                } else if (o instanceof PGPPublicKeyRing) {
                    importPublicKeyRing((PGPPublicKeyRing) o);
                } else {
                    System.out.println("sta je onda???");
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public void importPublicKeyRing(PGPPublicKeyRing publicKeyRing) {
        publicKeyRings = PGPPublicKeyRingCollection.addPublicKeyRing(publicKeyRings, publicKeyRing);
        savePublicKeyRing();
    }

    public void importSecretKeyRing(PGPSecretKeyRing secretKeyRing) {
        secretKeyRings = PGPSecretKeyRingCollection.addSecretKeyRing(secretKeyRings, secretKeyRing);
        saveSecretKeyRing();
    }

    public void exportSecretKeyRing(String fileName, String userId) {
        try (OutputStream out = new ArmoredOutputStream(new FileOutputStream(fileName))){
            Iterator<PGPSecretKeyRing> keyRingsIter = secretKeyRings.getKeyRings(userId);
            while (keyRingsIter.hasNext()) {
                PGPSecretKeyRing keyRing = keyRingsIter.next();
                keyRing.encode(out);
            }
            SuccessScreen successScreen = new SuccessScreen("Secret key successfully exported", "Secret key successfully exported");
            successScreen.showAndWait();
        } catch (PGPException | IOException e) {
            e.printStackTrace();
        }
    }

    public boolean exportPublicKeyRing(String fileName, String userID) {
        try (OutputStream out = new ArmoredOutputStream(new FileOutputStream(fileName))) {
            Iterator<PGPPublicKeyRing> keyRingsIter = publicKeyRings.getKeyRings(userID);
            while (keyRingsIter.hasNext()) {
                PGPPublicKeyRing keyRing = keyRingsIter.next();
                keyRing.encode(out);
            }
        } catch (IOException | PGPException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    /**
     * Metoda upisuje javni keyring u fajl.
     */
    private static void savePublicKeyRing() {
        try (OutputStream out = new FileOutputStream(publicRingFile)) {
            publicKeyRings.encode(out);
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

    /**
     * Metoda upisuje tajni keyring u fajl.
     */
    private static void saveSecretKeyRing() {
        try (OutputStream out = new FileOutputStream(secretRingFile)) {
            secretKeyRings.encode(out);
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

    public void printPublicKeyRings() {
        Iterator<PGPPublicKeyRing> keyRings = publicKeyRings.getKeyRings();
        int keyRingCounter = 1;
        while (keyRings.hasNext()) {
            System.out.println("keyRing number " + keyRingCounter++);
            printPublicKeyRingInfo(keyRings.next());
        }
    }

    public void printPrivateKeyRings() {
        Iterator<PGPSecretKeyRing> keyRings = secretKeyRings.getKeyRings();
        while (keyRings.hasNext()) {
            printSecretKeyRingInfo(keyRings.next());
        }
    }

    private void printPublicKeyRingInfo(PGPPublicKeyRing pkr) {
        Iterator<PGPPublicKey> publicKeys = pkr.getPublicKeys();
        while (publicKeys.hasNext()) {
            PGPPublicKey publicKey = publicKeys.next();
            System.out.println("key id: " + publicKey.getKeyID());
            System.out.println("isEncryptionKey: " + publicKey.isEncryptionKey());
            System.out.println("userIds: ");
            publicKey.getUserIDs().forEachRemaining(System.out::println);
        }
    }

    private void printSecretKeyRingInfo(PGPSecretKeyRing skr) {
        Iterator<PGPPublicKey> pubKeysIter = skr.getPublicKeys();
        Iterator<PGPSecretKey> secKeysIter = skr.getSecretKeys();
        System.out.println("##############");
        System.out.println("public keys: ");
        while (pubKeysIter.hasNext()) {
            PGPPublicKey key = pubKeysIter.next();
            Iterator<String> userIDs = key.getUserIDs();
            System.out.println("##############");
            System.out.println("key id: " + key.getKeyID());
            System.out.println("key size: " + key.getBitStrength());
            System.out.println("userIds:");
            userIDs.forEachRemaining(System.out::println);
            System.out.println("encryption key: " + key.isEncryptionKey());
            System.out.println("##############");
        }
        System.out.println("secret keys:");
        while (secKeysIter.hasNext()) {
            PGPSecretKey key = secKeysIter.next();
            Iterator<String> userIDs = key.getUserIDs();
            System.out.println("##############");
            System.out.println("key id: " + key.getKeyID());
            System.out.println("key encryption algorithm: " + key.getKeyEncryptionAlgorithm());
            System.out.println("userIds:");
            userIDs.forEachRemaining(System.out::println);
            System.out.println("signing key: " + key.isSigningKey());
            System.out.println("##############");
        }
    }

    public boolean verifySecretKeyPassword(Long keyId, String password) {
        PGPSecretKey secretKey = null;
        try {
            PGPSecretKeyRing secretKeyRing = secretKeyRings.getSecretKeyRing(keyId);
            Iterator<PGPSecretKey> secretKeys = secretKeyRing.getSecretKeys();
            while (secretKeys.hasNext()) {
                PGPSecretKey tempKey = secretKeys.next();
                if (tempKey.isSigningKey()) {
                    secretKey = tempKey;
                    break;
                }
            }
        } catch (PGPException e) {
            e.printStackTrace();
        }
        if (secretKey != null) {
            try {
                PBESecretKeyDecryptor keyDecryptor = new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(password.toCharArray());
                PGPPrivateKey privateKey = secretKey.extractPrivateKey(keyDecryptor);
            } catch (PGPException e) {
                return false;
            }
        }
        return true;
    }

    public void deleteSecretKey(Long keyId) {
        try {
            PGPSecretKeyRing secretKeyRing = secretKeyRings.getSecretKeyRing(keyId);
            // brisanje tajnog kljuca podrazumeva i brisanje svih njemu pridruzenih javnih kljuceva
            Iterator<PGPPublicKey> publicKeys = secretKeyRing.getPublicKeys();
            while (publicKeys.hasNext()) {
                PGPPublicKey publicKey = publicKeys.next();
                PGPPublicKeyRing publicKeyRing = null;
                if ((publicKeyRing = publicKeyRings.getPublicKeyRing(publicKey.getKeyID())) != null) {
                    publicKeyRings = PGPPublicKeyRingCollection.removePublicKeyRing(publicKeyRings, publicKeyRing);
                }
            }

            secretKeyRings = secretKeyRings.removeSecretKeyRing(secretKeyRings, secretKeyRing);
            saveSecretKeyRing();
            savePublicKeyRing();
        } catch (PGPException e) {
            e.printStackTrace();
        }
    }

    public void deletePublicKey(Long keyId) {
        try {
            PGPPublicKeyRing publicKeyRing = publicKeyRings.getPublicKeyRing(keyId);
            publicKeyRings = publicKeyRings.removePublicKeyRing(publicKeyRings, publicKeyRing);
            savePublicKeyRing();
        } catch (PGPException e) {
            e.printStackTrace();
        }
    }

    public List<Key> getSigningKeys() {
        List<Key> signingKeys = new LinkedList<>();
        Iterator<PGPSecretKeyRing> keyRings = secretKeyRings.getKeyRings();

        while (keyRings.hasNext()) {
            PGPSecretKeyRing keyRing = keyRings.next();
            Iterator<PGPSecretKey> secretKeys = keyRing.getSecretKeys();
            while (secretKeys.hasNext()) {
                PGPSecretKey secretKey = secretKeys.next();
                if (secretKey.isSigningKey()) {
                    Iterator<String> userIDs = secretKey.getUserIDs();
                    if (userIDs.hasNext()) {
                        signingKeys.add(new Key(secretKey.getKeyID(), userIDs.next()));
                    }
                }
            }
        }

        return signingKeys;
    }

    public List<Key> getEncryptionKeys() {
        List<Key> encryptionKeys = new LinkedList<>();
        Iterator<PGPPublicKeyRing> keyRings = publicKeyRings.getKeyRings();

        while (keyRings.hasNext()) {
            PGPPublicKeyRing keyRing = keyRings.next();
            Iterator<PGPPublicKey> publicKeys = keyRing.getPublicKeys();
            String userId = null;
            Long keyId = null;
            while (publicKeys.hasNext()) {
                PGPPublicKey publicKey = publicKeys.next();
                if (publicKey.getUserIDs().hasNext()) {
                    userId = (String) publicKey.getUserIDs().next();
                }
                if (publicKey.isEncryptionKey()) {
                    keyId = publicKey.getKeyID();
                }
            }
            encryptionKeys.add(new Key(keyId, userId));
        }
        return encryptionKeys;
    }

    public PGPPublicKeyRingCollection getPublicKeyRings() {
    	return publicKeyRings;
    }

    public PGPSecretKeyRingCollection getSecretKeyRings() {
    	return secretKeyRings;
    }

    public void setKeyPairGenerator(KeyPairGenerator keyPairGenerator) {
        this.keyPairGenerator = keyPairGenerator;
    }

    public PGPPublicKey getEncryptionKey(String userId, Long keyId) throws PGPException {
        Iterator<PGPPublicKeyRing> keyRings = publicKeyRings.getKeyRings(userId);
        PGPPublicKey publicKey = null;

        while (keyRings.hasNext() && (publicKey = keyRings.next().getPublicKey(keyId)) == null);
        return publicKey;
    }

    public PGPSecretKey getSigningKey(String userId, Long keyId) throws PGPException {
        Iterator<PGPSecretKeyRing> keyRings = secretKeyRings.getKeyRings(userId);
        PGPSecretKey secretKey = null;

        while (keyRings.hasNext() && (secretKey = keyRings.next().getSecretKey(keyId)) == null);
        return secretKey;
    }
}
