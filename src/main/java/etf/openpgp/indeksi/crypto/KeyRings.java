package etf.openpgp.indeksi.crypto;

import etf.openpgp.indeksi.crypto.generators.KeyPairGenerator;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Iterator;

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

    private File publicRingFile = new File(PUBLIC_KEYRING_FILE_LOCATION);
    private File secretRingFile = new File(SECRET_KEYRING_FILE_LOCATION);

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
            Object o = null;
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

    public void exportSecretKeyRing() {
        try (OutputStream out = new ArmoredOutputStream(new FileOutputStream("sec.asc"))){
            Iterator<PGPSecretKeyRing> keyRingsIter = secretKeyRings.getKeyRings("proka@test.com");
            while (keyRingsIter.hasNext()) {
                PGPSecretKeyRing keyRing = keyRingsIter.next();
                keyRing.encode(out);
            }
        } catch (PGPException | IOException e) {
            e.printStackTrace();
        }
    }

    public void exportPublicKeyRing() {
        try (OutputStream out = new ArmoredOutputStream(new FileOutputStream("pub.asc"))) {
            Iterator<PGPPublicKeyRing> keyRingsIter = publicKeyRings.getKeyRings("proka@test.com");
            while (keyRingsIter.hasNext()) {
                PGPPublicKeyRing keyRing = keyRingsIter.next();
                keyRing.encode(out);
            }
        } catch (IOException | PGPException e) {
            e.printStackTrace();
        }
    }

    /**
     * Metoda upisuje javni keyring u fajl.
     */
    private void savePublicKeyRing() {
        try (OutputStream out = new FileOutputStream(publicRingFile)) {
            publicKeyRings.encode(out);
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

    /**
     * Metoda upisuje tajni keyring u fajl.
     */
    private void saveSecretKeyRing() {
        try (OutputStream out = new FileOutputStream(secretRingFile)) {
            secretKeyRings.encode(out);
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

    public void printSecretKeyRing() {
        Iterator<PGPSecretKeyRing> secKrIter = secretKeyRings.getKeyRings();
        while (secKrIter.hasNext()) {
            PGPSecretKeyRing skr = secKrIter.next();
            printSecretKeyRingInfo(skr);
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

    public void setKeyPairGenerator(KeyPairGenerator keyPairGenerator) {
        this.keyPairGenerator = keyPairGenerator;
    }

}
