package etf.openpgp.indeksi.crypto;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;

import java.io.*;
import java.security.*;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;

/**
 * Klasa zaduzena za rad sa keyringovima. Sadrzi metode za generisanje novog para kljuceva, uvoz postojeceg kljuca
 * i izvoz kljuceva. Cuva informacije o svim postojecim javnim i tajnim kljucevima.
 *
 * @author Proka
 */
public class RSAKeyRing {

    private static final String PRIVATE_KEYRING_FILE_LOCATION = "private.keyring";
    private static final String PUBLIC_KEYRING_FILE_LOCATION = "public.keyring";

    private static File publicRingFile = new File(PUBLIC_KEYRING_FILE_LOCATION);
    private static File secretRingFile = new File(PRIVATE_KEYRING_FILE_LOCATION);

    private static PGPPublicKeyRingCollection publicKeyRings;
    private static PGPSecretKeyRingCollection secretKeyRings;

    static {
        initialize();
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
    public static void generateNewKeyPair(int keySizeSign, int keySizeEncrypt, int encryptionAlgorithm,
                                          String userID, String password) throws NoSuchProviderException,
            NoSuchAlgorithmException, PGPException {

        // kreiramo par kljuceva za potpisivanje
        KeyPairGenerator keyPairGeneratorSign = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGeneratorSign.initialize(keySizeSign);

        KeyPair keyPairSign = keyPairGeneratorSign.generateKeyPair();

        PGPKeyPair pgpKeyPairSign = new PGPKeyPair(PGPPublicKey.RSA_SIGN, keyPairSign, new Date(), "BC");

        // kreiramo par kljuceva za enkripciju
        KeyPairGenerator keyPairgeneratorEncrypt = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairgeneratorEncrypt.initialize(keySizeEncrypt);

        KeyPair keyPairEncrypt = keyPairgeneratorEncrypt.generateKeyPair();

        PGPKeyPair pgpKeyPairEncrypt = new PGPKeyPair(PGPPublicKey.RSA_ENCRYPT, keyPairEncrypt, new Date(), "BC");

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

    public static void exportSecretKeyRing() {
        try (OutputStream out = new ArmoredOutputStream(new FileOutputStream("sec.asc"))){
            Iterator<PGPSecretKeyRing> keyRingsIter = secretKeyRings.getKeyRings("testProka@test.com");
            while (keyRingsIter.hasNext()) {
                PGPSecretKeyRing keyRing = keyRingsIter.next();
                keyRing.encode(out);
            }
        } catch (PGPException | IOException e) {
            e.printStackTrace();
        }
    }

    public static void exportPublicKeyRing() {
        try (OutputStream out = new ArmoredOutputStream(new FileOutputStream("pub.asc"))) {
            Iterator<PGPPublicKeyRing> keyRingsIter = publicKeyRings.getKeyRings("testProka@test.com");
            while (keyRingsIter.hasNext()) {
                PGPPublicKeyRing keyRing = keyRingsIter.next();
                keyRing.encode(out);
            }
        } catch (IOException | PGPException e) {
            e.printStackTrace();
        }
    }

    /**
     * Metoda za inicijalizaciju klase. Ucitava keyringove sa diska ukoliko postoje, u suprotnom kreira nove keyringove
     * i inicijalizuje ih praznim listama.
     */
    private static final void initialize() {
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

    public static void printSecretKeyRing() {
        Iterator<PGPSecretKeyRing> secKrIter = secretKeyRings.getKeyRings();
        while (secKrIter.hasNext()) {
            PGPSecretKeyRing skr = secKrIter.next();
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
    }

}
