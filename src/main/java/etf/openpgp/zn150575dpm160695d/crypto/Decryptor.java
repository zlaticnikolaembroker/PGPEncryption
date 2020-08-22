package etf.openpgp.zn150575dpm160695d.crypto;

import org.bouncycastle.openpgp.*;

import javafx.stage.FileChooser;
import javafx.stage.Stage;

import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.util.io.Streams;

import etf.openpgp.zn150575dpm160695d.front.InfoScreen;
import etf.openpgp.zn150575dpm160695d.front.PasswordVerificator;

import java.io.*;
import java.util.Iterator;

public class Decryptor {
    private static final int BUFFER_SIZE = 1 << 16; // 64k

    private final KeyRings keyRings;
    private final Verifier verifier;

    public Decryptor(KeyRings keyRings) {
        this.keyRings = keyRings;
        this.verifier = new Verifier(keyRings);
    }
    
    private PGPPrivateKey findSecretKey(long keyID)
            throws Exception
        {
     
            PGPSecretKey pgpSecKey = this.keyRings.getSecretKeyRings().getSecretKey(keyID);
     
            if (pgpSecKey == null) {
                return null;
            }

            String password = PasswordVerificator.verify(keyID, this.keyRings);
            
            if (password == null) {
            	throw new Exception("Pass don't match");
            }
     
            return pgpSecKey.extractPrivateKey(password.toCharArray(), "BC");
        }
    
    public void decryptOrVerifyFile(InputStream in, String signaturePath, Stage stage)
        {
	    	try (InputStream inputStream = PGPUtil.getDecoderStream(in)) {

	            PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(inputStream);
	            PGPEncryptedDataList encryptedDataList = null;
	     
	            Object pgpObject = pgpObjectFactory.nextObject();

	            // ako je prvi objekat marker, pomeramo se na sledeci
				if (pgpObject instanceof PGPMarker) {
					pgpObject = pgpObjectFactory.nextObject();
				}

	            if (pgpObject instanceof PGPEncryptedDataList) {
	                encryptedDataList = (PGPEncryptedDataList) pgpObject;
	            }
	            if (encryptedDataList == null) {
	            	// nema enkriptovanih podataka, idemo na verifikaciju
					if (pgpObject instanceof PGPCompressedData) {
						//ovo ne bi nikad trebalo da se desi, jer je ili potpisan ili enkriptovan podatak.
						System.out.println("compressed data");
					}
					if (pgpObject instanceof PGPSignatureList) {
						verifier.verifySignature((PGPSignatureList) pgpObject, signaturePath);
					}
					return;
				}

	            Iterator<PGPPublicKeyEncryptedData> publicKeyEncryptedDataIterator = encryptedDataList.getEncryptedDataObjects();
	            PGPPrivateKey secretKey = null;
	            PGPPublicKeyEncryptedData pbe = null;
	     
	            while (secretKey == null && publicKeyEncryptedDataIterator.hasNext()) {
	                pbe = publicKeyEncryptedDataIterator.next();
	     
	                secretKey = this.findSecretKey(pbe.getKeyID());
	            }
	     
	            if (secretKey == null) {
	                throw new IllegalArgumentException("Secret key for message not found.");
	            }
	     
	            InputStream clear = pbe.getDataStream(secretKey, "BC");
	     
	            PGPObjectFactory plainFact = new PGPObjectFactory(clear);

				Object message = plainFact.nextObject();
				PGPOnePassSignatureList onePassSignatureList = null;
				PGPSignatureList signatureList = null;
				ByteArrayOutputStream bos = new ByteArrayOutputStream();
				StringBuilder labelTextBuilder = new StringBuilder();
				while (message != null) {
					if (message instanceof PGPCompressedData) {
						plainFact = new PGPObjectFactory(((PGPCompressedData) message).getDataStream());
						message = plainFact.nextObject();
					}

					if (message instanceof PGPLiteralData) {
						Streams.pipeAll(((PGPLiteralData) message).getInputStream(), bos);
					} else if (message instanceof PGPOnePassSignatureList) {
						onePassSignatureList = (PGPOnePassSignatureList) message;
					} else if (message instanceof PGPSignatureList) {
						signatureList = (PGPSignatureList) message;
					}
					message = plainFact.nextObject();
				}

				PGPPublicKey publicKey = null;
				if (onePassSignatureList != null && signatureList != null) {
					for (int i = 0; i < onePassSignatureList.size(); i++) {
						PGPOnePassSignature onePassSignature = onePassSignatureList.get(i);
						publicKey = keyRings.getPublicKeyRings().getPublicKey(onePassSignature.getKeyID());
						if (publicKey != null) {
							onePassSignature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);
							onePassSignature.update(bos.toByteArray());
							PGPSignature signature = signatureList.get(i);
							if (onePassSignature.verify(signature)) {
								labelTextBuilder.append(" signed by " + publicKey.getUserIDs().next() + " and verified ");
							} else {
								labelTextBuilder.append(" signature by " + publicKey.getUserIDs().next() + " could not be verified ");
							}
						} else {
							labelTextBuilder.append(" signed with unknown key");
						}
					}
				} else {
					labelTextBuilder.append(" not signed");
				}

				FileChooser fileChooser = new FileChooser();
				fileChooser.setTitle("Choose where you want to save decrypted file.");
				File outputFile = fileChooser.showSaveDialog(stage);
				int counter = 0;
				while (counter < 2 && outputFile == null) {
					fileChooser = new FileChooser();
					fileChooser.setTitle("Choose where you want to save decrypted file.");
					outputFile = fileChooser.showSaveDialog(stage);
					counter++;
				}

				if (outputFile == null) {
					return;
				}

				OutputStream out = new FileOutputStream(outputFile);
				out.write(bos.toByteArray());
				out.flush();
				out.close();

				InfoScreen success = new InfoScreen("File successfully decrypted", "File successfully decrypted " + labelTextBuilder.toString());
				success.showAndWait();

	        } catch(Exception e) {
                InfoScreen successScreen = new InfoScreen("Something went wrong", e.getMessage());
	            successScreen.showAndWait();
                e.printStackTrace();
            }
        }
}