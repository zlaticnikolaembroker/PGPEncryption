package etf.openpgp.indeksi.front;

import etf.openpgp.indeksi.crypto.KeyRings;

import java.util.Optional;

public class PasswordVerificator {

    public static boolean verify(long keyId, KeyRings keyRings) {
        int passwordAttemptCounter = 0;
        boolean passwordVerified = false;
        PasswordDialog passwordDialog = new PasswordDialog();

        while (!passwordVerified && passwordAttemptCounter < 3) {
            Optional<String> passwordOptional = passwordDialog.showAndWait();
            if (passwordOptional.isPresent()) {
                String password = passwordOptional.get();

                passwordVerified = keyRings.verifySecretKeyPassword(keyId, password);
            }
            passwordAttemptCounter++;
        }

        return passwordVerified;
    }

}
