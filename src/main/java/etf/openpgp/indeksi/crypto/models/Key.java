package etf.openpgp.indeksi.crypto.models;

public class Key {

    private Long keyId;
    private String userId;

    public Key(Long keyId, String userId) {
        this.keyId = keyId;
        this.userId = userId;
    }

    public Long getKeyId() {
        return keyId;
    }

    public String getUserId() {
        return userId;
    }

    @Override
    public String toString() {
        return userId;
    }
}
