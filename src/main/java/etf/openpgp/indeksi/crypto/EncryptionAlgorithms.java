package etf.openpgp.indeksi.crypto;

public enum EncryptionAlgorithms {
    IDEA(1, "IDEA"),
    TRIPLE_DES(2, "3DES");

    private int value;
    private String label;

    EncryptionAlgorithms(int value, String label) {
        this.value = value;
        this.label = label;
    }

    public int getValue() {
        return value;
    }

    public String getLabel() {
        return label;
    }

    public static EncryptionAlgorithms parse(String label) {
        EncryptionAlgorithms retVal = null;
        for (EncryptionAlgorithms algorithm : EncryptionAlgorithms.values()) {
            if (algorithm.getLabel().equals(label)) {
                retVal = algorithm;
                break;
            }
        }
        return retVal;
    }
}
