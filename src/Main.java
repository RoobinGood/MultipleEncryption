import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class Main {
    public static final String CIPHER_ALGORITHM = "AES";
    public static final String ECB_CHAIN_MODE = "ECB";
    public static final String CIPHER_PADDING = "PKCS5Padding";
    public static final String NO_PADDING = "NoPadding";
    public static final String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";
    public static final int AES_ORDINARY_KEY_LENGTH = 128;
    public static final int BYTE_LENGTH = 8;


    public static byte[] readData(String fName) throws IOException {
        FileInputStream fileInputStream = new FileInputStream(fName);
        byte[] data = new byte[fileInputStream.available()];
        fileInputStream.read(data);
        return data;
    }

    public static void writeData(String fName, byte[] data) throws IOException {
        FileOutputStream fileOutputStream = new FileOutputStream(fName);
        fileOutputStream.write(data);
    }

    public static void printBytes(byte[] x) {
        for (byte b: x) {
            String t = Integer.toHexString(b & 0xFF);
            while (t.length()<2)
                t = '0' + t;
            System.out.print(t);
        }
        System.out.println();
    }

    // E - D - E
    public static byte[] tripleEncryptECB(byte[] data, byte[] key1, byte[] key2, byte[] key3) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM + "/" + ECB_CHAIN_MODE + "/" + CIPHER_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key1, CIPHER_ALGORITHM));
        byte[] result = cipher.doFinal(data);
        cipher = Cipher.getInstance(CIPHER_ALGORITHM + "/" + ECB_CHAIN_MODE + "/" + NO_PADDING);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key2, CIPHER_ALGORITHM));
        result = cipher.doFinal(result);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key3, CIPHER_ALGORITHM));
        result = cipher.doFinal(result);
        return result;
    }

    public static byte[] tripleEncryptECB(byte[] data, byte[] key) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return tripleEncryptECB(data, Arrays.copyOfRange(key, 0, AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH),
                Arrays.copyOfRange(key, AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH, 2*AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH),
                Arrays.copyOfRange(key, 2*AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH, 3*AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH));
    }

    public static byte[] tripleDecryptECB(byte[] data, byte[] key1, byte[] key2, byte[] key3) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM + "/" + ECB_CHAIN_MODE + "/" + NO_PADDING);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key3, CIPHER_ALGORITHM));
        byte[] result = cipher.doFinal(data);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key2, CIPHER_ALGORITHM));
        result = cipher.doFinal(result);
        cipher = Cipher.getInstance(CIPHER_ALGORITHM + "/" + ECB_CHAIN_MODE + "/" + CIPHER_PADDING);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key1, CIPHER_ALGORITHM));
        result = cipher.doFinal(result);
        return result;
    }

    public static byte[] tripleDecryptECB(byte[] data, byte[] key) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return tripleDecryptECB(data, Arrays.copyOfRange(key, 0, AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH),
                Arrays.copyOfRange(key, AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH, 2 * AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH),
                Arrays.copyOfRange(key, 2 * AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH, 3 * AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH));
    }

    public static byte[] genKey(int bitLength) throws NoSuchAlgorithmException {
        SecureRandom secureRandom = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM);
        byte[] key = new byte[bitLength/BYTE_LENGTH];
        secureRandom.nextBytes(key);
        return key;
    }


    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException {
        String fileInName = "test\\test.jpg";
        String fileEOutName = "test\\testE.jpg";
        String fileDOutName = "test\\testD.jpg";

        byte[] key = genKey(3*AES_ORDINARY_KEY_LENGTH);
        writeData(fileEOutName, tripleEncryptECB(readData(fileInName), key));
        writeData(fileDOutName, tripleDecryptECB(readData(fileEOutName), key));
    }
}
