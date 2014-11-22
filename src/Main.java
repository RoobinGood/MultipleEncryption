import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class Main {
    public static final String CIPHER_ALGORITHM = "AES";
    public static final String ECB_CHAIN_MODE = "ECB";
    public static final String CBC_CHAIN_MODE = "CBC";
    public static final String CIPHER_PADDING = "PKCS5Padding";
    public static final String NO_PADDING = "NoPadding";
    public static final String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";
    public static final int AES_ORDINARY_KEY_LENGTH = 128;
    public static final int AES_BLOCK_SIZE = 128;
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

    // ECB: E - D - E
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

    public static void ecbTest(String fileInName, String fileEOutName, String fileDOutName) throws NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException {
        byte[] key = genKey(3*AES_ORDINARY_KEY_LENGTH);
        writeData(fileEOutName, tripleEncryptECB(readData(fileInName), key));
        writeData(fileDOutName, tripleDecryptECB(readData(fileEOutName), key));
    }


    // CBC: inner
    public static byte[] arrCat(byte[] arr1, byte[] arr2) {
        byte[] arr = new byte[arr1.length + arr2.length];
        System.arraycopy(arr1, 0, arr, 0, arr1.length);
        System.arraycopy(arr2, 0, arr, arr1.length, arr2.length);
        return arr;
    }

    public static byte[] tripleEncryptCBCInner(byte[] data, byte[] key1, byte[] key2, byte[] key3,
                                               byte[] iv1, byte[] iv2, byte[] iv3) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {
        int blockNum = data.length/(AES_BLOCK_SIZE/BYTE_LENGTH);
        byte[] result = new byte[ ( (data.length%(AES_BLOCK_SIZE/BYTE_LENGTH) == 0) ? blockNum : blockNum+1 )*(AES_BLOCK_SIZE/BYTE_LENGTH) ];

        Cipher cipher1 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + CBC_CHAIN_MODE + "/" + CIPHER_PADDING);
        cipher1.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key1, CIPHER_ALGORITHM), new IvParameterSpec(iv1));
        Cipher cipher2 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + CBC_CHAIN_MODE + "/" + NO_PADDING);
        cipher2.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key2, CIPHER_ALGORITHM), new IvParameterSpec(iv2));
        Cipher cipher3 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + CBC_CHAIN_MODE + "/" + NO_PADDING);
        cipher3.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key3, CIPHER_ALGORITHM), new IvParameterSpec(iv3));

        for (int i=0; i<blockNum; i++) {
            cipher1.update(data, i*(AES_BLOCK_SIZE/BYTE_LENGTH), AES_BLOCK_SIZE/BYTE_LENGTH, result, i*(AES_BLOCK_SIZE/BYTE_LENGTH));
            cipher2.update(result, i*(AES_BLOCK_SIZE/BYTE_LENGTH), AES_BLOCK_SIZE/BYTE_LENGTH, result, i*(AES_BLOCK_SIZE/BYTE_LENGTH));
            cipher3.update(result, i*(AES_BLOCK_SIZE/BYTE_LENGTH), AES_BLOCK_SIZE/BYTE_LENGTH, result, i*(AES_BLOCK_SIZE/BYTE_LENGTH));
        }
        cipher1.doFinal(data, blockNum*(AES_BLOCK_SIZE/BYTE_LENGTH), data.length%(AES_BLOCK_SIZE/BYTE_LENGTH), result, blockNum*(AES_BLOCK_SIZE/BYTE_LENGTH));
        cipher2.doFinal(result, blockNum*(AES_BLOCK_SIZE/BYTE_LENGTH), AES_BLOCK_SIZE/BYTE_LENGTH, result, blockNum*(AES_BLOCK_SIZE/BYTE_LENGTH));
        cipher3.doFinal(result, blockNum*(AES_BLOCK_SIZE/BYTE_LENGTH), AES_BLOCK_SIZE/BYTE_LENGTH, result, blockNum*(AES_BLOCK_SIZE/BYTE_LENGTH));

        return result;
    }

    public static byte[] tripleEncryptCBCInner(byte[] data, byte[] key, byte[] iv) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException, InvalidAlgorithmParameterException {
        return tripleEncryptCBCInner(data, Arrays.copyOfRange(key, 0, AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH),
                Arrays.copyOfRange(key, AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH, 2 * AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH),
                Arrays.copyOfRange(key, 2 * AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH, 3 * AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH),
                Arrays.copyOfRange(iv, 0, AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH),
                Arrays.copyOfRange(iv, AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH, 2 * AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH),
                Arrays.copyOfRange(iv, 2 * AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH, 3 * AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH));
    }

    public static byte[] tripleDecryptCBCInner(byte[] data, byte[] key1, byte[] key2, byte[] key3,
                                               byte[] iv1, byte[] iv2, byte[] iv3) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {
        int blockNum = data.length/(AES_BLOCK_SIZE/BYTE_LENGTH);
        byte[] result = new byte[data.length];

        Cipher cipher1 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + CBC_CHAIN_MODE + "/" + CIPHER_PADDING);
        cipher1.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key1, CIPHER_ALGORITHM), new IvParameterSpec(iv1));
        Cipher cipher2 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + CBC_CHAIN_MODE + "/" + NO_PADDING);
        cipher2.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key2, CIPHER_ALGORITHM), new IvParameterSpec(iv2));
        Cipher cipher3 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + CBC_CHAIN_MODE + "/" + NO_PADDING);
        cipher3.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key3, CIPHER_ALGORITHM), new IvParameterSpec(iv3));

        for (int i=0; i<blockNum-1; i++) {
            cipher3.update(data, i*(AES_BLOCK_SIZE/BYTE_LENGTH), AES_BLOCK_SIZE/BYTE_LENGTH, result, i*(AES_BLOCK_SIZE/BYTE_LENGTH));
            cipher2.update(result, i*(AES_BLOCK_SIZE/BYTE_LENGTH), AES_BLOCK_SIZE/BYTE_LENGTH, result, i*(AES_BLOCK_SIZE/BYTE_LENGTH));
            cipher1.update(result, i*(AES_BLOCK_SIZE/BYTE_LENGTH), AES_BLOCK_SIZE/BYTE_LENGTH, result, i*(AES_BLOCK_SIZE/BYTE_LENGTH));
        }
        cipher3.doFinal(data, (blockNum-1)*(AES_BLOCK_SIZE/BYTE_LENGTH), AES_BLOCK_SIZE/BYTE_LENGTH,
                result, (blockNum-1)*(AES_BLOCK_SIZE/BYTE_LENGTH));
        cipher2.doFinal(result, (blockNum-1)*(AES_BLOCK_SIZE/BYTE_LENGTH), AES_BLOCK_SIZE/BYTE_LENGTH,
                result, (blockNum-1)*(AES_BLOCK_SIZE/BYTE_LENGTH));
        printBytes(Arrays.copyOfRange(result, (blockNum-1)*(AES_BLOCK_SIZE/BYTE_LENGTH), blockNum*(AES_BLOCK_SIZE/BYTE_LENGTH)));
        int lastBlockLength = cipher1.doFinal(result, (blockNum-1)*(AES_BLOCK_SIZE/BYTE_LENGTH), AES_BLOCK_SIZE/BYTE_LENGTH,
                result, (blockNum-1)*(AES_BLOCK_SIZE/BYTE_LENGTH));
        System.out.print(lastBlockLength);

        return Arrays.copyOf(result, result.length - (AES_BLOCK_SIZE/BYTE_LENGTH - lastBlockLength));
    }

    public static byte[] tripleDecryptCBCInner(byte[] data, byte[] key, byte[] iv) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException, InvalidAlgorithmParameterException {
        return tripleDecryptCBCInner(data, Arrays.copyOfRange(key, 0, AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH),
                Arrays.copyOfRange(key, AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH, 2 * AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH),
                Arrays.copyOfRange(key, 2 * AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH, 3 * AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH),
                Arrays.copyOfRange(iv, 0, AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH),
                Arrays.copyOfRange(iv, AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH, 2 * AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH),
                Arrays.copyOfRange(iv, 2 * AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH, 3 * AES_ORDINARY_KEY_LENGTH/BYTE_LENGTH));
    }

    public static void cbcInnerTest(String fileInName, String fileEOutName, String fileDOutName) throws NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, ShortBufferException, InvalidAlgorithmParameterException {
        byte[] key = genKey(3*AES_ORDINARY_KEY_LENGTH);
        byte[] iv = genKey(3*AES_ORDINARY_KEY_LENGTH);
        writeData(fileEOutName, tripleEncryptCBCInner(readData(fileInName), key, iv));
        writeData(fileDOutName, tripleDecryptCBCInner(readData(fileEOutName), key, iv));
    }


    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, ShortBufferException, InvalidAlgorithmParameterException {
        String fileInName = "test\\test.jpg";
        String fileEOutName = "test\\testE.jpg";
        String fileDOutName = "test\\testD.jpg";

        cbcInnerTest(fileInName, fileEOutName, fileDOutName);
    }
}
