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
    public static final String CIPHER_ALGORITHM = "DES";
    public static final String ECB_CHAIN_MODE = "ECB";
    public static final String CBC_CHAIN_MODE = "CBC";
    public static final String CIPHER_PADDING = "PKCS5Padding";
    public static final String NO_PADDING = "NoPadding";
    public static final String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";
    public static final int ORDINARY_KEY_LENGTH = 64;
    public static final int IV_SIZE = 64;
    public static final int BLOCK_SIZE = 64;
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

    public static byte[] arrCat(byte[] arr1, byte[] arr2) {
        byte[] arr = new byte[arr1.length + arr2.length];
        System.arraycopy(arr1, 0, arr, 0, arr1.length);
        System.arraycopy(arr2, 0, arr, arr1.length, arr2.length);
        return arr;
    }

    public static byte[] arrXor(byte[] dst, int offset, byte[] arr) {
        for (int i=0; (i<arr.length) && (offset + i < dst.length); i++) {
            dst[offset + i] ^= arr[i];
        }
        return dst;
    }

    // ECB: E - D - E
    public static byte[] tripleEncryptECB(byte[] data, byte[] key1, byte[] key2, byte[] key3) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM + "/" + ECB_CHAIN_MODE + "/" + NO_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key1, CIPHER_ALGORITHM));
        byte[] result = cipher.doFinal(addPadding(data));
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key2, CIPHER_ALGORITHM));
        result = cipher.doFinal(result);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key3, CIPHER_ALGORITHM));
        result = cipher.doFinal(result);
        return result;
    }

    public static byte[] tripleEncryptECB(byte[] data, byte[] key) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return tripleEncryptECB(data, Arrays.copyOfRange(key, 0, ORDINARY_KEY_LENGTH /BYTE_LENGTH),
                Arrays.copyOfRange(key, ORDINARY_KEY_LENGTH /BYTE_LENGTH, 2* ORDINARY_KEY_LENGTH /BYTE_LENGTH),
                Arrays.copyOfRange(key, 2* ORDINARY_KEY_LENGTH /BYTE_LENGTH, 3* ORDINARY_KEY_LENGTH /BYTE_LENGTH));
    }

    public static byte[] tripleDecryptECB(byte[] data, byte[] key1, byte[] key2, byte[] key3) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM + "/" + ECB_CHAIN_MODE + "/" + NO_PADDING);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key3, CIPHER_ALGORITHM));
        byte[] result = cipher.doFinal(data);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key2, CIPHER_ALGORITHM));
        result = cipher.doFinal(result);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key1, CIPHER_ALGORITHM));
        result = cipher.doFinal(result);
        return delPadding(result);
    }

    public static byte[] tripleDecryptECB(byte[] data, byte[] key) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return tripleDecryptECB(data, Arrays.copyOfRange(key, 0, ORDINARY_KEY_LENGTH /BYTE_LENGTH),
                Arrays.copyOfRange(key, ORDINARY_KEY_LENGTH /BYTE_LENGTH, 2 * ORDINARY_KEY_LENGTH /BYTE_LENGTH),
                Arrays.copyOfRange(key, 2 * ORDINARY_KEY_LENGTH /BYTE_LENGTH, 3 * ORDINARY_KEY_LENGTH /BYTE_LENGTH));
    }

    public static byte[] genBytes(int bitLength) throws NoSuchAlgorithmException {
        SecureRandom secureRandom = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM);
        byte[] key = new byte[bitLength/BYTE_LENGTH];
        secureRandom.nextBytes(key);
        return key;
    }

    public static void ecbTest(String fileInName, String fileEOutName, String fileDOutName) throws NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException {
        byte[] key = genBytes(3 * ORDINARY_KEY_LENGTH);
        writeData(fileEOutName, tripleEncryptECB(readData(fileInName), key));
        writeData(fileDOutName, tripleDecryptECB(readData(fileEOutName), key));
    }


    // CBC: inner
    public static byte[] addPadding(byte[] data) {
        int blockNum = data.length/(BLOCK_SIZE /BYTE_LENGTH);
        int length = ( (data.length%(BLOCK_SIZE /BYTE_LENGTH) == 0) ? blockNum : blockNum+1 )*(BLOCK_SIZE /BYTE_LENGTH);

        byte[] result = new byte[length];
        int padSize = data.length%(BLOCK_SIZE /BYTE_LENGTH);
        System.arraycopy(data, 0, result, 0, data.length);
        for (int i=0; i<padSize; i++) {
            result[length - i - 1] = (byte)padSize;
        }

        return result;
    }

    public static byte[] delPadding(byte[] data) {
        int padSize = (int)data[data.length-1];

        for (int i=0; i<padSize; i++) {
            if (data[data.length - i - 1] != (byte)padSize) {
                return data;
            }
        }
        return Arrays.copyOfRange(data, 0, data.length-padSize);
    }

    public static byte[] tripleEncryptCBCInner(byte[] data, byte[] key1, byte[] key2, byte[] key3,
                                               byte[] iv1, byte[] iv2, byte[] iv3) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {
        byte[] result = addPadding(data);
        int blockNum = result.length/(BLOCK_SIZE /BYTE_LENGTH);


        Cipher cipher1 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + CBC_CHAIN_MODE + "/" + NO_PADDING);
        cipher1.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key1, CIPHER_ALGORITHM), new IvParameterSpec(iv1));
        Cipher cipher2 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + CBC_CHAIN_MODE + "/" + NO_PADDING);
        cipher2.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key2, CIPHER_ALGORITHM), new IvParameterSpec(iv2));
        Cipher cipher3 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + CBC_CHAIN_MODE + "/" + NO_PADDING);
        cipher3.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key3, CIPHER_ALGORITHM), new IvParameterSpec(iv3));

        for (int i=0; i<blockNum-1; i++) {
            cipher1.update(result, i*(BLOCK_SIZE /BYTE_LENGTH), BLOCK_SIZE /BYTE_LENGTH, result, i*(BLOCK_SIZE /BYTE_LENGTH));
            cipher2.update(result, i*(BLOCK_SIZE /BYTE_LENGTH), BLOCK_SIZE /BYTE_LENGTH, result, i*(BLOCK_SIZE /BYTE_LENGTH));
            cipher3.update(result, i*(BLOCK_SIZE /BYTE_LENGTH), BLOCK_SIZE /BYTE_LENGTH, result, i*(BLOCK_SIZE /BYTE_LENGTH));
        }
        cipher1.doFinal(result, (blockNum-1)*(BLOCK_SIZE /BYTE_LENGTH), BLOCK_SIZE /BYTE_LENGTH,
                result, (blockNum-1)*(BLOCK_SIZE /BYTE_LENGTH));
        cipher2.doFinal(result, (blockNum-1)*(BLOCK_SIZE /BYTE_LENGTH), BLOCK_SIZE /BYTE_LENGTH,
                result, (blockNum-1)*(BLOCK_SIZE /BYTE_LENGTH));
        cipher3.doFinal(result, (blockNum-1)*(BLOCK_SIZE /BYTE_LENGTH), BLOCK_SIZE /BYTE_LENGTH,
                result, (blockNum-1)*(BLOCK_SIZE /BYTE_LENGTH));

        return result;
    }

    public static byte[] tripleEncryptCBCInner(byte[] data, byte[] key, byte[] iv) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException, InvalidAlgorithmParameterException {
        return tripleEncryptCBCInner(data, Arrays.copyOfRange(key, 0, ORDINARY_KEY_LENGTH /BYTE_LENGTH),
                Arrays.copyOfRange(key, ORDINARY_KEY_LENGTH /BYTE_LENGTH, 2 * ORDINARY_KEY_LENGTH /BYTE_LENGTH),
                Arrays.copyOfRange(key, 2 * ORDINARY_KEY_LENGTH /BYTE_LENGTH, 3 * ORDINARY_KEY_LENGTH /BYTE_LENGTH),
                Arrays.copyOfRange(iv, 0, ORDINARY_KEY_LENGTH /BYTE_LENGTH),
                Arrays.copyOfRange(iv, ORDINARY_KEY_LENGTH /BYTE_LENGTH, 2 * ORDINARY_KEY_LENGTH /BYTE_LENGTH),
                Arrays.copyOfRange(iv, 2 * ORDINARY_KEY_LENGTH /BYTE_LENGTH, 3 * ORDINARY_KEY_LENGTH /BYTE_LENGTH));
    }

    public static byte[] tripleDecryptCBCInner(byte[] data, byte[] key1, byte[] key2, byte[] key3,
                                               byte[] iv1, byte[] iv2, byte[] iv3) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {
        int blockNum = data.length/(BLOCK_SIZE /BYTE_LENGTH);
        byte[] result = new byte[data.length];

        Cipher cipher1 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + CBC_CHAIN_MODE + "/" + NO_PADDING);
        cipher1.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key1, CIPHER_ALGORITHM), new IvParameterSpec(iv1));
        Cipher cipher2 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + CBC_CHAIN_MODE + "/" + NO_PADDING);
        cipher2.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key2, CIPHER_ALGORITHM), new IvParameterSpec(iv2));
        Cipher cipher3 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + CBC_CHAIN_MODE + "/" + NO_PADDING);
        cipher3.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key3, CIPHER_ALGORITHM), new IvParameterSpec(iv3));

        for (int i=0; i<blockNum-1; i++) {
            cipher3.update(data, i*(BLOCK_SIZE /BYTE_LENGTH), BLOCK_SIZE /BYTE_LENGTH, result, i*(BLOCK_SIZE /BYTE_LENGTH));
            cipher2.update(result, i*(BLOCK_SIZE /BYTE_LENGTH), BLOCK_SIZE /BYTE_LENGTH, result, i*(BLOCK_SIZE /BYTE_LENGTH));
            cipher1.update(result, i*(BLOCK_SIZE /BYTE_LENGTH), BLOCK_SIZE /BYTE_LENGTH, result, i*(BLOCK_SIZE /BYTE_LENGTH));
        }
        cipher3.doFinal(data, (blockNum-1)*(BLOCK_SIZE /BYTE_LENGTH), BLOCK_SIZE /BYTE_LENGTH,
                result, (blockNum-1)*(BLOCK_SIZE /BYTE_LENGTH));
        cipher2.doFinal(result, (blockNum-1) * (BLOCK_SIZE /BYTE_LENGTH), BLOCK_SIZE /BYTE_LENGTH,
                result, (blockNum-1) * (BLOCK_SIZE / BYTE_LENGTH));
        cipher1.doFinal(result, (blockNum-1)*(BLOCK_SIZE /BYTE_LENGTH), BLOCK_SIZE /BYTE_LENGTH,
                result, (blockNum-1)*(BLOCK_SIZE /BYTE_LENGTH));

        return delPadding(result);
    }

    public static byte[] tripleDecryptCBCInner(byte[] data, byte[] key, byte[] iv) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException, InvalidAlgorithmParameterException {
        return tripleDecryptCBCInner(data, Arrays.copyOfRange(key, 0, ORDINARY_KEY_LENGTH /BYTE_LENGTH),
                Arrays.copyOfRange(key, ORDINARY_KEY_LENGTH /BYTE_LENGTH, 2 * ORDINARY_KEY_LENGTH /BYTE_LENGTH),
                Arrays.copyOfRange(key, 2 * ORDINARY_KEY_LENGTH /BYTE_LENGTH, 3 * ORDINARY_KEY_LENGTH /BYTE_LENGTH),
                Arrays.copyOfRange(iv, 0, ORDINARY_KEY_LENGTH /BYTE_LENGTH),
                Arrays.copyOfRange(iv, ORDINARY_KEY_LENGTH /BYTE_LENGTH, 2 * ORDINARY_KEY_LENGTH /BYTE_LENGTH),
                Arrays.copyOfRange(iv, 2 * ORDINARY_KEY_LENGTH /BYTE_LENGTH, 3 * ORDINARY_KEY_LENGTH /BYTE_LENGTH));
    }

    public static void cbcInnerTest(String fileInName, String fileEOutName, String fileDOutName) throws NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, ShortBufferException, InvalidAlgorithmParameterException {
        byte[] key = genBytes(3 * ORDINARY_KEY_LENGTH);
        byte[] iv = genBytes(3 * IV_SIZE);
        writeData(fileEOutName, tripleEncryptCBCInner(readData(fileInName), key, iv));
        writeData(fileDOutName, tripleDecryptCBCInner(readData(fileEOutName), key, iv));
    }


    // CBC: outer
    public static byte[] tripleEncryptCBCOuter(byte[] data, byte[] key1, byte[] key2, byte[] key3,
                                               byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {
        byte[] result = addPadding(data);
        int blockNum = data.length/(BLOCK_SIZE /BYTE_LENGTH);

        Cipher cipher1 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + ECB_CHAIN_MODE + "/" + NO_PADDING);
        cipher1.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key1, CIPHER_ALGORITHM));
        Cipher cipher2 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + ECB_CHAIN_MODE + "/" + NO_PADDING);
        cipher2.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key2, CIPHER_ALGORITHM));
        Cipher cipher3 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + ECB_CHAIN_MODE + "/" + NO_PADDING);
        cipher3.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key3, CIPHER_ALGORITHM));

        byte[] currentIv = Arrays.copyOf(iv, iv.length);
        for (int i=0; i<blockNum-1; i++) {
            result = arrXor(result, i*(BLOCK_SIZE /BYTE_LENGTH), currentIv);
            cipher1.update(result, i*(BLOCK_SIZE /BYTE_LENGTH), BLOCK_SIZE /BYTE_LENGTH,
                    result, i*(BLOCK_SIZE /BYTE_LENGTH));
            cipher2.update(result, i*(BLOCK_SIZE /BYTE_LENGTH), BLOCK_SIZE /BYTE_LENGTH,
                    result, i*(BLOCK_SIZE /BYTE_LENGTH));
            cipher3.update(result, i*(BLOCK_SIZE /BYTE_LENGTH), BLOCK_SIZE /BYTE_LENGTH,
                    result, i*(BLOCK_SIZE /BYTE_LENGTH));
            currentIv = Arrays.copyOfRange(result, i*(BLOCK_SIZE /BYTE_LENGTH),
                    (i + 1)*(BLOCK_SIZE /BYTE_LENGTH));
        }
        result = arrXor(result, (blockNum-1)*(BLOCK_SIZE /BYTE_LENGTH), currentIv);
        cipher1.doFinal(result, (blockNum-1)*(BLOCK_SIZE /BYTE_LENGTH), BLOCK_SIZE /BYTE_LENGTH,
                result, (blockNum-1)*(BLOCK_SIZE /BYTE_LENGTH));
        cipher2.doFinal(result, (blockNum-1)*(BLOCK_SIZE /BYTE_LENGTH), BLOCK_SIZE /BYTE_LENGTH,
                result, (blockNum-1)*(BLOCK_SIZE /BYTE_LENGTH));
        cipher3.doFinal(result, (blockNum-1)*(BLOCK_SIZE /BYTE_LENGTH), BLOCK_SIZE /BYTE_LENGTH,
                result, (blockNum-1)*(BLOCK_SIZE /BYTE_LENGTH));

        return result;
    }

    public static byte[] tripleEncryptCBCOuter(byte[] data, byte[] key, byte[] iv) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException, InvalidAlgorithmParameterException {
        return tripleEncryptCBCOuter(data, Arrays.copyOfRange(key, 0, ORDINARY_KEY_LENGTH / BYTE_LENGTH),
                Arrays.copyOfRange(key, ORDINARY_KEY_LENGTH / BYTE_LENGTH, 2 * ORDINARY_KEY_LENGTH / BYTE_LENGTH),
                Arrays.copyOfRange(key, 2 * ORDINARY_KEY_LENGTH / BYTE_LENGTH, 3 * ORDINARY_KEY_LENGTH / BYTE_LENGTH),
                iv);
    }

    public static byte[] tripleDecryptCBCOuter(byte[] data, byte[] key1, byte[] key2, byte[] key3,
                                               byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {
        int blockNum = data.length/(BLOCK_SIZE /BYTE_LENGTH);
        byte[] result = Arrays.copyOf(data, data.length);

        Cipher cipher1 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + ECB_CHAIN_MODE + "/" + NO_PADDING);
        cipher1.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key1, CIPHER_ALGORITHM));
        Cipher cipher2 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + ECB_CHAIN_MODE + "/" + NO_PADDING);
        cipher2.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key2, CIPHER_ALGORITHM));
        Cipher cipher3 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + ECB_CHAIN_MODE + "/" + NO_PADDING);
        cipher3.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key3, CIPHER_ALGORITHM));

        byte[] currentIv = Arrays.copyOf(iv, iv.length);
        for (int i=0; i<blockNum-1; i++) {
            byte[] nextIv = Arrays.copyOfRange(result, i*(BLOCK_SIZE /BYTE_LENGTH),
                    (i + 1)*(BLOCK_SIZE /BYTE_LENGTH));
            cipher3.update(result, i*(BLOCK_SIZE /BYTE_LENGTH), BLOCK_SIZE /BYTE_LENGTH,
                    result, i*(BLOCK_SIZE /BYTE_LENGTH));
            cipher2.update(result, i*(BLOCK_SIZE /BYTE_LENGTH), BLOCK_SIZE /BYTE_LENGTH,
                    result, i*(BLOCK_SIZE /BYTE_LENGTH));
            cipher1.update(result, i*(BLOCK_SIZE /BYTE_LENGTH), BLOCK_SIZE /BYTE_LENGTH,
                    result, i*(BLOCK_SIZE /BYTE_LENGTH));
            result = arrXor(result, i*(BLOCK_SIZE /BYTE_LENGTH), currentIv);
            currentIv = Arrays.copyOf(nextIv, nextIv.length);
        }
        result = arrXor(result, blockNum*(BLOCK_SIZE /BYTE_LENGTH), currentIv);
        cipher3.doFinal(data, (blockNum-1)*(BLOCK_SIZE /BYTE_LENGTH), BLOCK_SIZE /BYTE_LENGTH,
                result, (blockNum-1)*(BLOCK_SIZE /BYTE_LENGTH));
        cipher2.doFinal(result, (blockNum-1) * (BLOCK_SIZE /BYTE_LENGTH), BLOCK_SIZE /BYTE_LENGTH,
                result, (blockNum-1) * (BLOCK_SIZE /BYTE_LENGTH));
        cipher1.doFinal(result, (blockNum-1)*(BLOCK_SIZE /BYTE_LENGTH), BLOCK_SIZE /BYTE_LENGTH,
                result, (blockNum-1)*(BLOCK_SIZE /BYTE_LENGTH));

        return delPadding(result);
    }

    public static byte[] tripleDecryptCBCOuter(byte[] data, byte[] key, byte[] iv) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException, InvalidAlgorithmParameterException {
        return tripleDecryptCBCOuter(data, Arrays.copyOfRange(key, 0, ORDINARY_KEY_LENGTH / BYTE_LENGTH),
                Arrays.copyOfRange(key, ORDINARY_KEY_LENGTH / BYTE_LENGTH, 2 * ORDINARY_KEY_LENGTH / BYTE_LENGTH),
                Arrays.copyOfRange(key, 2 * ORDINARY_KEY_LENGTH / BYTE_LENGTH, 3 * ORDINARY_KEY_LENGTH / BYTE_LENGTH),
                iv);
    }

    public static void cbcOuterTest(String fileInName, String fileEOutName, String fileDOutName) throws NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, ShortBufferException, InvalidAlgorithmParameterException {
        byte[] key = genBytes(3 * ORDINARY_KEY_LENGTH);
        byte[] iv = genBytes(IV_SIZE);
        writeData(fileEOutName, tripleEncryptCBCOuter(readData(fileInName), key, iv));
        writeData(fileDOutName, tripleDecryptCBCOuter(readData(fileEOutName), key, iv));
    }


    // With pad
    public static byte[] addPad(byte[] data) throws NoSuchAlgorithmException {
        SecureRandom secureRandom = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM);
        byte[] pad = new byte[BLOCK_SIZE /BYTE_LENGTH / 2];
        secureRandom.nextBytes(pad);
        return arrCat(pad, data);
    }

    public static byte[] delPad(byte[] data) {
        return Arrays.copyOfRange(data, BLOCK_SIZE /BYTE_LENGTH / 2, data.length);
    }

    public static byte[] tripleEncryptWithPad(byte[] data, byte[] key1, byte[] key2, byte[] key3) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM + "/" + ECB_CHAIN_MODE + "/" + CIPHER_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key1, CIPHER_ALGORITHM));
        byte[] result = cipher.doFinal(data);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key2, CIPHER_ALGORITHM));
        result = cipher.doFinal(addPad(result));
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key3, CIPHER_ALGORITHM));
        result = cipher.doFinal(addPad(result));
        return result;
    }

    public static byte[] tripleEncryptWithPad(byte[] data, byte[] key) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return tripleEncryptWithPad(data, Arrays.copyOfRange(key, 0, ORDINARY_KEY_LENGTH / BYTE_LENGTH),
                Arrays.copyOfRange(key, ORDINARY_KEY_LENGTH / BYTE_LENGTH, 2 * ORDINARY_KEY_LENGTH / BYTE_LENGTH),
                Arrays.copyOfRange(key, 2 * ORDINARY_KEY_LENGTH / BYTE_LENGTH, 3 * ORDINARY_KEY_LENGTH / BYTE_LENGTH));
    }

    public static byte[] tripleDecryptWithPad(byte[] data, byte[] key1, byte[] key2, byte[] key3) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM + "/" + ECB_CHAIN_MODE + "/" + CIPHER_PADDING);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key3, CIPHER_ALGORITHM));
        byte[] result = cipher.doFinal(data);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key2, CIPHER_ALGORITHM));
        result = cipher.doFinal(delPad(result));
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key1, CIPHER_ALGORITHM));
        result = cipher.doFinal(delPad(result));
        return result;
    }

    public static byte[] tripleDecryptWithPad(byte[] data, byte[] key) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return tripleDecryptWithPad(data, Arrays.copyOfRange(key, 0, ORDINARY_KEY_LENGTH / BYTE_LENGTH),
                Arrays.copyOfRange(key, ORDINARY_KEY_LENGTH / BYTE_LENGTH, 2 * ORDINARY_KEY_LENGTH / BYTE_LENGTH),
                Arrays.copyOfRange(key, 2 * ORDINARY_KEY_LENGTH / BYTE_LENGTH, 3 * ORDINARY_KEY_LENGTH / BYTE_LENGTH));
    }

    public static void withPadTest(String fileInName, String fileEOutName, String fileDOutName) throws NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, ShortBufferException, InvalidAlgorithmParameterException {
        byte[] key = genBytes(3 * ORDINARY_KEY_LENGTH);
        writeData(fileEOutName, tripleEncryptWithPad(readData(fileInName), key));
        writeData(fileDOutName, tripleDecryptWithPad(readData(fileEOutName), key));
    }



    // Time test
    public static void timeTestEncryption(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, ShortBufferException, InvalidAlgorithmParameterException {
        byte[] data = readData(fileName);
        byte[] key = genBytes(3 * ORDINARY_KEY_LENGTH);
        byte[] iv3 = genBytes(3* IV_SIZE);
        byte[] iv1 = Arrays.copyOf(iv3, IV_SIZE /BYTE_LENGTH);

        // may be for init libs...
        tripleEncryptECB(data, key);

        long t = System.currentTimeMillis();
        tripleEncryptECB(data, key);
        long ECBEncryptionTime = System.currentTimeMillis() - t;

        t = System.currentTimeMillis();
        tripleEncryptCBCInner(data, key, iv3);
        long innerCBCEncryptionTime = System.currentTimeMillis() - t;

        t = System.currentTimeMillis();
        tripleEncryptCBCOuter(data, key, iv1);
        long outerCBCEncryptionTime = System.currentTimeMillis() - t;

        t = System.currentTimeMillis();
        tripleEncryptWithPad(data, key);
        long padEncryptionTime = System.currentTimeMillis() - t;

        System.out.println("Encryption");
        System.out.println("ECB:       " + ECBEncryptionTime + " ms.");
        System.out.println("Inner CBC: " + innerCBCEncryptionTime + " ms.");
        System.out.println("Outer CBC: " + outerCBCEncryptionTime + " ms.");
        System.out.println("With pad:  " + padEncryptionTime + " ms.");
    }

    public static void timeTestDecryption(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, ShortBufferException, InvalidAlgorithmParameterException {
        byte[] data = readData(fileName);
        byte[] key = genBytes(3 * ORDINARY_KEY_LENGTH);
        byte[] iv3 = genBytes(3* IV_SIZE);
        byte[] iv1 = Arrays.copyOf(iv3, IV_SIZE /BYTE_LENGTH);

        byte[] encryptedData = tripleEncryptECB(data, key);
        long t = System.currentTimeMillis();
        tripleDecryptECB(encryptedData, key);
        long ECBEncryptionTime = System.currentTimeMillis() - t;

        encryptedData = tripleEncryptCBCInner(data, key, iv3);
        t = System.currentTimeMillis();
        tripleDecryptCBCInner(encryptedData, key, iv3);
        long innerCBCEncryptionTime = System.currentTimeMillis() - t;

        encryptedData = tripleEncryptCBCOuter(data, key, iv1);
        t = System.currentTimeMillis();
        tripleDecryptCBCOuter(encryptedData, key, iv1);
        long outerCBCEncryptionTime = System.currentTimeMillis() - t;

        encryptedData = tripleEncryptWithPad(data, key);
        t = System.currentTimeMillis();
        tripleDecryptWithPad(encryptedData, key);
        long padEncryptionTime = System.currentTimeMillis() - t;

        System.out.println("Decryption");
        System.out.println("ECB:       " + ECBEncryptionTime + " ms.");
        System.out.println("Inner CBC: " + innerCBCEncryptionTime + " ms.");
        System.out.println("Outer CBC: " + outerCBCEncryptionTime + " ms.");
        System.out.println("With pad:  " + padEncryptionTime + " ms.");
    }


    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, ShortBufferException, InvalidAlgorithmParameterException {
        String fileInName = "test\\test1.jpg";
        String fileEOutName = "test\\testE.jpg";
        String fileDOutName = "test\\testD.jpg";

        //ecbTest(fileInName, fileEOutName, fileDOutName);
        //cbcInnerTest(fileInName, fileEOutName, fileDOutName);
        //cbcOuterTest(fileInName, fileEOutName, fileDOutName);
        //withPadTest(fileInName, fileEOutName, fileDOutName);
        timeTestEncryption(fileInName);
        timeTestDecryption(fileInName);
    }
}
