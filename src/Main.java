import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

public class Main {
    public static final String CIPHER_ALGORITHM = "DES";
    public static final String ECB_CHAIN_MODE = "ECB";
    public static final String CBC_CHAIN_MODE = "CBC";
    public static final String CIPHER_PADDING = "PKCS5Padding";
    public static final String NO_PADDING = "NoPadding";
    public static final String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";
    public static final int ORDINARY_KEY_SIZE = 64;
    public static final int IV_SIZE = 64;
    public static final int BLOCK_SIZE = 64;
    public static final int BYTE_SIZE = 8;

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

    public static byte[] addPadding(byte[] data) {
        int blockNum = data.length/(BLOCK_SIZE / BYTE_SIZE);
        int length = ( (data.length%(BLOCK_SIZE / BYTE_SIZE) == 0) ? blockNum : blockNum+1 )*(BLOCK_SIZE / BYTE_SIZE);

        byte[] result = new byte[length];
        int padSize = data.length%(BLOCK_SIZE / BYTE_SIZE);
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
        return tripleEncryptECB(data, Arrays.copyOfRange(key, 0, ORDINARY_KEY_SIZE / BYTE_SIZE),
                Arrays.copyOfRange(key, ORDINARY_KEY_SIZE / BYTE_SIZE, 2* ORDINARY_KEY_SIZE / BYTE_SIZE),
                Arrays.copyOfRange(key, 2* ORDINARY_KEY_SIZE / BYTE_SIZE, 3* ORDINARY_KEY_SIZE / BYTE_SIZE));
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
        return tripleDecryptECB(data, Arrays.copyOfRange(key, 0, ORDINARY_KEY_SIZE / BYTE_SIZE),
                Arrays.copyOfRange(key, ORDINARY_KEY_SIZE / BYTE_SIZE, 2 * ORDINARY_KEY_SIZE / BYTE_SIZE),
                Arrays.copyOfRange(key, 2 * ORDINARY_KEY_SIZE / BYTE_SIZE, 3 * ORDINARY_KEY_SIZE / BYTE_SIZE));
    }

    public static byte[] genBytes(int bitLength) throws NoSuchAlgorithmException {
        SecureRandom secureRandom = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM);
        byte[] key = new byte[bitLength/ BYTE_SIZE];
        secureRandom.nextBytes(key);
        return key;
    }


    // CBC: inner
    public static byte[] tripleEncryptCBCInner(byte[] data, byte[] key1, byte[] key2, byte[] key3,
                                               byte[] iv1, byte[] iv2, byte[] iv3) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {
        byte[] result = addPadding(data);
        int blockNum = result.length/(BLOCK_SIZE / BYTE_SIZE);


        Cipher cipher1 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + CBC_CHAIN_MODE + "/" + NO_PADDING);
        cipher1.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key1, CIPHER_ALGORITHM), new IvParameterSpec(iv1));
        Cipher cipher2 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + CBC_CHAIN_MODE + "/" + NO_PADDING);
        cipher2.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key2, CIPHER_ALGORITHM), new IvParameterSpec(iv2));
        Cipher cipher3 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + CBC_CHAIN_MODE + "/" + NO_PADDING);
        cipher3.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key3, CIPHER_ALGORITHM), new IvParameterSpec(iv3));

        for (int i=0; i<blockNum-1; i++) {
            cipher1.update(result, i*(BLOCK_SIZE / BYTE_SIZE), BLOCK_SIZE / BYTE_SIZE, result, i*(BLOCK_SIZE / BYTE_SIZE));
            cipher2.update(result, i*(BLOCK_SIZE / BYTE_SIZE), BLOCK_SIZE / BYTE_SIZE, result, i*(BLOCK_SIZE / BYTE_SIZE));
            cipher3.update(result, i*(BLOCK_SIZE / BYTE_SIZE), BLOCK_SIZE / BYTE_SIZE, result, i*(BLOCK_SIZE / BYTE_SIZE));
        }
        cipher1.doFinal(result, (blockNum-1)*(BLOCK_SIZE / BYTE_SIZE), BLOCK_SIZE / BYTE_SIZE,
                result, (blockNum-1)*(BLOCK_SIZE / BYTE_SIZE));
        cipher2.doFinal(result, (blockNum-1)*(BLOCK_SIZE / BYTE_SIZE), BLOCK_SIZE / BYTE_SIZE,
                result, (blockNum-1)*(BLOCK_SIZE / BYTE_SIZE));
        cipher3.doFinal(result, (blockNum-1)*(BLOCK_SIZE / BYTE_SIZE), BLOCK_SIZE / BYTE_SIZE,
                result, (blockNum-1)*(BLOCK_SIZE / BYTE_SIZE));

        return result;
    }

    public static byte[] tripleEncryptCBCInner(byte[] data, byte[] key, byte[] iv) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException, InvalidAlgorithmParameterException {
        return tripleEncryptCBCInner(data, Arrays.copyOfRange(key, 0, ORDINARY_KEY_SIZE / BYTE_SIZE),
                Arrays.copyOfRange(key, ORDINARY_KEY_SIZE / BYTE_SIZE, 2 * ORDINARY_KEY_SIZE / BYTE_SIZE),
                Arrays.copyOfRange(key, 2 * ORDINARY_KEY_SIZE / BYTE_SIZE, 3 * ORDINARY_KEY_SIZE / BYTE_SIZE),
                Arrays.copyOfRange(iv, 0, ORDINARY_KEY_SIZE / BYTE_SIZE),
                Arrays.copyOfRange(iv, ORDINARY_KEY_SIZE / BYTE_SIZE, 2 * ORDINARY_KEY_SIZE / BYTE_SIZE),
                Arrays.copyOfRange(iv, 2 * ORDINARY_KEY_SIZE / BYTE_SIZE, 3 * ORDINARY_KEY_SIZE / BYTE_SIZE));
    }

    public static byte[] tripleDecryptCBCInner(byte[] data, byte[] key1, byte[] key2, byte[] key3,
                                               byte[] iv1, byte[] iv2, byte[] iv3) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {
        int blockNum = data.length/(BLOCK_SIZE / BYTE_SIZE);
        byte[] result = new byte[data.length];

        Cipher cipher1 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + CBC_CHAIN_MODE + "/" + NO_PADDING);
        cipher1.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key1, CIPHER_ALGORITHM), new IvParameterSpec(iv1));
        Cipher cipher2 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + CBC_CHAIN_MODE + "/" + NO_PADDING);
        cipher2.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key2, CIPHER_ALGORITHM), new IvParameterSpec(iv2));
        Cipher cipher3 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + CBC_CHAIN_MODE + "/" + NO_PADDING);
        cipher3.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key3, CIPHER_ALGORITHM), new IvParameterSpec(iv3));

        for (int i=0; i<blockNum-1; i++) {
            cipher3.update(data, i*(BLOCK_SIZE / BYTE_SIZE), BLOCK_SIZE / BYTE_SIZE, result, i*(BLOCK_SIZE / BYTE_SIZE));
            cipher2.update(result, i*(BLOCK_SIZE / BYTE_SIZE), BLOCK_SIZE / BYTE_SIZE, result, i*(BLOCK_SIZE / BYTE_SIZE));
            cipher1.update(result, i*(BLOCK_SIZE / BYTE_SIZE), BLOCK_SIZE / BYTE_SIZE, result, i*(BLOCK_SIZE / BYTE_SIZE));
        }
        cipher3.doFinal(data, (blockNum-1)*(BLOCK_SIZE / BYTE_SIZE), BLOCK_SIZE / BYTE_SIZE,
                result, (blockNum-1)*(BLOCK_SIZE / BYTE_SIZE));
        cipher2.doFinal(result, (blockNum-1) * (BLOCK_SIZE / BYTE_SIZE), BLOCK_SIZE / BYTE_SIZE,
                result, (blockNum-1) * (BLOCK_SIZE / BYTE_SIZE));
        cipher1.doFinal(result, (blockNum-1)*(BLOCK_SIZE / BYTE_SIZE), BLOCK_SIZE / BYTE_SIZE,
                result, (blockNum-1)*(BLOCK_SIZE / BYTE_SIZE));

        return delPadding(result);
    }

    public static byte[] tripleDecryptCBCInner(byte[] data, byte[] key, byte[] iv) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException, InvalidAlgorithmParameterException {
        return tripleDecryptCBCInner(data, Arrays.copyOfRange(key, 0, ORDINARY_KEY_SIZE / BYTE_SIZE),
                Arrays.copyOfRange(key, ORDINARY_KEY_SIZE / BYTE_SIZE, 2 * ORDINARY_KEY_SIZE / BYTE_SIZE),
                Arrays.copyOfRange(key, 2 * ORDINARY_KEY_SIZE / BYTE_SIZE, 3 * ORDINARY_KEY_SIZE / BYTE_SIZE),
                Arrays.copyOfRange(iv, 0, ORDINARY_KEY_SIZE / BYTE_SIZE),
                Arrays.copyOfRange(iv, ORDINARY_KEY_SIZE / BYTE_SIZE, 2 * ORDINARY_KEY_SIZE / BYTE_SIZE),
                Arrays.copyOfRange(iv, 2 * ORDINARY_KEY_SIZE / BYTE_SIZE, 3 * ORDINARY_KEY_SIZE / BYTE_SIZE));
    }


    // CBC: outer
    public static byte[] tripleEncryptCBCOuter(byte[] data, byte[] key1, byte[] key2, byte[] key3,
                                               byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {
        byte[] result = addPadding(data);
        int blockNum = data.length/(BLOCK_SIZE / BYTE_SIZE);

        Cipher cipher1 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + ECB_CHAIN_MODE + "/" + NO_PADDING);
        cipher1.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key1, CIPHER_ALGORITHM));
        Cipher cipher2 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + ECB_CHAIN_MODE + "/" + NO_PADDING);
        cipher2.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key2, CIPHER_ALGORITHM));
        Cipher cipher3 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + ECB_CHAIN_MODE + "/" + NO_PADDING);
        cipher3.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key3, CIPHER_ALGORITHM));

        byte[] currentIv = Arrays.copyOf(iv, iv.length);
        for (int i=0; i<blockNum-1; i++) {
            result = arrXor(result, i*(BLOCK_SIZE / BYTE_SIZE), currentIv);
            cipher1.update(result, i*(BLOCK_SIZE / BYTE_SIZE), BLOCK_SIZE / BYTE_SIZE,
                    result, i*(BLOCK_SIZE / BYTE_SIZE));
            cipher2.update(result, i*(BLOCK_SIZE / BYTE_SIZE), BLOCK_SIZE / BYTE_SIZE,
                    result, i*(BLOCK_SIZE / BYTE_SIZE));
            cipher3.update(result, i*(BLOCK_SIZE / BYTE_SIZE), BLOCK_SIZE / BYTE_SIZE,
                    result, i*(BLOCK_SIZE / BYTE_SIZE));
            currentIv = Arrays.copyOfRange(result, i*(BLOCK_SIZE / BYTE_SIZE),
                    (i + 1)*(BLOCK_SIZE / BYTE_SIZE));
        }
        result = arrXor(result, (blockNum-1)*(BLOCK_SIZE / BYTE_SIZE), currentIv);
        cipher1.doFinal(result, (blockNum-1)*(BLOCK_SIZE / BYTE_SIZE), BLOCK_SIZE / BYTE_SIZE,
                result, (blockNum-1)*(BLOCK_SIZE / BYTE_SIZE));
        cipher2.doFinal(result, (blockNum-1)*(BLOCK_SIZE / BYTE_SIZE), BLOCK_SIZE / BYTE_SIZE,
                result, (blockNum-1)*(BLOCK_SIZE / BYTE_SIZE));
        cipher3.doFinal(result, (blockNum-1)*(BLOCK_SIZE / BYTE_SIZE), BLOCK_SIZE / BYTE_SIZE,
                result, (blockNum-1)*(BLOCK_SIZE / BYTE_SIZE));

        return result;
    }

    public static byte[] tripleEncryptCBCOuter(byte[] data, byte[] key, byte[] iv) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException, InvalidAlgorithmParameterException {
        return tripleEncryptCBCOuter(data, Arrays.copyOfRange(key, 0, ORDINARY_KEY_SIZE / BYTE_SIZE),
                Arrays.copyOfRange(key, ORDINARY_KEY_SIZE / BYTE_SIZE, 2 * ORDINARY_KEY_SIZE / BYTE_SIZE),
                Arrays.copyOfRange(key, 2 * ORDINARY_KEY_SIZE / BYTE_SIZE, 3 * ORDINARY_KEY_SIZE / BYTE_SIZE),
                iv);
    }

    public static byte[] tripleDecryptCBCOuter(byte[] data, byte[] key1, byte[] key2, byte[] key3,
                                               byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {
        int blockNum = data.length/(BLOCK_SIZE / BYTE_SIZE);
        byte[] result = Arrays.copyOf(data, data.length);

        Cipher cipher1 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + ECB_CHAIN_MODE + "/" + NO_PADDING);
        cipher1.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key1, CIPHER_ALGORITHM));
        Cipher cipher2 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + ECB_CHAIN_MODE + "/" + NO_PADDING);
        cipher2.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key2, CIPHER_ALGORITHM));
        Cipher cipher3 = Cipher.getInstance(CIPHER_ALGORITHM + "/" + ECB_CHAIN_MODE + "/" + NO_PADDING);
        cipher3.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key3, CIPHER_ALGORITHM));

        byte[] currentIv = Arrays.copyOf(iv, iv.length);
        for (int i=0; i<blockNum-1; i++) {
            byte[] nextIv = Arrays.copyOfRange(result, i*(BLOCK_SIZE / BYTE_SIZE),
                    (i + 1)*(BLOCK_SIZE / BYTE_SIZE));
            cipher3.update(result, i*(BLOCK_SIZE / BYTE_SIZE), BLOCK_SIZE / BYTE_SIZE,
                    result, i*(BLOCK_SIZE / BYTE_SIZE));
            cipher2.update(result, i*(BLOCK_SIZE / BYTE_SIZE), BLOCK_SIZE / BYTE_SIZE,
                    result, i*(BLOCK_SIZE / BYTE_SIZE));
            cipher1.update(result, i*(BLOCK_SIZE / BYTE_SIZE), BLOCK_SIZE / BYTE_SIZE,
                    result, i*(BLOCK_SIZE / BYTE_SIZE));
            result = arrXor(result, i*(BLOCK_SIZE / BYTE_SIZE), currentIv);
            currentIv = Arrays.copyOf(nextIv, nextIv.length);
        }
        result = arrXor(result, blockNum*(BLOCK_SIZE / BYTE_SIZE), currentIv);
        cipher3.doFinal(data, (blockNum-1)*(BLOCK_SIZE / BYTE_SIZE), BLOCK_SIZE / BYTE_SIZE,
                result, (blockNum-1)*(BLOCK_SIZE / BYTE_SIZE));
        cipher2.doFinal(result, (blockNum-1) * (BLOCK_SIZE / BYTE_SIZE), BLOCK_SIZE / BYTE_SIZE,
                result, (blockNum-1) * (BLOCK_SIZE / BYTE_SIZE));
        cipher1.doFinal(result, (blockNum-1)*(BLOCK_SIZE / BYTE_SIZE), BLOCK_SIZE / BYTE_SIZE,
                result, (blockNum-1)*(BLOCK_SIZE / BYTE_SIZE));

        return delPadding(result);
    }

    public static byte[] tripleDecryptCBCOuter(byte[] data, byte[] key, byte[] iv) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException, InvalidAlgorithmParameterException {
        return tripleDecryptCBCOuter(data, Arrays.copyOfRange(key, 0, ORDINARY_KEY_SIZE / BYTE_SIZE),
                Arrays.copyOfRange(key, ORDINARY_KEY_SIZE / BYTE_SIZE, 2 * ORDINARY_KEY_SIZE / BYTE_SIZE),
                Arrays.copyOfRange(key, 2 * ORDINARY_KEY_SIZE / BYTE_SIZE, 3 * ORDINARY_KEY_SIZE / BYTE_SIZE),
                iv);
    }


    // With pad
    public static byte[] addPad(byte[] data) throws NoSuchAlgorithmException {
        SecureRandom secureRandom = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM);
        byte[] pad = new byte[BLOCK_SIZE / BYTE_SIZE / 2];
        secureRandom.nextBytes(pad);
        return arrCat(pad, data);
    }

    public static byte[] delPad(byte[] data) {
        return Arrays.copyOfRange(data, BLOCK_SIZE / BYTE_SIZE / 2, data.length);
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
        return tripleEncryptWithPad(data, Arrays.copyOfRange(key, 0, ORDINARY_KEY_SIZE / BYTE_SIZE),
                Arrays.copyOfRange(key, ORDINARY_KEY_SIZE / BYTE_SIZE, 2 * ORDINARY_KEY_SIZE / BYTE_SIZE),
                Arrays.copyOfRange(key, 2 * ORDINARY_KEY_SIZE / BYTE_SIZE, 3 * ORDINARY_KEY_SIZE / BYTE_SIZE));
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
        return tripleDecryptWithPad(data, Arrays.copyOfRange(key, 0, ORDINARY_KEY_SIZE / BYTE_SIZE),
                Arrays.copyOfRange(key, ORDINARY_KEY_SIZE / BYTE_SIZE, 2 * ORDINARY_KEY_SIZE / BYTE_SIZE),
                Arrays.copyOfRange(key, 2 * ORDINARY_KEY_SIZE / BYTE_SIZE, 3 * ORDINARY_KEY_SIZE / BYTE_SIZE));
    }


    // Time test
    public static void timeTestEncryption(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, ShortBufferException, InvalidAlgorithmParameterException {
        byte[] data = readData(fileName);
        byte[] key = genBytes(3 * ORDINARY_KEY_SIZE);
        byte[] iv3 = genBytes(3* IV_SIZE);
        byte[] iv1 = Arrays.copyOf(iv3, IV_SIZE / BYTE_SIZE);

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
        byte[] key = genBytes(3 * ORDINARY_KEY_SIZE);
        byte[] iv3 = genBytes(3* IV_SIZE);
        byte[] iv1 = Arrays.copyOf(iv3, IV_SIZE / BYTE_SIZE);

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

    public static String getFileName(String requiredFile, boolean shouldExist) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter " + requiredFile + " file name:");
        String fInName = scanner.nextLine();
        if (shouldExist)
            while (!(new File(fInName).exists())) {
                System.out.println("File does not exit. \nEnter " + requiredFile + " file name:");
                fInName = scanner.nextLine();
            }
        return fInName;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, ShortBufferException, InvalidAlgorithmParameterException {
        Scanner scanner = new Scanner(System.in);
        String cipherMode;
        System.out.println("Enter what do You want to do\n    1 - gen key\n    2 - encode\n    3 - decode\n    4 - time test");
        switch (scanner.nextLine().charAt(0)) {
            case '1':
                System.out.println("Enter cipher mode \n    1 - ECB\n    2 - inner CBC\n    3 - outer CBC\n    4 - with pad");
                cipherMode = scanner.nextLine();
                writeData(getFileName("output", false), genBytes(3 * ORDINARY_KEY_SIZE));
                switch (cipherMode.charAt(0)) {
                    case '2':
                        writeData(getFileName("iv", false), genBytes(3 * IV_SIZE));
                        break;
                    case '3':
                        writeData(getFileName("iv", false), genBytes(IV_SIZE));
                        break;
                    default:
                        System.out.println("Wrong argument");
                        break;
                }
                break;
            case '2':
                System.out.println("Enter cipher mode \n    1 - ECB\n    2 - inner CBC\n    3 - outer CBC\n    4 - with pad");
                cipherMode = scanner.nextLine();
                switch (cipherMode.charAt(0)) {
                    case '1':
                        writeData(getFileName("output", false), tripleEncryptECB(readData(getFileName("input", true)),
                                readData(getFileName("key", true))));
                        break;
                    case '2':
                        writeData(getFileName("output", false), tripleEncryptCBCInner(readData(getFileName("input", true)),
                                readData(getFileName("key", true)), readData(getFileName("iv", true))));
                        break;
                    case '3':
                        writeData(getFileName("output", false), tripleEncryptCBCOuter(readData(getFileName("input", true)),
                                readData(getFileName("key", true)), readData(getFileName("iv", true))));
                        break;
                    case '4':
                        writeData(getFileName("output", false), tripleEncryptWithPad(readData(getFileName("input", true)),
                                readData(getFileName("key", true))));
                        break;
                    default:
                        System.out.println("Wrong argument");
                        break;
                }
                break;
            case '3':
                System.out.println("Enter cipher mode \n    1 - ECB\n    2 - inner CBC\n    3 - outer CBC\n    4 - with pad");
                cipherMode = scanner.nextLine();
                switch (cipherMode.charAt(0)) {
                    case '1':
                        writeData(getFileName("output", false), tripleDecryptECB(readData(getFileName("input", true)),
                                readData(getFileName("key", true))));
                        break;
                    case '2':
                        writeData(getFileName("output", false), tripleDecryptCBCInner(readData(getFileName("input", true)),
                                readData(getFileName("key", true)), readData(getFileName("iv", true))));
                        break;
                    case '3':
                        writeData(getFileName("output", false), tripleDecryptCBCOuter(readData(getFileName("input", true)),
                                readData(getFileName("key", true)), readData(getFileName("iv", true))));
                        break;
                    case '4':
                        writeData(getFileName("output", false), tripleDecryptWithPad(readData(getFileName("input", true)),
                                readData(getFileName("key", true))));
                        break;
                    default:
                        System.out.println("Wrong argument");
                        break;
                }
                break;
            case '4':
                String fileInName = getFileName("input", true);
                timeTestEncryption(fileInName);
                timeTestDecryption(fileInName);
                break;
            default:
                System.out.println("Wrong argument");
                break;
        }
    }
}
