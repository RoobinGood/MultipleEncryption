import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class Main {

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



    public static byte[] tripleEncryptECB(byte[] data, byte[] key) {
        byte[] result = new byte[data.length];


        return result;
    }

    public static void main(String[] args) {

    }
}
