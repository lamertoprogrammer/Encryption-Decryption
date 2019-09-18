package encryptdecrypt;

import java.io.FileWriter;
import java.io.IOException;
import java.util.Scanner;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Main {
    public static void main(String[] args) {
        String mode = "";
        String data = "";
        String in = "";
        String out = "";
        String alg = "";
        int key = 0;
        for (int i = 0; i < args.length - 1; i+=2) {
            switch (args[i]) {
                case "-mode":
                    mode = args[i + 1];
                    break;
                case "-key":
                    key = Integer.parseInt(args[i + 1]);
                    break;
                case "-data":
                    data = args[i + 1];
                    break;
                case "-in":
                    in = args[i + 1];
                    break;
                case "-out":
                    out = args[i + 1];
                    break;
                case "-alg":
                    alg = args[i + 1];
            }
        }

        if (in.isEmpty() && data.isEmpty()) {
            Scanner scanner = new Scanner(System.in);
            data = scanner.nextLine();
        } else {
            try {
                data = new String(Files.readAllBytes(Paths.get(in)));
            } catch (IOException e) {
               System.out.println(e.getMessage());
            }
        }

        if (mode.isEmpty()) {
            mode = "enc";
        }

        CryptAlg algorithm = CryptAlgStaticFactory.getCryptAlgorithm(alg);

        String res = "";

        if ("dec".equals(mode)) {
            res = algorithm.decryptIt(data, key);
        } else if ("enc".equals(mode)) {
            res = algorithm.encryptIt(data, key);
        }
        if (out.isEmpty()) {
            System.out.println(res);
        } else {
            try (FileWriter fileWriter = new FileWriter(out)) {
                fileWriter.write(res);
            } catch (IOException e) {
                System.out.println(e.getMessage());
            }
        }
    }
}
abstract class CryptAlg {

    abstract String encryptIt(String message, int key);

    abstract String decryptIt(String ciphertext, int key);
}

class UnicodeCryptAlg extends CryptAlg {

    @Override
    String encryptIt(String message, int key) {
        char[] cryptMessageAsCharArray = new char[message.length()];
        for (int i = 0; i < message.length(); ++i) {
            cryptMessageAsCharArray[i] = (char) ((message.charAt(i) + key) % ('\uffff' + 1));
        }
        return String.valueOf(cryptMessageAsCharArray);
    }

    @Override
    String decryptIt(String ciphertext, int key) {
        return encryptIt(ciphertext, -key);
    }
}

class ShiftCryptAlg extends CryptAlg {

    @Override
    String encryptIt(String message, int key) {
        key = (key % ('z' - 'a' + 1) + ('z' - 'a' + 1)) % ('z' - 'a' + 1);
        char[] cryptMessageAsCharArray = new char[message.length()];
        for (int i = 0; i < message.length(); ++i) {
            if (Character.isLetter(message.charAt(i))) {
                if (Character.isLowerCase(message.charAt(i))) {
                    cryptMessageAsCharArray[i] = (char) ('a' + (message.charAt(i) - 'a' + key) % ('z' - 'a' + 1));
                } else {
                    cryptMessageAsCharArray[i] = (char) ('A' + (message.charAt(i) - 'A' + key) % ('Z' - 'A' + 1));
                }
            } else {
                cryptMessageAsCharArray[i] = message.charAt(i);
            }
        }
        return String.valueOf(cryptMessageAsCharArray);
    }

    @Override
    String decryptIt(String ciphertext, int key) {
        return encryptIt(ciphertext, -key);
    }
}

class CryptAlgStaticFactory {
    static CryptAlg getCryptAlgorithm(String alg) {
        switch(alg) {
            case "unicode": return new UnicodeCryptAlg();
            case "shift": return new ShiftCryptAlg();
            default: throw new IllegalArgumentException("Incorrect algorithm");
        }
    }
}