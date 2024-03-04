import java.io.*;
import java.net.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/*
 * Converting for Byte and Hex: https://www.baeldung.com/java-byte-arrays-hex-strings
 */
public class Gen {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        KeyPair alice_keys = generator.generateKeyPair();
        KeyPair bob_keys = generator.generateKeyPair();
        KeyPair alice_mackeys = generator.generateKeyPair();
        KeyPair bob_mackeys = generator.generateKeyPair();
        byte[] pub_header = "-----BEGIN PUBLIC KEY-----".getBytes();
        byte[] pub_footer = "-----END PUBLIC KEY-----".getBytes();
        byte[] priv_header = "-----BEGIN PRIVATE KEY-----".getBytes();
        byte[] priv_footer = "-----END PRIVATE KEY-----".getBytes();

        Path alice_public = Paths.get("a_public.pem");
        Files.write(alice_public, pub_header);
        Files.write(alice_public,
                Base64.getEncoder().encode(alice_keys.getPublic().getEncoded()), StandardOpenOption.APPEND);
        Files.write(alice_public, pub_footer, StandardOpenOption.APPEND);

        Path alice_private = Paths.get("a_private.pem");
        Files.write(alice_private, priv_header);
        Files.write(alice_private,
                Base64.getEncoder().encode(alice_keys.getPrivate().getEncoded()), StandardOpenOption.APPEND);
        Files.write(alice_private, priv_footer, StandardOpenOption.APPEND);

        Path alice_macpublic = Paths.get("a_macpublic.pem");
        Files.write(alice_macpublic, pub_header);
        Files.write(alice_macpublic,
                Base64.getEncoder().encode(alice_mackeys.getPublic().getEncoded()), StandardOpenOption.APPEND);
        Files.write(alice_macpublic, pub_footer, StandardOpenOption.APPEND);

        Path alice_macprivate = Paths.get("a_macprivate.pem");
        Files.write(alice_macprivate, priv_header);
        Files.write(alice_macprivate,
                Base64.getEncoder().encode(alice_mackeys.getPrivate().getEncoded()), StandardOpenOption.APPEND);
        Files.write(alice_macprivate, priv_footer, StandardOpenOption.APPEND);

        Path bob_public = Paths.get("b_public.pem");
        Files.write(bob_public, pub_header);
        Files.write(bob_public, Base64.getEncoder().encode(bob_keys.getPublic().getEncoded()),
                StandardOpenOption.APPEND);
        Files.write(bob_public, pub_footer, StandardOpenOption.APPEND);

        Path bob_private = Paths.get("b_private.pem");
        Files.write(bob_private, priv_header);
        Files.write(bob_private, Base64
                .getEncoder().encode(bob_keys.getPrivate().getEncoded()),
                StandardOpenOption.APPEND);
        Files.write(bob_private, priv_footer, StandardOpenOption.APPEND);

        Path bob_macpublic = Paths.get("b_macpublic.pem");
        Files.write(bob_macpublic, pub_header);
        Files.write(bob_macpublic, Base64.getEncoder().encode(bob_mackeys.getPublic().getEncoded()),
                StandardOpenOption.APPEND);
        Files.write(bob_macpublic, pub_footer, StandardOpenOption.APPEND);

        Path bob_macprivate = Paths.get("b_macprivate.pem");
        Files.write(bob_macprivate, priv_header);
        Files.write(bob_macprivate, Base64.getEncoder().encode(bob_mackeys.getPrivate().getEncoded()),
                StandardOpenOption.APPEND);
        Files.write(bob_macprivate, priv_footer, StandardOpenOption.APPEND);

    }

    public static RSAPrivateKey readPKCS8PrivateKey(File file) throws Exception {

        // reads from file
        String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

        // has to do with formatting of pem file
        String privateKeyPEM = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");

        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // tells what rule is beng used

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec); // should be key form
    }

    public static RSAPublicKey readPKCS8PublicKey(File file) throws Exception {

        // reads from file
        String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

        // has to do with formatting of pem file
        String publicKeyPEM = key
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "");

        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // tells what rule is beng used
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec); // should be key form
    }

    public static String encodeHexString(byte[] byteArray) {
        StringBuffer hexStringBuffer = new StringBuffer();
        for (int i = 0; i < byteArray.length; i++) {
            hexStringBuffer.append(byteToHex(byteArray[i]));
        }
        return hexStringBuffer.toString();
    }

    public static String byteToHex(byte num) {
        char[] hexDigits = new char[2];
        hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
        hexDigits[1] = Character.forDigit((num & 0xF), 16);
        return new String(hexDigits);
    }

    public static byte hexToByte(String hexString) {
        int firstDigit = toDigit(hexString.charAt(0));
        int secondDigit = toDigit(hexString.charAt(1));
        return (byte) ((firstDigit << 4) + secondDigit);
    }

    private static int toDigit(char hexChar) {
        int digit = Character.digit(hexChar, 16);
        if (digit == -1) {
            throw new IllegalArgumentException(
                    "Invalid Hexadecimal Character: " + hexChar);
        }
        return digit;
    }

    public static byte[] decodeHexString(String hexString) {
        if (hexString.length() % 2 == 1) {
            throw new IllegalArgumentException(
                    "Invalid hexadecimal String supplied.");
        }

        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < hexString.length(); i += 2) {
            bytes[i / 2] = hexToByte(hexString.substring(i, i + 2));
        }
        return bytes;
    }

}
