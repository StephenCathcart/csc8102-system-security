package uk.co.stephencathcart.system.security;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A class which includes methods for encrypting and decrypting files.
 *
 * @author Stephen Cathcart
 * @version 1.0
 * @since 2017-12-04
 */
public final class Safe {

    /**
     * Logger.
     */
    private static final Logger logger = LoggerFactory.getLogger(Safe.class);

    /**
     * Encrypts a plaintext file with a password and deletes the original file,
     *
     * @param file the plaintext file to encrypt
     * @param password the password used for encrypting the file
     * @throws ApplicationException if there's an error reading file
     */
    public void encrypt(File file, byte[] password) {
        if (FileUtil.isEncrypted(file)) {
            throw new ApplicationException("File is already encrypted");
        }
        File encryptedFile = new File(file.getPath().concat(FileUtil.ENCRYPTED_EXTENSION));

        try {
            KeyChain keys = deriveKeys(password);
            byte[] plaintext = FileUtil.read(file);
            byte[] iv = generateInitialVector();
            byte[] ciphertext = runCryptographicCipher(iv, keys.getAesKey(), plaintext, Cipher.ENCRYPT_MODE);
            byte[] hmac = generateHashedMessageAuthenticationCode(iv, ciphertext, keys.getMacKey());
            byte[] output = concatByteArrays(iv, ciphertext, hmac);

            FileUtil.write(encryptedFile, Base64.getEncoder().encode(output));
            logger.info("Created new encrypted file: {}", encryptedFile.getAbsolutePath());
            FileUtil.delete(file);
            logger.info("Removed the plaintext file: {}", file.getAbsolutePath());
        } catch (IOException ex) {
            throw new ApplicationException("Error reading file");
        }
    }

    /**
     * Decrypts an encrypted file with the given password. Finally it deletes
     * the encrypted file and restores the plaintext file.
     *
     * @param file the encrypted file to decrypt
     * @param password the password used for decrypting the file
     * @throws ApplicationException if there's an error reading file
     */
    public void decrypt(File file, byte[] password) {
        if (!FileUtil.isEncrypted(file)) {
            throw new ApplicationException("File is not encrypted");
        }
        File plaintextFile = new File(file.getPath().replace(FileUtil.ENCRYPTED_EXTENSION, ""));

        try {
            KeyChain keys = deriveKeys(password);
            byte[] encryptedtext = Base64.getDecoder().decode(FileUtil.read(file));
            byte[] iv = Arrays.copyOfRange(encryptedtext, 0, 16);
            byte[] ciphertext = Arrays.copyOfRange(encryptedtext, 16, encryptedtext.length - 20);
            byte[] hmac = Arrays.copyOfRange(encryptedtext, encryptedtext.length - 20, encryptedtext.length);
            byte[] dummyHMAC = generateHashedMessageAuthenticationCode(iv, ciphertext, keys.getMacKey());

            if (!Arrays.equals(hmac, dummyHMAC)) {
                throw new ApplicationException("Wrong password or possibly corrupted file");
            }

            byte[] plaintext = runCryptographicCipher(iv, keys.getAesKey(), ciphertext, Cipher.DECRYPT_MODE);

            FileUtil.write(plaintextFile, plaintext);
            logger.info("Restored the plaintext file: {}", plaintextFile.getAbsolutePath());
            FileUtil.delete(file);
            logger.info("Removed the encrypted file: {}", file.getAbsolutePath());
        } catch (IOException ex) {
            throw new ApplicationException("Error reading file");
        }
    }

    /**
     * Derives a 16-byte AES Key and a 16-byte MAC Key from the data to be
     * digested.
     *
     * @param data the input to be hashed, updated and digested
     * @return a wrapper object to hold the AES Key and MAC Key
     * @throws ApplicationException if the keys cannot be derived
     */
    private KeyChain deriveKeys(byte[] data) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(data);
            byte[] aesKey = Arrays.copyOfRange(hash, 0, 16);
            byte[] macKey = Arrays.copyOfRange(hash, 16, 32);
            return new KeyChain(aesKey, macKey);
        } catch (NoSuchAlgorithmException ex) {
            throw new ApplicationException("Error deriving keys");
        }
    }

    /**
     * Uses a secure random number generator to create a 16-byte block of
     * initial data (IV) to be used for the CBC.
     *
     * @return a 16-byte random IV
     */
    private byte[] generateInitialVector() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    /**
     * Generates either plaintext or ciphertext depending on Ciper mode
     * supplied. As stated in the coursework, it uses AES in the CBC mode with
     * the PKC5 padding scheme to encrypt data.
     *
     * @param iv 16-byte random data
     * @param key 16-byte AES key
     * @param plaintext plaintext bytes to encrypt
     * @return plaintext or ciphertext
     * @throws ApplicationException if the cipher operation fails
     */
    private byte[] runCryptographicCipher(byte[] iv, byte[] aesKey, byte[] ciphertext, int mode) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(mode, new SecretKeySpec(aesKey, "AES"), new IvParameterSpec(iv));
            return cipher.doFinal(ciphertext);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
            | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException ex) {
            throw new ApplicationException("Error generating plaintext");
        }
    }

    /**
     * Generates a HMAC signature used to verify that the data has not been
     * tampered with. As the MAC algorithm is SHA1, the hash value will be
     * 20-bytes.
     *
     * @param iv the initial vector
     * @param ciphertext the ciphertext
     * @param macKey the MAC Key
     * @return the HMAC to be used to verify the data
     * @throws ApplicationException if the MAC operation fails
     */
    private byte[] generateHashedMessageAuthenticationCode(byte[] iv, byte[] ciphertext, byte[] macKey) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(macKey, "HmacSHA1"));
            return mac.doFinal(concatByteArrays(iv, ciphertext));
        } catch (InvalidKeyException | NoSuchAlgorithmException ex) {
            throw new ApplicationException("Error generating HMAC");
        }
    }

    /**
     * Concatenates a given list of byte arrays (such as IV, ciphertext or HMAC)
     * in to one byte array.
     *
     * @param arrays the byte arrays to concatenate
     * @return a single byte array of concatenated byte arrays
     * @throws ApplicationException if the concatenation fails
     */
    private static byte[] concatByteArrays(byte[]... arrays) {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            for (byte[] array : arrays) {
                outputStream.write(array);
            }
            return outputStream.toByteArray();
        } catch (IOException ex) {
            throw new ApplicationException("Error concatenating byte arrays");
        }
    }
}
