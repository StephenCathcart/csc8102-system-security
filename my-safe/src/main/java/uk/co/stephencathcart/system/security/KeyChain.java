package uk.co.stephencathcart.system.security;

/**
 * A POJO to temporarily hold an AES Key and MAC Key generated from a password.
 *
 * @author Stephen Cathcart
 * @version 1.0
 * @since 2017-12-04
 */
public final class KeyChain {

    /**
     * The generated AES Key.
     */
    private final byte[] aesKey;
    /**
     * The generated MAC Key.
     */
    private final byte[] macKey;

    /**
     * Constructor.
     *
     * @param aesKey the AES Key
     * @param macKey the MAC Key
     */
    public KeyChain(byte[] aesKey, byte[] macKey) {
        this.aesKey = aesKey;
        this.macKey = macKey;
    }

    /**
     * Get the AES Key.
     *
     * @return the AES Key
     */
    public byte[] getAesKey() {
        return aesKey;
    }

    /**
     * Get the MAC Key.
     *
     * @return the MAC Key
     */
    public byte[] getMacKey() {
        return macKey;
    }
}
