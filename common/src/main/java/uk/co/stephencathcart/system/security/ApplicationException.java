package uk.co.stephencathcart.system.security;

/**
 * A general catch all application exception.
 *
 * @author Stephen Cathcart
 * @version 1.0
 * @since 2017-12-04
 */
public final class ApplicationException extends RuntimeException {

    /**
     * Constructor.
     *
     * @param message the error message
     */
    public ApplicationException(String message) {
        super(message);
    }
}
