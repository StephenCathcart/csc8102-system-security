package uk.co.stephencathcart.system.security;

import org.apache.commons.cli.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Main launcher for the application.
 *
 * @author Stephen Cathcart
 * @version 1.0
 * @since 2017-12-04
 */
public class Launcher {

    /**
     * Logger.
     */
    private static final Logger logger = LoggerFactory.getLogger(Launcher.class);

    /**
     * Applications main method. Checks if we are encrypting or decrypting then
     * calls the relevant Safe method. Any errors will be printed to console. If
     * the options supplied are invalid print help to the console.
     *
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        CommandLineOptions clo = new CommandLineOptions(args);
        clo.addOption("e", "encrypt", true, "encrypt file");
        clo.addOption("d", "decrypt", true, "decrypt file");

        Safe safe = new Safe();
        try {
            clo.build();
            byte[] password = FileUtil.readPassword();

            if (clo.hasOption('e')) {
                safe.encrypt(FileUtil.create(clo.getOptionValue('e')), password);
            } else if (clo.hasOption('d')) {
                safe.decrypt(FileUtil.create(clo.getOptionValue('d')), password);
            }
        } catch (ApplicationException ex) {
            logger.error(ex.getMessage());
        } catch (ParseException ex) {
            clo.printHelp("java -jar my-safe");
        }
    }
}
