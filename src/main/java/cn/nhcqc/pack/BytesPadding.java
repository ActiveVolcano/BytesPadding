package cn.nhcqc.pack;

import java.security.SecureRandom;
import java.util.*;

/**
 * Tiny bytes padding library.
 * @author CHEN Qingcan
 */
public class BytesPadding {

	//------------------------------------------------------------------------
    /**
     * PKCS #5 padding, same as padPKCS7 (original, 8).
     * <ul>
     * <li>Returns a new array containing padded bytes in normal cases.
     * <li>Returns null if {original} is null.
     * </ul>
     * @param   original    Bytes to be padded.
     * @return              Padded bytes.
     */
    public static byte[] padPKCS5 (final byte[] original) {
        return padPKCS7 (original, 8);
    }

    /**
     * PKCS #7 padding.
     * <ul>
     * <li>Returns a new array containing padded bytes in normal cases.
     * <li>Returns the {original} itself if {original} is null, or {lenBlock} is not positive.
     * </ul>
     * @param   original    Bytes to be padded.
     * @param   lenBlock    Block length in bytes. e.g. 16 for China SM4 and USA AES.
     * @return              Padded bytes.
     */
    public static byte[] padPKCS7 (final byte[] original, final int lenBlock) {
        if (original == null || lenBlock <= 0) return original;
        int lenOri   = original.length;
        int lenPad   = lenBlock - lenOri % lenBlock;
        int lenPKCS7 = lenOri + lenPad;
        byte[] pkcs7 = Arrays.copyOf (original, lenPKCS7);
        Arrays.fill  (pkcs7, lenOri, lenPKCS7, (byte) lenPad);
        return pkcs7;
    }

    //------------------------------------------------------------------------
    /** Which random class will be used. */
    public static enum FlagRandom {
        /** java.util.Random, fast, less secure. */
        PSEUDO,
        /** java.security.SecureRandom, slow, cryptographically strong. */
        SECURE,
    }

    /**
     * ISO 10126 padding, same as padISO10126 (original, lenBlock, FlagRandom.PSEUDO).
     * <ul>
     * <li>Returns a new array containing padded bytes in normal cases.
     * <li>Returns the {original} itself if {original} is null, or {lenBlock} is not positive.
     * </ul>
     * @param   original    Bytes to be padded.
     * @param   lenBlock    Block length in bytes. e.g. 16 for China SM4 and USA AES.
     * @return              Padded bytes.
     */
    public static byte[] padISO10126 (final byte[] original, final int lenBlock) {
        return padISO10126 (original, lenBlock, FlagRandom.PSEUDO);
    }

    /**
     * ISO 10126 padding.
     * <ul>
     * <li>Returns a new array containing padded bytes in normal cases.
     * <li>Returns the {original} itself if {original} is null, or {lenBlock} is not positive.
     * </ul>
     * @param   original    Bytes to be padded.
     * @param   lenBlock    Block length in bytes. e.g. 16 for China SM4 and USA AES.
     * @param   flagRandom  Which random class will be used.
     * @return              Padded bytes.
     */
    public static byte[] padISO10126 (final byte[] original, final int lenBlock, final FlagRandom flagRandom) {
        if (original == null || lenBlock <= 0) return original;
        int lenOri   = original.length;
        int lenPad   = lenBlock - lenOri % lenBlock;
        int lenISO   = lenOri + lenPad;
        byte[] iso   = Arrays.copyOf (original, lenISO);

        byte[] rand  = new byte [lenPad - 1];
        (flagRandom == FlagRandom.PSEUDO ? new Random () : new SecureRandom ()).nextBytes (rand);
        System.arraycopy (rand, 0, iso, lenOri, rand.length);

        iso [lenISO - 1] = (byte) lenPad;
        return iso;
    }

    //------------------------------------------------------------------------
    /**
     * Zero padding.
     * <ul>
     * <li>Returns a new array containing padded bytes in normal cases.
     * <li>Returns the {original} itself if {original} is null, or {lenBlock} is not positive.
     * </ul>
     * @param   original    Bytes to be padded.
     * @param   lenBlock    Block length in bytes. e.g. 16 for China SM4 and USA AES.
     * @return              Padded bytes.
     */
    public static byte[] padZero (final byte[] original, final int lenBlock) {
        if (original == null || lenBlock <= 0) return original;
        int lenOri   = original.length;
        int lenPad   = lenBlock - lenOri % lenBlock;
        int lenZero  = lenOri + lenPad;
        byte[] zero  = Arrays.copyOf (original, lenZero);
        return zero;
    }

    //------------------------------------------------------------------------
    /** How to deal with the tail zero byte when unpadding. */
    public static enum FlagTailZero {
        /** Removes all tail zero bytes. */
        REMOVE_ALL,
        /** Keeps a tail zero byte. */
        KEEP_ONE,
    }

    /**
     * Unpadding PKCS #5 / PKCS #7 / ISO 10126 / zero padded bytes,
     * removing all tail zero bytes if the original is zero padded,
     * same as unpadZero (original, FlagTailZero.REMOVE_ALL).
     * <ul>
     * <li>Returns a new array containing unpadded bytes in normal cases.
     * <li>Returns the {original} itself if {original} is null or empty array,
     *     or {original} size is less than the padding value.
     * </ul>
     * @param   original    Padded bytes.
     * @return              Unpadded bytes.
     */
    public static byte[] unpad (final byte[] original) {
        return unpad (original, FlagTailZero.REMOVE_ALL);
    }

    /**
     * Unpadding PKCS #5 / PKCS #7 / ISO 10126 / zero padded bytes.
     * <ul>
     * <li>Returns a new array containing unpadded bytes in normal cases.
     * <li>Returns the {original} itself if {original} is null or empty array,
     *     or {original} size is less than the padding value.
     * </ul>
     * @param   original      Padded bytes.
     * @param   flagTailZero  How to deal with the tail zero byte.
     * @return                Unpadded bytes.
     */
    public static byte[] unpad (final byte[] original, final FlagTailZero flagTailZero) {
        if (original == null || original.length <= 0) return original;

        int lenOri   = original.length;
        int lenPad   = original [lenOri - 1] & 0xFF;
        int lenUnpad = lenOri - lenPad;

        if (lenPad == 0) { // zero padded
            int iTail    = lenOri - 1;
            for (; iTail >= 0 ; --iTail) {
                if (original [iTail] != 0) break;
            }
            lenUnpad = flagTailZero == FlagTailZero.REMOVE_ALL ? iTail + 1 : iTail + 2;
        }

        return lenUnpad >= 0 ? Arrays.copyOf (original, lenUnpad) : original;
    }

}
