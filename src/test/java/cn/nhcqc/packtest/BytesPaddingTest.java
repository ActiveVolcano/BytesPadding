package cn.nhcqc.packtest;

import cn.nhcqc.pack.BytesPadding;
import cn.nhcqc.pack.BytesPadding.FlagTailZero;

import org.junit.jupiter.api.*;

public class BytesPaddingTest {

	@BeforeAll
	public static void init () {
	}

	@AfterAll
	public static void cleanup () {
	}

    //------------------------------------------------------------------------
	static String base16 (final byte[] b) {
	    if (b == null || b.length <= 0) return "";
	    StringBuilder s = new StringBuilder (b.length * 2);
	    for (byte b1 : b) s.append (String.format ("%02X", b1));
	    return s.toString ();
	}

    //------------------------------------------------------------------------
    static byte[] original0 = new byte[0];
	static byte[] original1 = new byte[] { (byte) 0xAA };
    static byte[] original16 = new byte[] {
        (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03,
        (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
        (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B,
        (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F,
    };

    //------------------------------------------------------------------------
    @Test
    public void testPKCS5 () {
        Assertions.assertEquals (null, BytesPadding.padPKCS5 (null));

        byte[] padded0 = BytesPadding.padPKCS5 (original0);
        Assertions.assertEquals ("0808080808080808",
            base16 (padded0));
        Assertions.assertEquals (base16 (original0),
            base16 (BytesPadding.unpad (padded0)));

        byte[] padded1 = BytesPadding.padPKCS5 (original1);
        Assertions.assertEquals ("AA07070707070707",
            base16 (padded1));
        Assertions.assertEquals (base16 (original1),
            base16 (BytesPadding.unpad (padded1)));

        byte[] padded16 = BytesPadding.padPKCS5 (original16);
        Assertions.assertEquals ("000102030405060708090A0B0C0D0E0F0808080808080808",
            base16 (padded16));
        Assertions.assertEquals (base16 (original16),
            base16 (BytesPadding.unpad (padded16)));
    }

	//------------------------------------------------------------------------
	@Test
	public void testPKCS7 () {
		Assertions.assertEquals (null, BytesPadding.padPKCS7 (null, 16));
        Assertions.assertEquals (original1, BytesPadding.padPKCS7 (original1, -1));
        Assertions.assertEquals (original1, BytesPadding.padPKCS7 (original1, 0));

        byte[] padded0_4 = BytesPadding.padPKCS7 (original0, 4);
        Assertions.assertEquals ("04040404",
            base16 (padded0_4));
        Assertions.assertEquals (base16 (original0),
            base16 (BytesPadding.unpad (padded0_4)));

        byte[] padded1_1 = BytesPadding.padPKCS7 (original1, 1);
        Assertions.assertEquals ("AA01",
            base16 (padded1_1));
        Assertions.assertEquals (base16 (original1),
            base16 (BytesPadding.unpad (padded1_1)));

        byte[] padded1_16 = BytesPadding.padPKCS7 (original1, 16);
        Assertions.assertEquals ("AA0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",
            base16 (padded1_16));
        Assertions.assertEquals (base16 (original1),
            base16 (BytesPadding.unpad (padded1_16)));

        byte[] padded16_1 = BytesPadding.padPKCS7 (original16, 1);
        Assertions.assertEquals ("000102030405060708090A0B0C0D0E0F01",
            base16 (padded16_1));
        Assertions.assertEquals (base16 (original16),
            base16 (BytesPadding.unpad (padded16_1)));

        byte[] padded16_10 = BytesPadding.padPKCS7 (original16, 10);
        Assertions.assertEquals ("000102030405060708090A0B0C0D0E0F04040404",
            base16 (padded16_10));
        Assertions.assertEquals (base16 (original16),
            base16 (BytesPadding.unpad (padded16_10)));

        byte[] padded16_16 = BytesPadding.padPKCS7 (original16, 16);
        Assertions.assertEquals ("000102030405060708090A0B0C0D0E0F10101010101010101010101010101010",
            base16 (padded16_16));
        Assertions.assertEquals (base16 (original16),
            base16 (BytesPadding.unpad (padded16_16)));
	}

    //------------------------------------------------------------------------
    @Test
    public void testISO10126 () {
        Assertions.assertEquals (null, BytesPadding.padISO10126 (null, 16));
        Assertions.assertEquals (original1, BytesPadding.padISO10126 (original1, -1));
        Assertions.assertEquals (original1, BytesPadding.padISO10126 (original1, 0));
        Assertions.assertEquals ((byte) 4, BytesPadding.padISO10126 (original0, 4)[3]);
        Assertions.assertEquals ((byte) 1, BytesPadding.padISO10126 (original1, 1)[1]);
        // System.out.println (base16 (BytesPadding.padISO10126 (original1, 16)));
        Assertions.assertEquals ((byte) 15, BytesPadding.padISO10126 (original1, 16)[15]);
        Assertions.assertEquals ((byte) 1, BytesPadding.padISO10126 (original16, 1)[16]);
        Assertions.assertEquals ((byte) 4, BytesPadding.padISO10126 (original16, 10)[19]);
        Assertions.assertEquals ((byte) 16, BytesPadding.padISO10126 (original16, 16)[31]);
    }

    //------------------------------------------------------------------------
    @Test
    public void testZero () {
        Assertions.assertEquals (null, BytesPadding.padZero (null, 16));
        Assertions.assertEquals (original1, BytesPadding.padZero (original1, -1));
        Assertions.assertEquals (original1, BytesPadding.padZero (original1, 0));

        byte[] padded0_4 = BytesPadding.padZero (original0, 4);
        Assertions.assertEquals ("00000000",
            base16 (padded0_4));
        Assertions.assertEquals ("",
            base16 (BytesPadding.unpad (padded0_4)));
        Assertions.assertEquals ("00",
            base16 (BytesPadding.unpad (padded0_4, FlagTailZero.KEEP_ONE)));

        byte[] padded1_1 = BytesPadding.padZero (original1, 1);
        Assertions.assertEquals ("AA00",
            base16 (padded1_1));
        Assertions.assertEquals ("AA",
            base16 (BytesPadding.unpad (padded1_1)));
        Assertions.assertEquals ("AA00",
            base16 (BytesPadding.unpad (padded1_1, FlagTailZero.KEEP_ONE)));

        Assertions.assertEquals ("AA000000000000000000000000000000",
            base16 (BytesPadding.padZero (original1, 16)));
        Assertions.assertEquals ("000102030405060708090A0B0C0D0E0F00",
            base16 (BytesPadding.padZero (original16, 1)));
        Assertions.assertEquals ("000102030405060708090A0B0C0D0E0F00000000",
            base16 (BytesPadding.padZero (original16, 10)));
        Assertions.assertEquals ("000102030405060708090A0B0C0D0E0F00000000000000000000000000000000",
            base16 (BytesPadding.padZero (original16, 16)));
    }

}
