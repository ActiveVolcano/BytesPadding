# BytesPadding
The Bouncy Castle library already provides padding functions.
However, that is rather huge, rather complex,
and sometimes what we need is only an easy-to-use lightweight library.
So here it is, BytesPadding, a tiny bytes padding library for Java.

# How to compile
* Environment: Java ≥ 8, Maven ≥ 3
* Command:
```cmd
mvn package
```

# How to use
```java
byte[] original = new byte[] { (byte) 0xAB };
// PKCS #5 padding
byte[] padded5 = BytesPadding.padPKCS5 (original);
// PKCS #7 padding with 16 bytes block
byte[] padded7_16 = BytesPadding.padPKCS7 (original, 16);
// ISO 10126 padding with 16 bytes block
byte[] padded10126_16 = BytesPadding.padISO10126 (original, 16);
// Zero padding with 16 bytes block
byte[] padded0_16 = BytesPadding.padZero (original, 16);

byte[] unpad;
// unpadding
unpad = BytesPadding.unpad (padded5);
unpad = BytesPadding.unpad (padded7_16);
unpad = BytesPadding.unpad (padded10126_16);
unpad = BytesPadding.unpad (padded0_16);
// unpadding zero-padded bytes and keeping a tail 0
unpad = BytesPadding.unpad (padded0_16, FlagTailZero.KEEP_ONE);
```
