package HospitalCard;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class PatientCardApplet extends Applet {

    private final static byte CARD_CLA = (byte) 0x80;

    // ... (Các mã lnh c gi nguyên) ...
    private final static byte INS_SET_SALT        = (byte) 0x20;
    private final static byte INS_SET_PIN_HASH    = (byte) 0x21;
    private final static byte INS_SET_WRAP_USER   = (byte) 0x22;
    private final static byte INS_SET_WRAP_ADMIN  = (byte) 0x23;
    private final static byte INS_SET_PROFILE_ENC = (byte) 0x24;
    
    private final static byte INS_GET_SALT        = (byte) 0x25;
    private final static byte INS_VERIFY_PIN_HASH = (byte) 0x26;
    private final static byte INS_GET_DATA_ENC    = (byte) 0x27;

    // === THÊM MÃ LNH MI CHO TRNG THÁI TH ===
    private final static byte INS_GET_STATUS      = (byte) 0x28; // Ly trng thái
    private final static byte INS_SET_STATUS      = (byte) 0x29; // Cp nht trng thái

    // ... (Các lnh ví, rsa gi nguyên) ...
    private final static byte INS_GET_BALANCE     = (byte) 0x30;
    private final static byte INS_CREDIT          = (byte) 0x31;
    private final static byte INS_DEBIT           = (byte) 0x32;
    private final static byte INS_GEN_RSA_KEYPAIR = (byte) 0x52;
    private final static byte INS_SIGN_CHALLENGE  = (byte) 0x51;

    // B nh
    private byte[] saltUser;
    private byte[] hashedPinUser;
    private byte[] wrappedMkUser;
    private byte[] wrappedMkAdmin;
    private byte[] encryptedProfile;
    
    // === THÊM BIN C TRNG THÁI ===
    private byte[] cardStatus; // [0]: 1=FirstLogin, 0=Normal

    private short profileLen;
    private boolean isUserLoggedIn;
    private byte pinTries;
    private short balance;

    // RSA Objects
    private KeyPair rsaKeyPair;
    private RSAPrivateKey rsaPrivKey;
    private RSAPublicKey rsaPubKey;
    private Cipher rsaCipher;

    protected PatientCardApplet(byte[] bArray, short bOffset, byte bLength) {
        // 1. Cp phát
        saltUser        = new byte[16];
        hashedPinUser   = new byte[32];
        wrappedMkUser   = new byte[32];
        wrappedMkAdmin  = new byte[32];
        encryptedProfile = new byte[256];
        
        // Cp phát bin trng thái
        cardStatus = new byte[1];
        cardStatus[0] = 1; // Mc nh là 1 (Ln u tiên)

        // 2. Init bin
        profileLen = 0;
        pinTries = 3;
        balance = 0;
        isUserLoggedIn = false;

        // 3. Init RSA
        try {
            rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_512);
            rsaPrivKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
            rsaPubKey  = (RSAPublicKey) rsaKeyPair.getPublic();
            rsaCipher  = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        } catch(Exception e) { rsaKeyPair = null; }

        register(bArray, (short)(bOffset + 1), bArray[bOffset]);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new PatientCardApplet(bArray, bOffset, bLength);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) { isUserLoggedIn = false; return; }

        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_CLA] != CARD_CLA) ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        byte ins = buf[ISO7816.OFFSET_INS];
        
        // Logic setIncomingAndReceive nh c
        if (ins == INS_SET_SALT || ins == INS_SET_PIN_HASH || 
            ins == INS_SET_WRAP_USER || ins == INS_SET_WRAP_ADMIN || 
            ins == INS_SET_PROFILE_ENC || ins == INS_VERIFY_PIN_HASH ||
            ins == INS_CREDIT || ins == INS_DEBIT || ins == INS_SIGN_CHALLENGE ||
            ins == INS_SET_STATUS) { // Thêm lnh set status
            apdu.setIncomingAndReceive();
        }

        switch (ins) {
            // ... (Các case c gi nguyên) ...
            case INS_SET_SALT: Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, saltUser, (short)0, (short)16); break;
            case INS_SET_PIN_HASH: Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, hashedPinUser, (short)0, (short)32); break;
            case INS_SET_WRAP_USER: Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, wrappedMkUser, (short)0, (short)32); break;
            case INS_SET_WRAP_ADMIN: Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, wrappedMkAdmin, (short)0, (short)32); break;
            case INS_SET_PROFILE_ENC:
                short len = (short)(buf[ISO7816.OFFSET_LC] & 0xFF);
                if (len > 255) len = 255;
                Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, encryptedProfile, (short)0, len);
                profileLen = len;
                pinTries = 3;
                break;

            case INS_GET_SALT:
                Util.arrayCopyNonAtomic(saltUser, (short)0, buf, (short)0, (short)16);
                apdu.setOutgoingAndSend((short)0, (short)16);
                break;

            case INS_VERIFY_PIN_HASH:
                if (pinTries == 0) ISOException.throwIt((short)0x6983);
                if (Util.arrayCompare(buf, ISO7816.OFFSET_CDATA, hashedPinUser, (short)0, (short)32) == 0) {
                    isUserLoggedIn = true;
                    pinTries = 3;
                } else {
                    isUserLoggedIn = false;
                    pinTries--;
                    ISOException.throwIt((short)(0x63C0 | pinTries));
                }
                break;

            case INS_GET_DATA_ENC:
                if (!isUserLoggedIn) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                if (buf[ISO7816.OFFSET_P1] == 0x01) {
                    Util.arrayCopyNonAtomic(wrappedMkUser, (short)0, buf, (short)0, (short)32);
                    apdu.setOutgoingAndSend((short)0, (short)32);
                } else {
                    Util.arrayCopyNonAtomic(encryptedProfile, (short)0, buf, (short)0, profileLen);
                    apdu.setOutgoingAndSend((short)0, profileLen);
                }
                break;

            // === LOGIC TRNG THÁI TH (MI) ===
            case INS_GET_STATUS:
                // Tr v byte trng thái (1=FirstLogin, 0=Normal)
                buf[0] = cardStatus[0];
                apdu.setOutgoingAndSend((short)0, (short)1);
                break;

            case INS_SET_STATUS:
                // Cp nht trng thái (Gi 0x00 xung  tt FirstLogin)
                cardStatus[0] = buf[ISO7816.OFFSET_CDATA];
                break;

            // ... (Các case Ví, RSA gi nguyên code c ca bn) ...
            case INS_GET_BALANCE:
                if (!isUserLoggedIn) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                Util.setShort(buf, (short)0, balance);
                apdu.setOutgoingAndSend((short)0, (short)2);
                break;
            case INS_CREDIT:
                if (!isUserLoggedIn) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                balance += Util.getShort(buf, ISO7816.OFFSET_CDATA);
                break;
            case INS_DEBIT:
                if (!isUserLoggedIn) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                short val = Util.getShort(buf, ISO7816.OFFSET_CDATA);
                if (balance < val) ISOException.throwIt((short)0x6A85);
                balance -= val;
                break;
            case INS_GEN_RSA_KEYPAIR:
                if (rsaKeyPair == null) ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                rsaKeyPair.genKeyPair();
                short modLen = rsaPubKey.getModulus(buf, (short)2);
                Util.setShort(buf, (short)0, modLen);
                short expOff = (short)(2 + modLen);
                short expLen = rsaPubKey.getExponent(buf, (short)(expOff + 2));
                Util.setShort(buf, expOff, expLen);
                short totalLen = (short)(expOff + 2 + expLen);
                apdu.setOutgoingAndSend((short)0, totalLen);
                break;
            case INS_SIGN_CHALLENGE:
                if (!isUserLoggedIn) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                if (rsaPrivKey == null || !rsaPrivKey.isInitialized()) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                short inLen = (short)(buf[ISO7816.OFFSET_LC] & 0xFF);
                try {
                    rsaCipher.init(rsaPrivKey, Cipher.MODE_ENCRYPT);
                    short sigLen = rsaCipher.doFinal(buf, ISO7816.OFFSET_CDATA, inLen, buf, (short)0);
                    apdu.setOutgoingAndSend((short)0, sigLen);
                } catch (Exception e) { ISOException.throwIt(ISO7816.SW_UNKNOWN); }
                break;

            default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
}
