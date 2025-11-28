package HospitalCard;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class PatientCardApplet extends Applet {

    private final static byte CARD_CLA = (byte) 0xB0;

    private final static byte INS_VERIFY_PIN   = (byte) 0x20;
    private final static byte INS_CHANGE_PIN   = (byte) 0x21;
    private final static byte INS_SET_PIN      = (byte) 0x22;
    private final static byte INS_GET_BALANCE  = (byte) 0x30;
    private final static byte INS_CREDIT       = (byte) 0x31;
    private final static byte INS_DEBIT        = (byte) 0x32;
    private final static byte INS_SET_PATIENT_ID = (byte) 0x40;
    private final static byte INS_GET_PATIENT_ID = (byte) 0x41;
    private final static byte INS_SET_PROFILE    = (byte) 0x42;
    private final static byte INS_SET_RSA_KEY    = (byte) 0x50;
    private final static byte INS_SIGN_CHALLENGE = (byte) 0x51;

    private static final byte PIN_TRY_LIMIT      = 3;
    private static final byte MAX_PIN_SIZE       = 6;
    private static final short MAX_PATIENT_ID_LEN = 20;
    private static final short MAX_FULLNAME_LEN  = 40;
    private static final short MAX_DOB_LEN       = 10;
    private static final short MAX_BLOODTYPE_LEN = 3;
    private static final short MAX_ALLERGIES_LEN = 40;
    private static final short MAX_CHRONIC_LEN   = 40;
    private static final short MAX_HEALTHID_LEN  = 20;

    private OwnerPIN pin;
    private short balance;
    private byte[] patientId;
    private short patientIdLen;
    private byte[] fullName, dateOfBirth, bloodType, allergies, chronicIllness, healthInsuranceId;
    private short fullNameLen, dateOfBirthLen, bloodTypeLen, allergiesLen, chronicLen, healthIdLen;

    private RSAPrivateKey rsaPrivKey;
    private Cipher rsaCipher;

    protected PatientCardApplet(byte[] bArray, short bOffset, byte bLength) {
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
        byte[] defaultPin = { (byte)'1', (byte)'2', (byte)'3', (byte)'4' };
        pin.update(defaultPin, (short)0, (byte)4);
        balance = 0;

        patientId = new byte[MAX_PATIENT_ID_LEN];
        fullName = new byte[MAX_FULLNAME_LEN];
        dateOfBirth = new byte[MAX_DOB_LEN];
        bloodType = new byte[MAX_BLOODTYPE_LEN];
        allergies = new byte[MAX_ALLERGIES_LEN];
        chronicIllness = new byte[MAX_CHRONIC_LEN];
        healthInsuranceId = new byte[MAX_HEALTHID_LEN];

        // --- QUAN TRNG: KHI TO RSA 512 bit ---
        try {
            rsaPrivKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
            rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        } catch (CryptoException e) {
            // Nu th không h tr 512, rsaPrivKey s null
            rsaPrivKey = null;
        }

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new PatientCardApplet(bArray, bOffset, bLength);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buffer = apdu.getBuffer();
        if (buffer[ISO7816.OFFSET_CLA] == 0x00 && buffer[ISO7816.OFFSET_INS] == (byte)0xA4) return;
        if (buffer[ISO7816.OFFSET_CLA] != CARD_CLA) ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_VERIFY_PIN:     verifyPIN(apdu); break;
            case INS_CHANGE_PIN:     changePIN(apdu); break;
            case INS_SET_PIN:        setPinFromAdmin(apdu); break;
            case INS_GET_BALANCE:    getBalance(apdu); break;
            case INS_CREDIT:         credit(apdu); break;
            case INS_DEBIT:          debit(apdu); break;
            case INS_SET_PATIENT_ID: setPatientId(apdu); break;
            case INS_GET_PATIENT_ID: getPatientId(apdu); break;
            case INS_SET_PROFILE:    setProfile(apdu); break;
            case INS_SET_RSA_KEY:    setRsaPrivateKey(apdu); break;
            case INS_SIGN_CHALLENGE: signChallenge(apdu); break;
            default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void verifyPIN(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte len = buf[ISO7816.OFFSET_LC];
        apdu.setIncomingAndReceive();
        if (pin.check(buf, ISO7816.OFFSET_CDATA, len)) return;
        short tries = pin.getTriesRemaining();
        if (tries == 0) ISOException.throwIt((short)0x6983);
        ISOException.throwIt((short)(0x63C0 | tries));
    }

    private void changePIN(APDU apdu) {
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        byte[] buf = apdu.getBuffer();
        byte len = buf[ISO7816.OFFSET_LC];
        apdu.setIncomingAndReceive();
        if (len < 4 || len > MAX_PIN_SIZE) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        pin.update(buf, ISO7816.OFFSET_CDATA, len);
    }

    private void setPinFromAdmin(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte len = buf[ISO7816.OFFSET_LC];
        apdu.setIncomingAndReceive();
        if (len < 4 || len > MAX_PIN_SIZE) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        pin.reset();
        pin.update(buf, ISO7816.OFFSET_CDATA, len);
    }

    private void getBalance(APDU apdu) {
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        byte[] buf = apdu.getBuffer();
        Util.setShort(buf, (short)0, balance);
        apdu.setOutgoingAndSend((short)0, (short)2);
    }

    private void credit(APDU apdu) {
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        byte[] buf = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        short money = Util.getShort(buf, ISO7816.OFFSET_CDATA);
        if (money <= 0) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        balance += money;
    }

    private void debit(APDU apdu) {
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        byte[] buf = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        short money = Util.getShort(buf, ISO7816.OFFSET_CDATA);
        if (money <= 0) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        if (balance < money) ISOException.throwIt(ISO7816.SW_FILE_FULL);
        balance -= money;
    }

    private void setPatientId(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short len = (short)(buf[ISO7816.OFFSET_LC] & 0xFF);
        if (len > MAX_PATIENT_ID_LEN) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        apdu.setIncomingAndReceive();
        Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, patientId, (short)0, len);
        patientIdLen = len;
    }

    private void getPatientId(APDU apdu) {
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        byte[] buf = apdu.getBuffer();
        Util.arrayCopyNonAtomic(patientId, (short)0, buf, (short)0, patientIdLen);
        apdu.setOutgoingAndSend((short)0, patientIdLen);
    }

    private void setProfile(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short lc = (short)(buf[ISO7816.OFFSET_LC] & 0xFF);
        apdu.setIncomingAndReceive();
        short offset = ISO7816.OFFSET_CDATA;
        fullNameLen = buf[offset++];
        Util.arrayCopyNonAtomic(buf, offset, fullName, (short)0, fullNameLen); offset += fullNameLen;
        dateOfBirthLen = buf[offset++];
        Util.arrayCopyNonAtomic(buf, offset, dateOfBirth, (short)0, dateOfBirthLen); offset += dateOfBirthLen;
        bloodTypeLen = buf[offset++];
        Util.arrayCopyNonAtomic(buf, offset, bloodType, (short)0, bloodTypeLen); offset += bloodTypeLen;
        allergiesLen = buf[offset++];
        Util.arrayCopyNonAtomic(buf, offset, allergies, (short)0, allergiesLen); offset += allergiesLen;
        chronicLen = buf[offset++];
        Util.arrayCopyNonAtomic(buf, offset, chronicIllness, (short)0, chronicLen); offset += chronicLen;
        healthIdLen = buf[offset++];
        Util.arrayCopyNonAtomic(buf, offset, healthInsuranceId, (short)0, healthIdLen); 
    }

    // --- RSA FIX ---
    private void setRsaPrivateKey(APDU apdu) {
        if (rsaPrivKey == null) ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);

        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive(); // c d liu
        if (len <= 0) ISOException.throwIt(ISO7816.SW_DATA_INVALID);

        short offset = ISO7816.OFFSET_CDATA;
        try {
            // 1. Modulus
            short lenMod = (short)(buf[offset] & 0xFF);
            offset++; 
            rsaPrivKey.setModulus(buf, offset, lenMod);
            offset += lenMod;

            // 2. Exponent
            short lenExp = (short)(buf[offset] & 0xFF);
            offset++;
            rsaPrivKey.setExponent(buf, offset, lenExp);
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
    }

    private void signChallenge(APDU apdu) {
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        if (rsaPrivKey == null) ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);

        byte[] buf = apdu.getBuffer();
        short len = (short)(buf[ISO7816.OFFSET_LC] & 0xFF);
        apdu.setIncomingAndReceive();
        try {
            rsaCipher.init(rsaPrivKey, Cipher.MODE_ENCRYPT);
            short sigLen = rsaCipher.doFinal(buf, ISO7816.OFFSET_CDATA, len, buf, (short)0);
            apdu.setOutgoingAndSend((short)0, sigLen);
        } catch (CryptoException e) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }
}
