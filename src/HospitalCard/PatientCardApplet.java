package HospitalCard;

import javacard.framework.*;

public class PatientCardApplet extends Applet {

    private final static byte CARD_CLA = (byte) 0xB0;

    // Lnh PIN
    private final static byte INS_VERIFY_PIN   = (byte) 0x20;
    private final static byte INS_CHANGE_PIN   = (byte) 0x21;
    private final static byte INS_SET_PIN      = (byte) 0x22; // ADMIN t PIN mi, không cn verify

    // Lnh ví
    private final static byte INS_GET_BALANCE  = (byte) 0x30;
    private final static byte INS_CREDIT       = (byte) 0x31;
    private final static byte INS_DEBIT        = (byte) 0x32;

    // Lnh liên quan n h s bnh nhân
    private final static byte INS_SET_PATIENT_ID = (byte) 0x40;
    private final static byte INS_GET_PATIENT_ID = (byte) 0x41;
    private final static byte INS_SET_PROFILE    = (byte) 0x42; // ghi h s tóm tt

    // PIN & s d
    private OwnerPIN pin;
    private short balance;
    private static final byte PIN_TRY_LIMIT = 3;
    private static final byte MAX_PIN_SIZE  = 6;  // PIN ti a 6 s

    // patient_id
    private static final short MAX_PATIENT_ID_LEN = 20;
    private byte[] patientId;
    private short patientIdLen;

    // H s bnh nhân (tóm tt)
    private static final short MAX_FULLNAME_LEN    = 40;
    private static final short MAX_DOB_LEN         = 10; // YYYY-MM-DD
    private static final short MAX_BLOODTYPE_LEN   = 3;
    private static final short MAX_ALLERGIES_LEN   = 40;
    private static final short MAX_CHRONIC_LEN     = 40;
    private static final short MAX_HEALTHID_LEN    = 20;

    private byte[] fullName;
    private short fullNameLen;

    private byte[] dateOfBirth;
    private short dateOfBirthLen;

    private byte[] bloodType;
    private short bloodTypeLen;

    private byte[] allergies;
    private short allergiesLen;

    private byte[] chronicIllness;
    private short chronicLen;

    private byte[] healthInsuranceId;
    private short healthIdLen;

    protected PatientCardApplet(byte[] bArray, short bOffset, byte bLength) {
        // PIN mc nh 1234 (sau này admin có th override bng INS_SET_PIN)
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
        byte[] defaultPin = { (byte)'1', (byte)'2', (byte)'3', (byte)'4' };
        pin.update(defaultPin, (short)0, (byte)4);

        // S d ban u
        balance = 0;

        // Khi to patient_id
        patientId = new byte[MAX_PATIENT_ID_LEN];
        patientIdLen = 0;

        // Khi to các field h s
        fullName = new byte[MAX_FULLNAME_LEN];
        fullNameLen = 0;

        dateOfBirth = new byte[MAX_DOB_LEN];
        dateOfBirthLen = 0;

        bloodType = new byte[MAX_BLOODTYPE_LEN];
        bloodTypeLen = 0;

        allergies = new byte[MAX_ALLERGIES_LEN];
        allergiesLen = 0;

        chronicIllness = new byte[MAX_CHRONIC_LEN];
        chronicLen = 0;

        healthInsuranceId = new byte[MAX_HEALTHID_LEN];
        healthIdLen = 0;

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new PatientCardApplet(bArray, bOffset, bLength);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;

        byte[] buffer = apdu.getBuffer();

        // B qua SELECT chun ISO
        if (buffer[ISO7816.OFFSET_CLA] == (byte)0x00 &&
            buffer[ISO7816.OFFSET_INS] == (byte)0xA4) {
            return;
        }

        if (buffer[ISO7816.OFFSET_CLA] != CARD_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        byte ins = buffer[ISO7816.OFFSET_INS];

        switch (ins) {
            case INS_VERIFY_PIN:
                verifyPIN(apdu);
                break;
            case INS_CHANGE_PIN:
                changePIN(apdu);
                break;
            case INS_SET_PIN:
                setPinFromAdmin(apdu);
                break;
            case INS_GET_BALANCE:
                getBalance(apdu);
                break;
            case INS_CREDIT:
                credit(apdu);
                break;
            case INS_DEBIT:
                debit(apdu);
                break;
            case INS_SET_PATIENT_ID:
                setPatientId(apdu);
                break;
            case INS_GET_PATIENT_ID:
                getPatientId(apdu);
                break;
            case INS_SET_PROFILE:
                setProfile(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // ===== XÁC THC PIN =====
    private void verifyPIN(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte numBytes = buf[ISO7816.OFFSET_LC];
        apdu.setIncomingAndReceive();

        if (pin.check(buf, ISO7816.OFFSET_CDATA, numBytes)) {
            return; // PIN úng
        } else {
            if (pin.getTriesRemaining() == 0) {
                ISOException.throwIt((short)0x6983); // th b khóa
            }
            short sw = (short)(0x63C0 | pin.getTriesRemaining());
            ISOException.throwIt(sw); // PIN sai, còn X ln th
        }
    }

    // ===== I PIN (bnh nhân dùng, yêu cu ã verify) =====
    private void changePIN(APDU apdu) {
        if (!pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        byte[] buf = apdu.getBuffer();
        byte numBytes = buf[ISO7816.OFFSET_LC];
        apdu.setIncomingAndReceive();

        if (numBytes <= 0 || numBytes > MAX_PIN_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        pin.update(buf, ISO7816.OFFSET_CDATA, numBytes);
    }

    // ===== T PIN T ADMIN (không cn verify) =====
    private void setPinFromAdmin(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte numBytes = buf[ISO7816.OFFSET_LC];
        apdu.setIncomingAndReceive();

        if (numBytes <= 0 || numBytes > MAX_PIN_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Reset trng thái PIN (s ln th) ri t PIN mi
        pin.reset();
        pin.update(buf, ISO7816.OFFSET_CDATA, numBytes);
    }

    // ===== LY S D =====
    private void getBalance(APDU apdu) {
        if (!pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        byte[] buf = apdu.getBuffer();
        Util.setShort(buf, (short)0, balance);
        apdu.setOutgoingAndSend((short)0, (short)2);
    }

    // ===== NP TIN =====
    private void credit(APDU apdu) {
        if (!pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        byte[] buf = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        short amount = Util.getShort(buf, ISO7816.OFFSET_CDATA);
        if (amount <= 0) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        balance += amount;
    }

    // ===== THANH TOÁN =====
    private void debit(APDU apdu) {
        if (!pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        byte[] buf = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        short amount = Util.getShort(buf, ISO7816.OFFSET_CDATA);
        if (amount <= 0) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        if (balance < amount) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL); // không  tin
        }
        balance -= amount;
    }

    // ===== GHI PATIENT_ID (admin dùng khi cp th) =====
    private void setPatientId(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short lc = (short)(buf[ISO7816.OFFSET_LC] & 0xFF);

        if (lc <= 0 || lc > MAX_PATIENT_ID_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short recvLen = apdu.setIncomingAndReceive();
        Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, patientId, (short)0, recvLen);
        patientIdLen = recvLen;
    }

    // ===== C PATIENT_ID (kiosk dùng sau khi PIN OK) =====
    private void getPatientId(APDU apdu) {
        if (!pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        byte[] buf = apdu.getBuffer();
        Util.arrayCopyNonAtomic(patientId, (short)0, buf, (short)0, patientIdLen);
        apdu.setOutgoingAndSend((short)0, patientIdLen);
    }

    // ===== GHI H S TÓM TT LÊN TH =====
    /*
       Data gi cho INS_SET_PROFILE:

       [lenFullName][fullName bytes]
       [lenDob][dob bytes]
       [lenBlood][blood bytes]
       [lenAllergies][allergies bytes]
       [lenChronic][chronic bytes]
       [lenHealthId][healthId bytes]
    */
    private void setProfile(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short lc = (short)(buf[ISO7816.OFFSET_LC] & 0xFF);
        if (lc <= 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short recvLen = apdu.setIncomingAndReceive();
        short offset = ISO7816.OFFSET_CDATA;

        // 1. H tên
        byte len = buf[offset++];
        if (len < 0 || (short)len > MAX_FULLNAME_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopyNonAtomic(buf, offset, fullName, (short)0, len);
        fullNameLen = (short)len;
        offset += len;

        // 2. Ngày sinh
        len = buf[offset++];
        if (len < 0 || (short)len > MAX_DOB_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopyNonAtomic(buf, offset, dateOfBirth, (short)0, len);
        dateOfBirthLen = (short)len;
        offset += len;

        // 3. Nhóm máu
        len = buf[offset++];
        if (len < 0 || (short)len > MAX_BLOODTYPE_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopyNonAtomic(buf, offset, bloodType, (short)0, len);
        bloodTypeLen = (short)len;
        offset += len;

        // 4. D ng
        len = buf[offset++];
        if (len < 0 || (short)len > MAX_ALLERGIES_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopyNonAtomic(buf, offset, allergies, (short)0, len);
        allergiesLen = (short)len;
        offset += len;

        // 5. Bnh mãn tính
        len = buf[offset++];
        if (len < 0 || (short)len > MAX_CHRONIC_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopyNonAtomic(buf, offset, chronicIllness, (short)0, len);
        chronicLen = (short)len;
        offset += len;

        // 6. Mã BHYT
        len = buf[offset++];
        if (len < 0 || (short)len > MAX_HEALTHID_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopyNonAtomic(buf, offset, healthInsuranceId, (short)0, len);
        healthIdLen = (short)len;
    }
}
