use std::io::Error;

const DELIMITER: u8 = 255;
const QR_CODE_VERSION: [u8; 2] = [86, 50]; // Corresponds to "V2"
const DOB_LENGTH_BYTES: usize = 10; // Date of birth is in DD-MM-YYYY format
const DOB_FIELD_POSITION: usize = 4; // Date of birth is the 4th field in the QR code data
const DATA_LENGTH_PER_STEP: usize = 128; // 128 bytes will be hashed per Nova step

pub struct AadhaarQRData {
    pub signed_data: Vec<u8>,
    pub rsa_signature: Vec<u8>,
    pub dob_location: usize,
}

pub fn parse_aadhaar_qr_data(qr_data: Vec<u8>) -> Result<AadhaarQRData, Error> {
    let qr_data_len = qr_data.len();

    if qr_data_len < 256 {
        return Err(Error::other(
            "QR data is shorter than 2048-bit RSA signature",
        ));
    }

    if qr_data[0] != QR_CODE_VERSION[0] || qr_data[1] != QR_CODE_VERSION[1] {
        return Err(Error::other("Aadhaar QR code version is not V2"));
    }

    let mut num_delimiters_seen = 0;
    let mut i = 2;
    while i < DATA_LENGTH_PER_STEP {
        if qr_data[i] == DELIMITER {
            num_delimiters_seen += 1;
        }
        i += 1;
        if num_delimiters_seen == DOB_FIELD_POSITION {
            break;
        }
    }
    let dob_location = i;
    if dob_location + DOB_LENGTH_BYTES - 1 >= DATA_LENGTH_PER_STEP {
        // Circuit assumes that the date of birth is contained in the first 128 bytes
        // This requires the holder's Name to fit in 89 characters
        return Err(Error::other("Date of birth is not in first 128 bytes"));
    }

    Ok(AadhaarQRData {
        signed_data: qr_data[0..qr_data_len - 256].to_vec(), // All bytes except last 256 are signed
        rsa_signature: qr_data[qr_data_len - 256..].to_vec(), // Last 256 bytes have the RSA signature
        dob_location,
    })
}
