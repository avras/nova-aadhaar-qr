use bellpepper::gadgets::multipack::{bytes_to_bits, compute_multipacking, pack_bits};
use bellpepper_core::{
    boolean::{AllocatedBit, Boolean},
    num::AllocatedNum,
    ConstraintSystem, LinearCombination, SynthesisError,
};
use bellpepper_nonnative::{
    mp::bignat::{nat_to_limbs, BigNat},
    util::{bit::Bit, gadget::Gadget, num::Num},
};
use ff::{PrimeField, PrimeFieldBits};
use nova_snark::traits::circuit::StepCircuit;
use num_bigint::{BigInt, Sign};
use sha2::{compress256, digest::generic_array::GenericArray};

use crate::{
    dob::{
        calculate_age_in_years, delimiter_count_before_dob_is_correct,
        get_day_month_year_conditional, left_shift_bytes, DOB_INDEX_BIT_LENGTH,
    },
    poseidon::PoseidonHasher,
    qr::AadhaarQRData,
    rsa::{
        emsa_pkcs1v15_encode, BIGNAT_LIMB_WIDTH, BIGNAT_NUM_LIMBS, RSA_MODULUS_HEX_BYTES,
        RSA_MODULUS_LENGTH_BYTES,
    },
    sha256::{
        sha256_digest_to_scalars, sha256_initial_digest_scalars, sha256_msg_block_sequence,
        sha256_state_to_bytes, SHA256_BLOCK_LENGTH_BYTES, SHA256_DIGEST_LENGTH_BYTES, SHA256_IV,
    },
    util::{
        alloc_constant, alloc_num_equals, alloc_num_equals_constant, bignat_to_allocatednum_limbs,
        boolean_implies, check_decomposition, conditionally_select,
        conditionally_select_boolean_vec, conditionally_select_vec, less_than_or_equal,
        num_to_bits,
    },
};

pub const NUM_OPCODE_BITS: usize = 7; // 2 MS bits for SHA256 + 5 LS bits for RSA
pub const NUM_RSA_OPCODE_BITS: u64 = 5;
pub const RSA_OPCODE_MASK: u64 = (1 << NUM_RSA_OPCODE_BITS) - 1;
pub const OP_SHA256_FIRST: u64 = 0;
pub const OP_SHA256_OTHER: u64 = 1;
pub const OP_SHA256_NOOP: u64 = 2;
pub const OP_RSA_FIRST: u64 = 0;
pub const OP_RSA_LAST: u64 = 16;
pub const OP_CODE_LAST: u64 = (OP_SHA256_NOOP << NUM_RSA_OPCODE_BITS) + OP_RSA_LAST;

const DATE_LENGTH_BYTES: usize = 10;
const TIMESTAMP_START_BYTE_INDEX: usize = 9;
const NAME_START_BYTE_INDEX: usize = 27;

#[derive(Clone, Debug)]
pub struct AadhaarAgeProofCircuit<Scalar>
where
    Scalar: PrimeField,
{
    opcode: u64,
    next_opcode: u64,
    num_sha256_msg_blocks_even: bool,
    dob_byte_index: usize,
    sha256_msg_block_pair: [u8; 2 * SHA256_BLOCK_LENGTH_BYTES],
    current_sha256_digest_bytes: [u8; SHA256_DIGEST_LENGTH_BYTES],
    rsa_sig: [u8; RSA_MODULUS_LENGTH_BYTES],
    prev_nullifier: Scalar,
    rsa_sig_power: [Scalar; BIGNAT_NUM_LIMBS],
}

impl<Scalar> Default for AadhaarAgeProofCircuit<Scalar>
where
    Scalar: PrimeField,
{
    fn default() -> Self {
        Self {
            opcode: 0,
            next_opcode: 0,
            num_sha256_msg_blocks_even: false,
            dob_byte_index: 0,
            sha256_msg_block_pair: [0u8; 2 * SHA256_BLOCK_LENGTH_BYTES],
            current_sha256_digest_bytes: [0u8; SHA256_DIGEST_LENGTH_BYTES],
            prev_nullifier: Scalar::ZERO,
            rsa_sig: [0u8; RSA_MODULUS_LENGTH_BYTES],
            rsa_sig_power: [Scalar::ZERO; BIGNAT_NUM_LIMBS],
        }
    }
}

impl<Scalar> AadhaarAgeProofCircuit<Scalar>
where
    Scalar: PrimeFieldBits,
{
    fn update_nullifier(prev_nullifier: Scalar, current_msg_blocks: &[u8]) -> Scalar {
        assert_eq!(current_msg_blocks.len(), 2 * SHA256_BLOCK_LENGTH_BYTES);

        let msg_blocks_bits = bytes_to_bits(current_msg_blocks);
        let mut msg_blocks_scalars = compute_multipacking::<Scalar>(&msg_blocks_bits);
        msg_blocks_scalars.insert(0, prev_nullifier);
        let nullifier_hasher = PoseidonHasher::new(msg_blocks_scalars.len() as u32);
        let next_nullifier = nullifier_hasher.hash(&msg_blocks_scalars);
        next_nullifier
    }

    pub fn calc_initial_primary_circuit_input(current_date_bytes: &[u8]) -> Vec<Scalar> {
        let sha256_iv = sha256_initial_digest_scalars::<Scalar>();
        let initial_opcode = Scalar::from((OP_SHA256_FIRST << NUM_RSA_OPCODE_BITS) + OP_RSA_FIRST);

        let aadhaar_io_hasher = PoseidonHasher::<Scalar>::new(3 + BIGNAT_NUM_LIMBS as u32);
        let mut initial_io_values = sha256_iv;
        // The +1 is for the previous nullifier hash
        initial_io_values.extend_from_slice(&[Scalar::ZERO; BIGNAT_NUM_LIMBS + 1]);
        let initial_io_hash = aadhaar_io_hasher.hash(&initial_io_values);

        let current_date_bits = bytes_to_bits(current_date_bytes);
        let current_date_scalars = compute_multipacking::<Scalar>(&current_date_bits);
        assert_eq!(current_date_scalars.len(), 1);
        let current_date_scalar = current_date_scalars[0];

        // The last scalar corresponds to the current date
        vec![initial_opcode, initial_io_hash, current_date_scalar]
    }

    pub fn new_state_sequence(
        aadhaar_qr_data: &AadhaarQRData,
    ) -> Vec<AadhaarAgeProofCircuit<Scalar>> {
        let mut sha256_msg_blocks = sha256_msg_block_sequence(aadhaar_qr_data.signed_data.clone());
        let num_sha256_msg_blocks_even = sha256_msg_blocks.len() % 2 == 0;

        if !num_sha256_msg_blocks_even {
            sha256_msg_blocks.push([0u8; SHA256_BLOCK_LENGTH_BYTES]);
        }

        let mut aadhaar_steps = vec![];

        let mut sha256_state = SHA256_IV;
        let mut prev_nullifier = Scalar::ZERO;
        let first_opcode = (OP_SHA256_FIRST << NUM_RSA_OPCODE_BITS) + OP_RSA_FIRST;
        let first_next_opcode = (OP_SHA256_OTHER << NUM_RSA_OPCODE_BITS) + OP_RSA_FIRST + 1u64;
        let modulus_bigint = BigInt::from_bytes_be(Sign::Plus, &RSA_MODULUS_HEX_BYTES);
        // Initialize the RSA signature power to the RSA signature value
        let mut rsa_sig_power_bigint =
            BigInt::from_bytes_be(Sign::Plus, &aadhaar_qr_data.rsa_signature);
        let rsa_sig_scalars =
            nat_to_limbs::<Scalar>(&rsa_sig_power_bigint, BIGNAT_LIMB_WIDTH, BIGNAT_NUM_LIMBS)
                .unwrap()
                .try_into()
                .unwrap();

        let first_sha256_msg_block_pair: [u8; 2 * SHA256_BLOCK_LENGTH_BYTES] =
            [sha256_msg_blocks[0], sha256_msg_blocks[1]]
                .concat()
                .try_into()
                .unwrap();

        // First step
        aadhaar_steps.push(Self {
            opcode: first_opcode,
            next_opcode: first_next_opcode,
            num_sha256_msg_blocks_even,
            dob_byte_index: aadhaar_qr_data.dob_byte_index,
            sha256_msg_block_pair: first_sha256_msg_block_pair,
            current_sha256_digest_bytes: sha256_state_to_bytes(sha256_state).try_into().unwrap(),
            prev_nullifier,
            rsa_sig: aadhaar_qr_data.rsa_signature.clone().try_into().unwrap(),
            rsa_sig_power: rsa_sig_scalars,
        });

        // Square the signature
        rsa_sig_power_bigint = rsa_sig_power_bigint.modpow(&BigInt::from(2u64), &modulus_bigint);

        let msg_blocks_without_timestamp: [u8; 2 * SHA256_BLOCK_LENGTH_BYTES] = [
            &first_sha256_msg_block_pair[0..TIMESTAMP_START_BYTE_INDEX],
            &[0u8; NAME_START_BYTE_INDEX - TIMESTAMP_START_BYTE_INDEX],
            &first_sha256_msg_block_pair[NAME_START_BYTE_INDEX..],
        ]
        .concat()
        .try_into()
        .unwrap();
        prev_nullifier = Self::update_nullifier(prev_nullifier, &msg_blocks_without_timestamp);

        compress256(
            &mut sha256_state,
            &[*GenericArray::from_slice(&sha256_msg_blocks[0])],
        );
        compress256(
            &mut sha256_state,
            &[*GenericArray::from_slice(&sha256_msg_blocks[1])],
        );

        // Append 16 RSA steps for repeated squaring (or multiplying) of the signature
        for i in 1..=16 {
            let mut sha256_msg_block_pair = [0u8; 2 * SHA256_BLOCK_LENGTH_BYTES];
            // We assume that the number 128-byte blocks in the QR code is less than 17. It usually 8 or 9
            let opcode;
            let next_opcode;
            if i < sha256_msg_blocks.len() / 2 {
                sha256_msg_block_pair = [sha256_msg_blocks[2 * i], sha256_msg_blocks[2 * i + 1]]
                    .concat()
                    .try_into()
                    .unwrap();
                opcode = (OP_SHA256_OTHER << NUM_RSA_OPCODE_BITS) + OP_RSA_FIRST + i as u64;
                if i == sha256_msg_blocks.len() / 2 - 1 {
                    next_opcode = (OP_SHA256_NOOP << NUM_RSA_OPCODE_BITS) + (i + 1) as u64;
                } else {
                    next_opcode = opcode + 1;
                }
            } else {
                opcode = (OP_SHA256_NOOP << NUM_RSA_OPCODE_BITS) + i as u64;
                next_opcode = opcode + 1;
            }

            let rsa_sig_power_scalars =
                nat_to_limbs::<Scalar>(&rsa_sig_power_bigint, BIGNAT_LIMB_WIDTH, BIGNAT_NUM_LIMBS)
                    .unwrap()
                    .try_into()
                    .unwrap();

            let step = Self {
                opcode,
                next_opcode,
                num_sha256_msg_blocks_even,
                dob_byte_index: aadhaar_qr_data.dob_byte_index,
                sha256_msg_block_pair,
                current_sha256_digest_bytes: sha256_state_to_bytes(sha256_state)
                    .try_into()
                    .unwrap(),
                prev_nullifier,
                rsa_sig: aadhaar_qr_data.rsa_signature.clone().try_into().unwrap(),
                rsa_sig_power: rsa_sig_power_scalars,
            };

            aadhaar_steps.push(step);

            if i < sha256_msg_blocks.len() / 2 {
                compress256(
                    &mut sha256_state,
                    &[*GenericArray::from_slice(&sha256_msg_blocks[2 * i])],
                );
                if i != sha256_msg_blocks.len() / 2 - 1 || num_sha256_msg_blocks_even {
                    compress256(
                        &mut sha256_state,
                        &[*GenericArray::from_slice(&sha256_msg_blocks[2 * i + 1])],
                    );
                }
                prev_nullifier = Self::update_nullifier(prev_nullifier, &sha256_msg_block_pair);
            }
            rsa_sig_power_bigint =
                rsa_sig_power_bigint.modpow(&BigInt::from(2u64), &modulus_bigint);
        }

        aadhaar_steps
    }
}

impl<Scalar> StepCircuit<Scalar> for AadhaarAgeProofCircuit<Scalar>
where
    Scalar: PrimeFieldBits,
{
    fn arity(&self) -> usize {
        3
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let opcode = &z[0];
        let next_opcode = AllocatedNum::alloc(cs.namespace(|| "next opcode"), || {
            Ok(Scalar::from(self.next_opcode))
        })?;
        // check that opcode fits in 7 bits
        let opcode_bits_le =
            num_to_bits(cs.namespace(|| "Decompose opcode"), opcode, NUM_OPCODE_BITS)?;
        let sha256_opcode_bits_le = opcode_bits_le[NUM_RSA_OPCODE_BITS as usize..].to_vec();
        let rsa_opcode_bits_le = opcode_bits_le[..NUM_RSA_OPCODE_BITS as usize].to_vec();

        // Allocate SHA256 and RSA opcodes
        let sha256_opcode = AllocatedNum::alloc(cs.namespace(|| "SHA256 opcode"), || {
            Ok(Scalar::from(self.opcode >> NUM_RSA_OPCODE_BITS))
        })?;
        let rsa_opcode = AllocatedNum::alloc(cs.namespace(|| "RSA opcode"), || {
            Ok(Scalar::from(self.opcode & RSA_OPCODE_MASK))
        })?;

        // check allocated sha256 opcode matches with input opcode bits
        check_decomposition(
            cs.namespace(|| "check SHA256 opcode allocation"),
            &sha256_opcode,
            sha256_opcode_bits_le,
        )?;
        // check allocated RSA opcode matches with input opcode bits
        check_decomposition(
            cs.namespace(|| "check RSA opcode allocation"),
            &rsa_opcode,
            rsa_opcode_bits_le,
        )?;

        // check that next opcode fits in 7 bits
        let next_opcode_bits_le = num_to_bits(
            cs.namespace(|| "Decompose next opcode"),
            &next_opcode,
            NUM_OPCODE_BITS,
        )?;
        let next_sha256_opcode_bits_le =
            next_opcode_bits_le[NUM_RSA_OPCODE_BITS as usize..].to_vec();
        let next_rsa_opcode_bits_le = next_opcode_bits_le[..NUM_RSA_OPCODE_BITS as usize].to_vec();

        let next_sha256_opcode =
            AllocatedNum::alloc(cs.namespace(|| "next SHA256 opcode"), || {
                Ok(Scalar::from(self.next_opcode >> NUM_RSA_OPCODE_BITS))
            })?;
        let next_rsa_opcode = AllocatedNum::alloc(cs.namespace(|| "next RSA opcode"), || {
            Ok(Scalar::from(self.next_opcode & RSA_OPCODE_MASK))
        })?;

        // check allocated next sha256 opcode matches with allocated next opcode bits
        check_decomposition(
            cs.namespace(|| "check next SHA256 opcode allocation"),
            &next_sha256_opcode,
            next_sha256_opcode_bits_le,
        )?;
        // check allocated next RSA opcode matches with input opcode bits
        check_decomposition(
            cs.namespace(|| "check next RSA opcode allocation"),
            &next_rsa_opcode,
            next_rsa_opcode_bits_le,
        )?;

        // Constraints related to the opcode inputs
        cs.enforce(
            || "next RSA opcode is always one more than current RSA opcode",
            |lc| lc + next_rsa_opcode.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + CS::one() + rsa_opcode.get_variable(),
        );

        cs.enforce(
            || "next SHA256 opcode is identical or one more",
            |lc| lc + sha256_opcode.get_variable() - next_sha256_opcode.get_variable(),
            |lc| lc + CS::one() + sha256_opcode.get_variable() - next_sha256_opcode.get_variable(),
            |lc| lc,
        );

        let is_next_sha256_opcode_equal_to_sha256_opcode = alloc_num_equals(
            cs.namespace(|| "SHA256 opcode and next SHA256 opcode are equal"),
            &sha256_opcode,
            &next_sha256_opcode,
        )?;

        let is_sha256_opcode_first_sha256 = alloc_num_equals_constant(
            cs.namespace(|| "first SHA256 opcode flag"),
            &sha256_opcode,
            Scalar::from(OP_SHA256_FIRST),
        )?;
        let is_sha256_opcode_other_sha256 = alloc_num_equals_constant(
            cs.namespace(|| "first SHA256 opcode flag"),
            &sha256_opcode,
            Scalar::from(OP_SHA256_OTHER),
        )?;
        let is_sha256_opcode_noop_sha256 = alloc_num_equals_constant(
            cs.namespace(|| "No-op SHA256 opcode flag"),
            &sha256_opcode,
            Scalar::from(OP_SHA256_NOOP),
        )?;
        let is_next_sha256_opcode_noop_sha256 = alloc_num_equals_constant(
            cs.namespace(|| "Next SHA256 is No-op SHA256 opcode flag"),
            &next_sha256_opcode,
            Scalar::from(OP_SHA256_NOOP),
        )?;

        let is_sha256_opcode_last_sha256 = Boolean::and(
            cs.namespace(|| "last SHA256 opcode flag"),
            &is_sha256_opcode_other_sha256,
            &is_next_sha256_opcode_noop_sha256,
        )?;
        let is_sha256_opcode_active = is_sha256_opcode_noop_sha256.not();

        let is_rsa_opcode_first_rsa = alloc_num_equals_constant(
            cs.namespace(|| "first RSA opcode flag"),
            &rsa_opcode,
            Scalar::from(OP_RSA_FIRST),
        )?;
        let is_opcode_last_rsa = alloc_num_equals_constant(
            cs.namespace(|| "last RSA opcode flag"),
            &rsa_opcode,
            Scalar::from(OP_RSA_LAST),
        )?;

        let should_next_sha256_opcode_be_one_more = Boolean::or(
            cs.namespace(|| "first SHA256 OR last SHA256"),
            &is_sha256_opcode_first_sha256,
            &is_sha256_opcode_last_sha256,
        )?;

        // if opcode is first or last SHA256, next opcode should be 1 more
        boolean_implies(
            cs.namespace(|| "if opcode is first or last SHA256, then next opcode is incremented"),
            &should_next_sha256_opcode_be_one_more,
            &is_next_sha256_opcode_equal_to_sha256_opcode.not(),
        )?;

        // Check that the non-deterministic inputs hash to the expected value
        let io_hash = &z[1];
        let current_sha256_digest_scalar_values =
            sha256_digest_to_scalars::<Scalar>(&self.current_sha256_digest_bytes);

        let current_sha256_digest_scalars = current_sha256_digest_scalar_values
            .into_iter()
            .enumerate()
            .map(|(i, s)| {
                AllocatedNum::alloc(
                    cs.namespace(|| format!("alloc SHA256 current digest scalar {i}")),
                    || Ok(s),
                )
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;
        let prev_nullifier =
            AllocatedNum::alloc_infallible(cs.namespace(|| "alloc previous nullifier"), || {
                self.prev_nullifier
            });
        let rsa_sig_power_allocatednum_limbs = self
            .rsa_sig_power
            .into_iter()
            .enumerate()
            .map(|(i, s)| {
                AllocatedNum::alloc(
                    cs.namespace(|| format!("alloc current RSA sig power scalar {i}")),
                    || Ok(s),
                )
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;
        let allocated_zero_limbs = (0..BIGNAT_NUM_LIMBS)
            .into_iter()
            .map(|i| {
                alloc_constant(
                    cs.namespace(|| format!("alloc zero limb {i}")),
                    Scalar::ZERO,
                )
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;
        let limbs_to_be_hashed = conditionally_select_vec(
            cs.namespace(|| "select between actual RSA sig power and zero limbs"),
            &allocated_zero_limbs,
            &rsa_sig_power_allocatednum_limbs,
            &is_sha256_opcode_first_sha256,
        )?;

        let aadhaar_io_hasher = PoseidonHasher::<Scalar>::new(3 + BIGNAT_NUM_LIMBS as u32);
        let mut io_hash_preimage = current_sha256_digest_scalars.clone();
        io_hash_preimage.push(prev_nullifier.clone());
        io_hash_preimage.extend(limbs_to_be_hashed.clone().into_iter());
        let calc_io_hash = aadhaar_io_hasher.hash_in_circuit(
            &mut cs.namespace(|| "hash non-deterministic inputs"),
            &io_hash_preimage,
        )?;

        let io_hash_preimage_correct = alloc_num_equals(
            cs.namespace(|| "hash equality flag"),
            io_hash,
            &calc_io_hash,
        )?;
        Boolean::enforce_equal(
            cs.namespace(|| "hashes must be equal"),
            &io_hash_preimage_correct,
            &Boolean::Constant(true),
        )?;

        let first_sha256_msg_block_bits =
            bytes_to_bits(&self.sha256_msg_block_pair[0..SHA256_BLOCK_LENGTH_BYTES]);
        let second_sha256_msg_block_bits =
            bytes_to_bits(&self.sha256_msg_block_pair[SHA256_BLOCK_LENGTH_BYTES..]);

        let first_sha256_msg_block_booleans: Vec<Boolean> = first_sha256_msg_block_bits
            .into_iter()
            .enumerate()
            .map(|(i, b)| {
                Boolean::from(
                    AllocatedBit::alloc(
                        cs.namespace(|| format!("first SHA256 block input bit {i}")),
                        Some(b),
                    )
                    .unwrap(),
                )
            })
            .collect();
        let second_sha256_msg_block_booleans: Vec<Boolean> = second_sha256_msg_block_bits
            .into_iter()
            .enumerate()
            .map(|(i, b)| {
                Boolean::from(
                    AllocatedBit::alloc(
                        cs.namespace(|| format!("second SHA256 block input bit {i}")),
                        Some(b),
                    )
                    .unwrap(),
                )
            })
            .collect();

        let dob_byte_index =
            AllocatedNum::alloc_infallible(cs.namespace(|| "alloc DoB byte index"), || {
                Scalar::from(self.dob_byte_index as u64)
            });

        let mut two_sha256_msg_blocks = first_sha256_msg_block_booleans.clone();
        two_sha256_msg_blocks.extend(second_sha256_msg_block_booleans.clone().into_iter());

        let delimiter_count_correct = delimiter_count_before_dob_is_correct(
            cs.namespace(|| "check if delimiter count before DoB is correct"),
            &two_sha256_msg_blocks,
            &dob_byte_index,
        )?;
        boolean_implies(
            cs.namespace(|| "if first SHA256 step then delimiter count must be correct"),
            &is_sha256_opcode_first_sha256,
            &delimiter_count_correct,
        )?;

        let mut shift_bits =
            dob_byte_index.to_bits_le(cs.namespace(|| "decompose DoB byte index"))?;
        shift_bits.truncate(DOB_INDEX_BIT_LENGTH);

        let shifted_msg_blocks = left_shift_bytes(
            cs.namespace(|| "left shift to bring DoB bytes to the beginning"),
            &two_sha256_msg_blocks,
            &shift_bits,
        )?;
        let (day, month, year) = get_day_month_year_conditional(
            cs.namespace(|| "get birth day, month, year"),
            &shifted_msg_blocks[0..DATE_LENGTH_BYTES * 8],
            &is_sha256_opcode_first_sha256,
        )?;

        let mut current_date_bits = z[2].to_bits_le(cs.namespace(|| "alloc current date bits"))?;
        current_date_bits.truncate(DATE_LENGTH_BYTES * 8);

        let (current_day, current_month, current_year) = get_day_month_year_conditional(
            cs.namespace(|| "get current birth day, month, year"),
            &current_date_bits,
            &is_sha256_opcode_first_sha256,
        )?;

        let age = calculate_age_in_years(
            cs.namespace(|| "calculate age"),
            &day,
            &month,
            &year,
            &current_day,
            &current_month,
            &current_year,
            &is_sha256_opcode_first_sha256,
        )?;
        let age18 = alloc_constant(cs.namespace(|| "alloc 18"), Scalar::from(18u64))?;
        let age_gte_18 = less_than_or_equal(
            cs.namespace(|| "age <= 18"),
            &age18,
            &age,
            19, // In the first step, age will occupy 7 bits but in later steps it can occupy 19 bits
        )?;
        boolean_implies(
            cs.namespace(|| "if first SHA256 step then age must at least 18"),
            &is_sha256_opcode_first_sha256,
            &age_gte_18,
        )?;

        // Nullifier calculation
        let mut two_sha256_msg_blocks_without_timestamp = vec![];
        for i in 0..TIMESTAMP_START_BYTE_INDEX * 8 {
            two_sha256_msg_blocks_without_timestamp.push(two_sha256_msg_blocks[i].clone());
        }
        for _i in TIMESTAMP_START_BYTE_INDEX * 8..NAME_START_BYTE_INDEX * 8 {
            two_sha256_msg_blocks_without_timestamp.push(Boolean::Constant(false));
        }
        for i in NAME_START_BYTE_INDEX * 8..2 * SHA256_BLOCK_LENGTH_BYTES * 8 {
            two_sha256_msg_blocks_without_timestamp.push(two_sha256_msg_blocks[i].clone());
        }

        let mut msg_block_alloc_nums_without_timestamp: Vec<AllocatedNum<Scalar>> = vec![];
        two_sha256_msg_blocks_without_timestamp
            .chunks(Scalar::CAPACITY as usize)
            .into_iter()
            .enumerate()
            .for_each(|(i, c)| {
                let tmp = pack_bits(
                    cs.namespace(|| format!("packs bits without timestamp {i}")),
                    c,
                )
                .unwrap();
                msg_block_alloc_nums_without_timestamp.push(tmp);
            });

        let mut msg_block_alloc_nums: Vec<AllocatedNum<Scalar>> = vec![];
        two_sha256_msg_blocks
            .chunks(Scalar::CAPACITY as usize)
            .into_iter()
            .enumerate()
            .for_each(|(i, c)| {
                let tmp = pack_bits(cs.namespace(|| format!("packs bits with timestamp {i}")), c)
                    .unwrap();
                msg_block_alloc_nums.push(tmp);
            });

        let mut nullifier_msg_block_alloc_nums = conditionally_select_vec(
            cs.namespace(|| "omit timestamp bits in first step"),
            &msg_block_alloc_nums_without_timestamp,
            &msg_block_alloc_nums,
            &is_sha256_opcode_first_sha256,
        )?;
        nullifier_msg_block_alloc_nums.insert(0, prev_nullifier.clone());
        let nullifier_hasher =
            PoseidonHasher::<Scalar>::new(nullifier_msg_block_alloc_nums.len() as u32);
        let new_nullifier = nullifier_hasher.hash_in_circuit(
            &mut cs.namespace(|| "hash msg block scalars to get nullifier"),
            &nullifier_msg_block_alloc_nums,
        )?;
        let nullifier = conditionally_select(
            cs.namespace(|| "choose between new and prev nullifiers"),
            &new_nullifier,
            &prev_nullifier,
            &is_sha256_opcode_active,
        )?;

        // Compute SHA256 hash of the pair of message blocks
        let first_sha256_io = super::sha256::compress(
            &mut cs.namespace(|| "Compress first SHA256 message block"),
            &first_sha256_msg_block_booleans,
            &current_sha256_digest_scalars,
        )?;
        let second_sha256_io = super::sha256::compress(
            &mut cs.namespace(|| "Compress second SHA256 message block"),
            &second_sha256_msg_block_booleans,
            &first_sha256_io.next_digest_scalars,
        )?;

        let num_sha256_msg_blocks_even = Boolean::from(
            AllocatedBit::alloc(
                cs.namespace(|| "alloc number of SHA256 msg blocks is even"),
                Some(self.num_sha256_msg_blocks_even),
            )
            .unwrap(),
        );

        let is_opcode_not_last_sha256_or_num_sha256_msg_blocks_even = Boolean::or(
            cs.namespace(|| "not last SHA256 opcode OR number of SHA256 blocks is even"),
            &is_sha256_opcode_last_sha256.not(),
            &num_sha256_msg_blocks_even,
        )?;

        let first_or_second_sha256_digest_scalars = conditionally_select_vec(
            cs.namespace(|| "Choose between first and second SHA256 digests"),
            &second_sha256_io.next_digest_scalars,
            &first_sha256_io.next_digest_scalars,
            &is_opcode_not_last_sha256_or_num_sha256_msg_blocks_even,
        )?;
        let first_or_second_sha256_digest_bits = conditionally_select_boolean_vec(
            cs.namespace(|| "Choose between first and second SHA256 digest bits"),
            &second_sha256_io.next_digest_bits,
            &first_sha256_io.next_digest_bits,
            &is_opcode_not_last_sha256_or_num_sha256_msg_blocks_even,
        )?;
        let next_sha256_digest_scalars = conditionally_select_vec(
            cs.namespace(|| "Choose between current and next SHA256 digests"),
            &first_or_second_sha256_digest_scalars,
            &current_sha256_digest_scalars,
            &is_sha256_opcode_active,
        )?;
        let next_sha256_digest_bits = conditionally_select_boolean_vec(
            cs.namespace(|| "Choose between current and next SHA256 digest bits"),
            &first_or_second_sha256_digest_bits,
            &first_sha256_io.current_digest_bits,
            &is_sha256_opcode_active,
        )?;

        // Check that the hash of the non-deterministically provided RSA signature matches
        // the hash of the RSA signatures used in the previous step
        let prev_rsa_sig_hash = &z[2];
        let rsa_signature_bigint = BigInt::from_bytes_be(Sign::Plus, &self.rsa_sig);
        let rsa_signature = BigNat::<Scalar>::alloc_from_nat(
            cs.namespace(|| "alloc RSA signature"),
            || Ok(rsa_signature_bigint),
            BIGNAT_LIMB_WIDTH,
            BIGNAT_NUM_LIMBS,
        )?;
        let rsa_signature_allocatednum_limbs = bignat_to_allocatednum_limbs(
            &mut cs.namespace(|| "alloc RSA sig limbs"),
            &rsa_signature,
        )?;

        let rsa_sig_hasher = PoseidonHasher::<Scalar>::new(BIGNAT_NUM_LIMBS as u32);
        let rsa_sig_hash = rsa_sig_hasher.hash_in_circuit(
            &mut cs.namespace(|| "hash RSA sig scalars"),
            &rsa_signature_allocatednum_limbs,
        )?;

        let is_rsa_sig_hash_unchanged = alloc_num_equals(
            cs.namespace(|| "RSA sig hashes equality flag"),
            prev_rsa_sig_hash,
            &rsa_sig_hash,
        )?;

        boolean_implies(
            cs.namespace(|| {
                "if RSA opcode is not the first RSA opcode, then RSA sig hash must be unchanged"
            }),
            &is_rsa_opcode_first_rsa.not(),
            &is_rsa_sig_hash_unchanged,
        )?;

        let rsa_sig_power_num_limbs = rsa_sig_power_allocatednum_limbs
            .iter()
            .map(|al| Num {
                num: LinearCombination::from_variable(al.get_variable()),
                value: al.get_value(),
            })
            .collect::<Vec<_>>();

        let rsa_sig_power =
            BigNat::<Scalar>::from_limbs(rsa_sig_power_num_limbs, BIGNAT_LIMB_WIDTH);

        let modulus_bigint = BigInt::from_bytes_be(Sign::Plus, &RSA_MODULUS_HEX_BYTES);
        let modulus_limb_values =
            nat_to_limbs::<Scalar>(&modulus_bigint, BIGNAT_LIMB_WIDTH, BIGNAT_NUM_LIMBS)?;

        let modulus = BigNat::<Scalar>::alloc_from_nat(
            cs.namespace(|| "alloc RSA modulus"),
            || Ok(modulus_bigint),
            BIGNAT_LIMB_WIDTH,
            BIGNAT_NUM_LIMBS,
        )?;
        let modulus_limbs = modulus.as_limbs::<CS>();

        for i in 0..BIGNAT_NUM_LIMBS {
            cs.enforce(
                || "check equality of allocated limb {i} with constant limb",
                |lc| lc + &modulus_limbs[i].num - (modulus_limb_values[i], CS::one()),
                |lc| lc + CS::one(),
                |lc| lc,
            )
        }

        let (_, rsa_sig_power_squared) = rsa_sig_power.mult_mod(
            cs.namespace(|| format!("square the signature power")),
            &rsa_sig_power,
            &modulus,
        )?;

        let (_, rsa_sig_power_times_sig) = rsa_sig_power.mult_mod(
            cs.namespace(|| format!("multiply squared signature power with signature")),
            &rsa_signature,
            &modulus,
        )?;

        let is_opcode_last_rsa_bit = Bit {
            bit: is_opcode_last_rsa.lc(CS::one(), Scalar::ONE),
            value: is_opcode_last_rsa.get_value(),
        };

        let next_rsa_sig_power = BigNat::<Scalar>::mux(
            cs.namespace(|| "select between square and square times sig"),
            &is_opcode_last_rsa_bit,
            &rsa_sig_power_squared,
            &rsa_sig_power_times_sig,
        )?;

        let encoded_msg_bitvec = emsa_pkcs1v15_encode::<Scalar, CS>(&next_sha256_digest_bits);
        // Note that the bits are reversed to as recompose expects bits in little-endian order
        let encoded_msg_bignat =
            BigNat::<Scalar>::recompose(&encoded_msg_bitvec.reversed(), BIGNAT_LIMB_WIDTH);

        let is_signature_valid = encoded_msg_bignat.is_equal(
            cs.namespace(|| "Check that powered signature equals encoded message"),
            &next_rsa_sig_power,
        )?;

        // If opcode is last RSA, then signature must be valid
        boolean_implies(
            cs.namespace(|| "last RSA opcode => RSA signature valid"),
            &is_opcode_last_rsa,
            &is_signature_valid,
        )?;

        let next_rsa_sig_power_allocatednum_limbs = bignat_to_allocatednum_limbs(
            &mut cs.namespace(|| "allocated limbs of next RSA sig power"),
            &next_rsa_sig_power,
        )?;

        let mut io_allocatednums = next_sha256_digest_scalars.clone();
        io_allocatednums.push(nullifier.clone());
        io_allocatednums.extend(next_rsa_sig_power_allocatednum_limbs.into_iter());

        let new_io_hash = aadhaar_io_hasher
            .hash_in_circuit(&mut cs.namespace(|| "hash IO"), &io_allocatednums)?;

        let zero = alloc_constant(cs.namespace(|| "alloc zero"), Scalar::ZERO)?;
        let last_z_out = vec![next_opcode.clone(), zero, nullifier];

        let z_out = conditionally_select_vec(
            cs.namespace(|| "Choose between outputs of last opcode and others"),
            &last_z_out,
            &[next_opcode, new_io_hash, rsa_sig_hash],
            &is_opcode_last_rsa,
        )?;

        Ok(z_out)
    }
}
