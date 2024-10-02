use bellpepper::gadgets::multipack::bytes_to_bits;
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
    poseidon::{AadhaarIOHasher, RSASigHasher},
    qr::AadhaarQRData,
    rsa::{
        emsa_pkcs1v15_encode, BIGNAT_LIMB_WIDTH, BIGNAT_NUM_LIMBS, RSA_MODULUS_HEX_BYTES,
        RSA_MODULUS_LENGTH_BYTES,
    },
    sha256::{
        sha256_digest_to_scalars, sha256_msg_block_sequence, sha256_state_to_bytes,
        SHA256_BLOCK_LENGTH_BYTES, SHA256_DIGEST_LENGTH_BYTES, SHA256_IV,
    },
    util::{
        alloc_num_equals, alloc_num_equals_constant, bignat_to_allocatednum_limbs, boolean_implies,
        conditionally_select_boolean_vec, conditionally_select_vec,
    },
};

pub const OP_SHA256: u64 = 0u64;
pub const OP_RSA_FIRST: u64 = 1u64;
pub const OP_RSA_LAST: u64 = 17u64;

#[derive(Clone, Debug)]
pub struct AadhaarAgeProofCircuit<Scalar>
where
    Scalar: PrimeField,
{
    next_opcode: Scalar,
    num_sha256_msg_blocks_even: bool,
    sha256_msg_block_pair: [u8; 2 * SHA256_BLOCK_LENGTH_BYTES],
    current_sha256_digest_bytes: [u8; SHA256_DIGEST_LENGTH_BYTES],
    rsa_sig: [u8; RSA_MODULUS_LENGTH_BYTES],
    rsa_sig_power: [Scalar; BIGNAT_NUM_LIMBS],
}

impl<Scalar> Default for AadhaarAgeProofCircuit<Scalar>
where
    Scalar: PrimeField,
{
    fn default() -> Self {
        Self {
            next_opcode: Scalar::ZERO,
            num_sha256_msg_blocks_even: false,
            sha256_msg_block_pair: [0u8; 2 * SHA256_BLOCK_LENGTH_BYTES],
            current_sha256_digest_bytes: [0u8; SHA256_DIGEST_LENGTH_BYTES],
            rsa_sig: [0u8; RSA_MODULUS_LENGTH_BYTES],
            rsa_sig_power: [Scalar::ZERO; BIGNAT_NUM_LIMBS],
        }
    }
}

impl<Scalar> AadhaarAgeProofCircuit<Scalar>
where
    Scalar: PrimeFieldBits,
{
    pub fn new_state_sequence(
        aadhaar_qr_data: &AadhaarQRData,
    ) -> Vec<AadhaarAgeProofCircuit<Scalar>> {
        let mut sha256_msg_blocks = sha256_msg_block_sequence(aadhaar_qr_data.signed_data.clone());
        let num_sha256_msg_blocks_even = sha256_msg_blocks.len() % 2 == 0;

        if !num_sha256_msg_blocks_even {
            sha256_msg_blocks.push([0u8; SHA256_BLOCK_LENGTH_BYTES]);
        }

        let mut aadhaar_steps = vec![];
        let sha256_opcode = Scalar::from(OP_SHA256);

        let mut sha256_state = SHA256_IV;

        for i in 0..(sha256_msg_blocks.len() / 2) - 1 {
            aadhaar_steps.push(Self {
                next_opcode: sha256_opcode,
                num_sha256_msg_blocks_even,
                sha256_msg_block_pair: [sha256_msg_blocks[2 * i], sha256_msg_blocks[2 * i + 1]]
                    .concat()
                    .try_into()
                    .unwrap(),
                current_sha256_digest_bytes: sha256_state_to_bytes(sha256_state)
                    .try_into()
                    .unwrap(),
                rsa_sig: [0u8; RSA_MODULUS_LENGTH_BYTES],
                rsa_sig_power: [Scalar::ZERO; BIGNAT_NUM_LIMBS],
            });
            compress256(
                &mut sha256_state,
                &[*GenericArray::from_slice(&sha256_msg_blocks[2 * i])],
            );
            compress256(
                &mut sha256_state,
                &[*GenericArray::from_slice(&sha256_msg_blocks[2 * i + 1])],
            );
        }

        let first_rsa_opcode = Scalar::from(OP_RSA_FIRST);
        // Last SHA256 step
        aadhaar_steps.push(Self {
            next_opcode: first_rsa_opcode, // first RSA opcode
            num_sha256_msg_blocks_even,
            sha256_msg_block_pair: [
                sha256_msg_blocks[sha256_msg_blocks.len() - 2],
                sha256_msg_blocks[sha256_msg_blocks.len() - 1],
            ]
            .concat()
            .try_into()
            .unwrap(),
            current_sha256_digest_bytes: sha256_state_to_bytes(sha256_state).try_into().unwrap(),
            rsa_sig: aadhaar_qr_data.rsa_signature.clone().try_into().unwrap(),
            rsa_sig_power: [Scalar::ZERO; BIGNAT_NUM_LIMBS],
        });

        compress256(
            &mut sha256_state,
            &[*GenericArray::from_slice(
                &sha256_msg_blocks[sha256_msg_blocks.len() - 2],
            )],
        );
        if num_sha256_msg_blocks_even {
            compress256(
                &mut sha256_state,
                &[*GenericArray::from_slice(
                    &sha256_msg_blocks[sha256_msg_blocks.len() - 1],
                )],
            );
        }

        let modulus_bigint = BigInt::from_bytes_be(Sign::Plus, &RSA_MODULUS_HEX_BYTES);
        // Initialize the RSA signature power to the RSA signature value
        let mut rsa_sig_power_bigint =
            BigInt::from_bytes_be(Sign::Plus, &aadhaar_qr_data.rsa_signature);

        // Append 17 RSA steps for repeated squaring of the signature
        for i in 1..=17 {
            let rsa_sig_power_scalars =
                nat_to_limbs::<Scalar>(&rsa_sig_power_bigint, BIGNAT_LIMB_WIDTH, BIGNAT_NUM_LIMBS)
                    .unwrap()
                    .try_into()
                    .unwrap();
            let next_opcode = first_rsa_opcode + Scalar::from(i);

            let rsa_step = Self {
                next_opcode,
                num_sha256_msg_blocks_even,
                sha256_msg_block_pair: [0u8; 2 * SHA256_BLOCK_LENGTH_BYTES],
                current_sha256_digest_bytes: sha256_state_to_bytes(sha256_state)
                    .try_into()
                    .unwrap(),
                rsa_sig: aadhaar_qr_data.rsa_signature.clone().try_into().unwrap(),
                rsa_sig_power: rsa_sig_power_scalars,
            };

            aadhaar_steps.push(rsa_step);
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

    fn get_counter_type(&self) -> nova_snark::StepCounterType {
        nova_snark::StepCounterType::Incremental
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let opcode = &z[0];
        let next_opcode =
            AllocatedNum::alloc(cs.namespace(|| "next opcode"), || Ok(self.next_opcode))?;

        // Constraints related to the opcode input
        cs.enforce(
            || "next opcode is opcode or opcode+1",
            |lc| lc + opcode.get_variable() - next_opcode.get_variable(),
            |lc| lc + CS::one() + opcode.get_variable() - next_opcode.get_variable(),
            |lc| lc,
        );

        let is_next_opcode_equal_to_opcode = alloc_num_equals(
            cs.namespace(|| "opcode and next opcode are equal"),
            opcode,
            &next_opcode,
        )?;

        let is_opcode_sha256 = alloc_num_equals_constant(
            cs.namespace(|| "SHA256 flag"),
            opcode,
            Scalar::from(OP_SHA256),
        )?;
        let is_opcode_last_sha256 = Boolean::and(
            cs.namespace(|| "last SHA256 opcode flag"),
            &is_opcode_sha256,
            &is_next_opcode_equal_to_opcode.not(),
        )?;

        let is_opcode_rsa = is_opcode_sha256.not();
        let _is_opcode_first_rsa = alloc_num_equals_constant(
            cs.namespace(|| "first RSA opcode flag"),
            opcode,
            Scalar::from(OP_RSA_FIRST),
        )?;
        let is_opcode_last_rsa = alloc_num_equals_constant(
            cs.namespace(|| "last RSA opcode flag"),
            opcode,
            Scalar::from(OP_RSA_LAST),
        )?;

        // if opcode is RSA, next opcode should be 1 more
        boolean_implies(
            cs.namespace(|| "if opcode is RSA, then next opcode is incremented"),
            &is_opcode_rsa,
            &is_next_opcode_equal_to_opcode.not(),
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

        let aadhaar_io_hasher = AadhaarIOHasher::<Scalar>::new(2 + BIGNAT_NUM_LIMBS as u32);
        let mut io_hash_preimage = current_sha256_digest_scalars.clone();
        io_hash_preimage.extend(rsa_sig_power_allocatednum_limbs.clone());
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

        // Compute SHA256 hash of the pair of message blocks
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

        let first_or_second_sha256_digest_scalars = conditionally_select_vec(
            cs.namespace(|| "Choose between first and second SHA256 digests"),
            &second_sha256_io.next_digest_scalars,
            &first_sha256_io.next_digest_scalars,
            &num_sha256_msg_blocks_even,
        )?;
        let first_or_second_sha256_digest_bits = conditionally_select_boolean_vec(
            cs.namespace(|| "Choose between first and second SHA256 digest bits"),
            &second_sha256_io.next_digest_bits,
            &first_sha256_io.next_digest_bits,
            &num_sha256_msg_blocks_even,
        )?;
        let next_sha256_digest_scalars = conditionally_select_vec(
            cs.namespace(|| "Choose between current and next SHA256 digests"),
            &first_or_second_sha256_digest_scalars,
            &current_sha256_digest_scalars,
            &is_opcode_sha256,
        )?;
        let next_sha256_digest_bits = conditionally_select_boolean_vec(
            cs.namespace(|| "Choose between current and next SHA256 digest bits"),
            &first_or_second_sha256_digest_bits,
            &first_sha256_io.current_digest_bits,
            &is_opcode_sha256,
        )?;

        // Check that the hash of the non-deterministically provided RSA signature matches
        // the hash of the RSA signatures used in the previous step
        let prev_rsa_sig_hash = &z[2];
        let rsa_signature_bigint = BigInt::from_bytes_be(Sign::Plus, &self.rsa_sig);
        let rsa_signature = BigNat::<Scalar>::alloc_from_nat(
            cs.namespace(|| "alloc RSA modulus"),
            || Ok(rsa_signature_bigint),
            BIGNAT_LIMB_WIDTH,
            BIGNAT_NUM_LIMBS,
        )?;
        let rsa_signature_allocatednum_limbs = bignat_to_allocatednum_limbs(
            &mut cs.namespace(|| "alloc RSA sig limbs"),
            &rsa_signature,
        )?;

        let rsa_sig_hasher = RSASigHasher::<Scalar>::new(BIGNAT_NUM_LIMBS as u32);
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
            cs.namespace(|| "if opcode is RSA, the RSA sig hash must be unchanged"),
            &is_opcode_rsa,
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

        let is_opcode_last_sha256_bit = Bit {
            bit: is_opcode_last_sha256.lc(CS::one(), Scalar::ONE),
            value: is_opcode_last_sha256.get_value(),
        };

        let next_rsa_sig_power = BigNat::<Scalar>::mux(
            cs.namespace(|| "select between next sig power and initial sig value"),
            &is_opcode_last_sha256_bit,
            &next_rsa_sig_power,
            &rsa_signature,
        )?;

        let next_rsa_sig_power_allocatednum_limbs = bignat_to_allocatednum_limbs(
            &mut cs.namespace(|| "allocated limbs of next RSA sig power"),
            &next_rsa_sig_power,
        )?;

        let mut io_allocatednums = next_sha256_digest_scalars.clone();
        io_allocatednums.extend(next_rsa_sig_power_allocatednum_limbs);

        let new_io_hash = aadhaar_io_hasher
            .hash_in_circuit(&mut cs.namespace(|| "hash IO"), &io_allocatednums)?;

        // Pack the final SHA256 hash in two scalars for debugging. TODO: Fix this
        let mut last_z_out = vec![next_opcode.clone()];
        last_z_out.extend(next_sha256_digest_scalars);

        let z_out = conditionally_select_vec(
            cs.namespace(|| "Choose between current and next SHA256 masked digests"),
            &last_z_out,
            &[next_opcode, new_io_hash, rsa_sig_hash],
            &is_opcode_last_rsa,
        )?;

        Ok(z_out)
    }
}
