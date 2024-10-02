use bellpepper::gadgets::{
    multipack::{bytes_to_bits, compute_multipacking, pack_bits},
    sha256::sha256_compression_function,
    uint32::UInt32,
};
use bellpepper_core::{boolean::Boolean, num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeFieldBits;
use generic_array::{typenum::U64, GenericArray};

pub(crate) const SHA256_BLOCK_LENGTH_BYTES: usize = 64;
pub(crate) const SHA256_BLOCK_LENGTH_BITS: usize = 512;
pub(crate) const SHA256_DIGEST_LENGTH_BYTES: usize = 32;
pub(crate) const SHA256_DIGEST_LENGTH_BITS: usize = 256;
pub(crate) const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub(crate) fn sha256_state_to_bytes(state: [u32; 8]) -> Vec<u8> {
    state.into_iter().flat_map(|x| x.to_be_bytes()).collect()
}

pub(crate) fn sha256_digest_to_scalars<Scalar>(
    digest: &[u8; SHA256_DIGEST_LENGTH_BYTES],
) -> Vec<Scalar>
where
    Scalar: PrimeFieldBits,
{
    compute_multipacking(&bytes_to_bits(digest))
}

pub fn sha256_initial_digest_scalars<Scalar>() -> Vec<Scalar>
where
    Scalar: PrimeFieldBits,
{
    let initial_vector: [u8; SHA256_DIGEST_LENGTH_BYTES] = sha256_state_to_bytes(SHA256_IV)
        .as_slice()
        .try_into()
        .unwrap();
    sha256_digest_to_scalars(&initial_vector)
}

pub fn sha256_scalars_to_digest<Scalar>(scalars: Vec<Scalar>) -> [u8; SHA256_DIGEST_LENGTH_BYTES]
where
    Scalar: PrimeFieldBits,
{
    assert!((Scalar::CAPACITY as usize) * scalars.len() >= SHA256_DIGEST_LENGTH_BITS);
    let mut digest_bits = scalars
        .into_iter()
        .flat_map(|s| s.to_le_bits().into_iter().take(Scalar::CAPACITY as usize))
        .collect::<Vec<bool>>();
    digest_bits.truncate(SHA256_DIGEST_LENGTH_BITS);

    assert_eq!(digest_bits.len() % 8, 0);
    assert_eq!(digest_bits.len(), SHA256_DIGEST_LENGTH_BITS);

    let digest: Vec<u8> = digest_bits
        .chunks(8)
        .map(|c| {
            let mut b = 0u8;
            for i in 0..8 {
                // The digest bits are interpreted as big-endian bytes
                if c[i] {
                    b += 1 << (7 - i);
                }
            }
            b
        })
        .collect::<Vec<_>>();

    digest.as_slice().try_into().unwrap()
}

fn padded_input_to_blocks(input: Vec<u8>) -> Vec<GenericArray<u8, U64>> {
    assert!(input.len() % SHA256_BLOCK_LENGTH_BYTES == 0);
    let blocks = input.chunks(SHA256_BLOCK_LENGTH_BYTES).collect::<Vec<_>>();

    blocks
        .iter()
        .map(|a| GenericArray::<u8, U64>::from_slice(a).clone())
        .collect()
}

fn add_sha256_padding(input: Vec<u8>) -> Vec<u8> {
    let length_in_bits = (input.len() * 8) as u64;
    let mut padded_input = input;

    // appending a single '1' bit followed by 7 '0' bits
    // This is because the input is a byte vector
    padded_input.push(128u8);

    // Append zeros until the padded input (including 64-byte length)
    // is a multiple of 64 bytes. Note that input is always a byte vector.
    while (padded_input.len() + 8) % SHA256_BLOCK_LENGTH_BYTES != 0 {
        padded_input.push(0u8);
    }
    padded_input.append(&mut length_in_bits.to_be_bytes().to_vec());
    padded_input
}

pub(crate) fn sha256_msg_block_sequence(input: Vec<u8>) -> Vec<[u8; SHA256_BLOCK_LENGTH_BYTES]> {
    let padded_input = add_sha256_padding(input);
    let blocks_vec: Vec<GenericArray<u8, U64>> = padded_input_to_blocks(padded_input);

    blocks_vec
        .into_iter()
        .map(|b| b.try_into().unwrap())
        .collect()
}

pub(crate) struct Sha256IOState<Scalar: PrimeFieldBits> {
    pub(crate) current_digest_bits: Vec<Boolean>,
    pub(crate) next_digest_scalars: Vec<AllocatedNum<Scalar>>,
    pub(crate) next_digest_bits: Vec<Boolean>,
}

pub(crate) fn compress<Scalar, CS>(
    cs: &mut CS,
    msg_block: &[Boolean],
    current_digest: &[AllocatedNum<Scalar>],
) -> Result<Sha256IOState<Scalar>, SynthesisError>
where
    Scalar: PrimeFieldBits,
    CS: ConstraintSystem<Scalar>,
{
    assert!((Scalar::CAPACITY as usize) * current_digest.len() >= SHA256_DIGEST_LENGTH_BITS);
    assert_eq!(msg_block.len(), SHA256_BLOCK_LENGTH_BITS);

    let mut current_digest_bits = current_digest
        .iter()
        .enumerate()
        .flat_map(|(i, d)| {
            d.to_bits_le(cs.namespace(|| format!("current digest bits from scalar {i}")))
                .unwrap()
                .into_iter()
                .take(Scalar::CAPACITY as usize)
        })
        .collect::<Vec<Boolean>>();
    current_digest_bits.truncate(SHA256_DIGEST_LENGTH_BITS);

    let mut current_state: Vec<UInt32> = vec![];
    for c in current_digest_bits.chunks(32) {
        current_state.push(UInt32::from_bits_be(c));
    }
    assert_eq!(current_state.len(), 8);

    // SHA256 compression function application
    let next_state: Vec<UInt32> = sha256_compression_function(&mut *cs, msg_block, &current_state)?;
    assert_eq!(next_state.len(), 8);

    let next_digest_bits: Vec<Boolean> = next_state
        .into_iter()
        .flat_map(|u| u.into_bits_be())
        .collect();
    assert_eq!(next_digest_bits.len(), SHA256_DIGEST_LENGTH_BITS);

    let z_out = next_digest_bits
        .chunks(Scalar::CAPACITY as usize)
        .into_iter()
        .enumerate()
        .map(|(i, c)| {
            pack_bits(
                cs.namespace(|| format!("Packing a chunk {i} of next digest bits")),
                c,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    Ok(Sha256IOState {
        current_digest_bits,
        next_digest_scalars: z_out,
        next_digest_bits,
    })
}
