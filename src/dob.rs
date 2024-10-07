use bellpepper_core::{
    boolean::Boolean, num::AllocatedNum, ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::{PrimeField, PrimeFieldBits};

use crate::{
    sha256::{SHA256_BLOCK_LENGTH_BITS, SHA256_BLOCK_LENGTH_BYTES},
    util::{
        alloc_constant, alloc_num_equals, alloc_num_equals_constant,
        conditionally_select_boolean_vec, less_than, less_than_or_equal, range_check_num,
        range_check_num_conditional,
    },
};

const NUM_DELIMITERS_BEFORE_DOB: u64 = 4;
pub(crate) const DOB_INDEX_BIT_LENGTH: usize = 7; // log2(2 * SHA256_BLOCK_LENGTH_BYTES)

/// Left shift the input vector of `Boolean`s by 8 times
/// the little-endian integer represented by `shift_bits`
pub(crate) fn left_shift_bytes<Scalar, CS>(
    mut cs: CS,
    a: &[Boolean],
    shift_bits: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    // length of vector is 2^(3 + number of bits in shift_bits)
    assert_eq!(1usize << (shift_bits.len() + 3), a.len());

    let mut a_without_shift_i = a.to_vec();

    for i in 0..shift_bits.len() {
        let shift_i = 8usize << i;
        let mut a_with_shift_i = a_without_shift_i
            .clone()
            .drain(shift_i..)
            .collect::<Vec<_>>();
        // append false bits at the end of the vector
        for _ in 0..shift_i {
            a_with_shift_i.push(Boolean::Constant(false));
        }
        a_without_shift_i = conditionally_select_boolean_vec(
            cs.namespace(|| format!("select between shifted and unshifted {i}")),
            &a_with_shift_i,
            &a_without_shift_i,
            &shift_bits[i],
        )?;
    }

    Ok(a_without_shift_i)
}

/// Convert a big-endian character byte in the range 48 to 57
/// to a base10 digit in the 0 to 9. If `condition` is true, check
/// that the character byte does fall in the range 48 to 57.
pub(crate) fn character_byte_to_base10_digit_conditional<Scalar, CS>(
    mut cs: CS,
    a: &[Boolean],
    condition: &Boolean,
) -> Result<AllocatedNum<Scalar>, SynthesisError>
where
    Scalar: PrimeFieldBits,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(a.len(), 8);

    let character_value = a
        .into_iter()
        .enumerate()
        .fold(Some(Scalar::ZERO), |acc, (i, x)| match x.get_value() {
            Some(b) => acc.map(|v| if b { v + Scalar::from(1 << (7 - i)) } else { v }),
            None => None,
        });
    let character = AllocatedNum::alloc(cs.namespace(|| "alloc character"), || {
        character_value.ok_or(SynthesisError::AssignmentMissing)
    })?;

    cs.enforce(
        || "check character consistency with character bits",
        |mut lc| {
            let mut coeff = Scalar::ONE;
            for b in a.iter().rev() {
                lc = lc + &b.lc(CS::one(), coeff);
                coeff = coeff.double();
            }
            lc
        },
        |lc| lc + CS::one(),
        |lc| lc + character.get_variable(),
    );

    // The digits 0 to 9 have ASCII byte codes 48 to 57
    range_check_num_conditional(
        cs.namespace(|| "check that character fits in 6 bits "),
        &character,
        6,
        condition,
    )?;

    let char48 = alloc_constant(cs.namespace(|| "alloc 48"), Scalar::from(48u64))?;
    let char57 = alloc_constant(cs.namespace(|| "alloc 57"), Scalar::from(57u64))?;

    let lower_bound_satisfied =
        less_than_or_equal(cs.namespace(|| "ch >= 48"), &char48, &character, 8)?;
    let upper_bound_satisfied =
        less_than_or_equal(cs.namespace(|| "ch <= 57"), &character, &char57, 8)?;

    let bounds_satisfied = Boolean::and(
        cs.namespace(|| "ch >= 48 AND ch <= 57"),
        &lower_bound_satisfied,
        &upper_bound_satisfied,
    )?;

    let bounds_satisfied_or_condition_is_false = Boolean::or(
        cs.namespace(|| "bounds satisfied OR condition is false"),
        &bounds_satisfied,
        &condition.not(),
    )?;

    Boolean::enforce_equal(
        cs.namespace(|| "bounds satisfied == true"),
        &bounds_satisfied_or_condition_is_false,
        &Boolean::Constant(true),
    )?;

    let digit = AllocatedNum::alloc(cs.namespace(|| "alloc digit"), || {
        character_value
            .map(|v| v - Scalar::from(48u64))
            .ok_or(SynthesisError::AssignmentMissing)
    })?;

    cs.enforce(
        || "check character and digit consistency",
        |lc| lc + digit.get_variable() + (Scalar::from(48u64), CS::one()),
        |lc| lc + CS::one(),
        |lc| lc + character.get_variable(),
    );

    Ok(digit)
}

pub(crate) fn get_day_month_year_conditional<Scalar, CS>(
    mut cs: CS,
    a: &[Boolean],
    condition: &Boolean,
) -> Result<
    (
        AllocatedNum<Scalar>,
        AllocatedNum<Scalar>,
        AllocatedNum<Scalar>,
    ),
    SynthesisError,
>
where
    Scalar: PrimeFieldBits,
    CS: ConstraintSystem<Scalar>,
{
    // Date bytes are in the format DD-MM-YYYY
    assert_eq!(a.len(), 80);

    let day_tens = character_byte_to_base10_digit_conditional(
        cs.namespace(|| "tens place of day"),
        &a[0..8],
        condition,
    )?;
    let day_ones = character_byte_to_base10_digit_conditional(
        cs.namespace(|| "ones place of day"),
        &a[8..16],
        condition,
    )?;
    let day = AllocatedNum::alloc(cs.namespace(|| "alloc day"), || {
        match (day_tens.get_value(), day_ones.get_value()) {
            (Some(d10), Some(d1)) => Ok(d10 * Scalar::from(10u64) + d1),
            (_, _) => Err(SynthesisError::AssignmentMissing),
        }
    })?;
    cs.enforce(
        || "check day and its digits are consistent",
        |lc| lc + (Scalar::from(10u64), day_tens.get_variable()) + day_ones.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + day.get_variable(),
    );

    let month_tens = character_byte_to_base10_digit_conditional(
        cs.namespace(|| "tens place of month"),
        &a[24..32],
        condition,
    )?;
    let month_ones = character_byte_to_base10_digit_conditional(
        cs.namespace(|| "ones place of month"),
        &a[32..40],
        condition,
    )?;
    let month = AllocatedNum::alloc(cs.namespace(|| "alloc month"), || {
        match (month_tens.get_value(), month_ones.get_value()) {
            (Some(m10), Some(m1)) => Ok(m10 * Scalar::from(10u64) + m1),
            _ => Err(SynthesisError::AssignmentMissing),
        }
    })?;
    cs.enforce(
        || "check month and its digits are consistent",
        |lc| lc + (Scalar::from(10u64), month_tens.get_variable()) + month_ones.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + month.get_variable(),
    );

    let year_1000s = character_byte_to_base10_digit_conditional(
        cs.namespace(|| "1000s place of year"),
        &a[48..56],
        condition,
    )?;
    let year_100s = character_byte_to_base10_digit_conditional(
        cs.namespace(|| "100s place of year"),
        &a[56..64],
        condition,
    )?;
    let year_tens = character_byte_to_base10_digit_conditional(
        cs.namespace(|| "10s place of year"),
        &a[64..72],
        condition,
    )?;
    let year_ones = character_byte_to_base10_digit_conditional(
        cs.namespace(|| "1s place of year"),
        &a[72..],
        condition,
    )?;

    let year = AllocatedNum::alloc(cs.namespace(|| "alloc year"), || {
        match (
            year_1000s.get_value(),
            year_100s.get_value(),
            year_tens.get_value(),
            year_ones.get_value(),
        ) {
            (Some(y1000), Some(y100), Some(y10), Some(y1)) => Ok(y1000 * Scalar::from(1000u64)
                + y100 * Scalar::from(100u64)
                + y10 * Scalar::from(10u64)
                + y1),
            _ => Err(SynthesisError::AssignmentMissing),
        }
    })?;
    cs.enforce(
        || "check year and its digits are consistent",
        |lc| {
            lc + (Scalar::from(1000u64), year_1000s.get_variable())
                + (Scalar::from(100u64), year_100s.get_variable())
                + (Scalar::from(10u64), year_tens.get_variable())
                + year_ones.get_variable()
        },
        |lc| lc + CS::one(),
        |lc| lc + year.get_variable(),
    );

    Ok((day, month, year))
}

pub(crate) fn calculate_age_in_years<Scalar, CS>(
    mut cs: CS,
    day: &AllocatedNum<Scalar>,
    month: &AllocatedNum<Scalar>,
    year: &AllocatedNum<Scalar>,
    current_day: &AllocatedNum<Scalar>,
    current_month: &AllocatedNum<Scalar>,
    current_year: &AllocatedNum<Scalar>,
    condition: &Boolean,
) -> Result<AllocatedNum<Scalar>, SynthesisError>
where
    Scalar: PrimeFieldBits,
    CS: ConstraintSystem<Scalar>,
{
    // will work for year < 4096
    range_check_num_conditional(
        cs.namespace(|| "check current year fits in 12 bits"),
        current_year,
        12,
        condition,
    )?;
    range_check_num_conditional(
        cs.namespace(|| "check current month fits in 4 bits"),
        current_month,
        4,
        condition,
    )?;
    range_check_num_conditional(
        cs.namespace(|| "check current day fits in 5 bits"),
        current_day,
        5,
        condition,
    )?;

    let year_diff = AllocatedNum::alloc(cs.namespace(|| "alloc year diff"), || {
        match (year.get_value(), current_year.get_value()) {
            (Some(y), Some(curr_y)) => Ok(curr_y - y),
            _ => Err(SynthesisError::AssignmentMissing),
        }
    })?;

    // 7 bits of age accommodates 128 years. This also ensures that current_year >= year
    range_check_num_conditional(
        cs.namespace(|| "check year difference fits in 7 bits"),
        &year_diff,
        7,
        condition,
    )?;
    cs.enforce(
        || "ensure year + year_diff = current_year",
        |lc| lc + year.get_variable() + year_diff.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + current_year.get_variable(),
    );

    let same_year = alloc_num_equals(cs.namespace(|| "years are the same"), current_year, year)?;
    let current_month_lt_month = less_than(
        cs.namespace(|| "current month < month"),
        current_month,
        month,
        12, // A month in the first 128 block occupies 4 bits but in later blocks can occupy 12 bits
    )?;
    let current_day_lt_day = less_than(
        cs.namespace(|| "current day < day"),
        current_day,
        day,
        12, // A day in the first 128 block occupies 5 bits but in later blocks can occupy 12 bits
    )?;
    let months_equal = alloc_num_equals(
        cs.namespace(|| "check months are equal"),
        month,
        current_month,
    )?;

    let curr_day_lt_in_same_month = Boolean::and(
        cs.namespace(|| "months equal AND lower day"),
        &months_equal,
        &current_day_lt_day,
    )?;

    let month_lt_or_curr_day_lt = Boolean::or(
        cs.namespace(|| "month is lower OR lower day in same month"),
        &current_month_lt_month,
        &curr_day_lt_in_same_month,
    )?;

    let sub_one_year = Boolean::and(
        cs.namespace(|| "NOT(same year) AND (month is lower OR lower day in same month)"),
        &same_year.not(),
        &month_lt_or_curr_day_lt,
    )?;

    let age = AllocatedNum::alloc(cs.namespace(|| "alloc age"), || {
        match (sub_one_year.get_value(), year_diff.get_value()) {
            (Some(b), Some(yd)) => {
                if b {
                    Ok(yd - Scalar::ONE)
                } else {
                    Ok(yd)
                }
            }
            _ => Err(SynthesisError::AssignmentMissing),
        }
    })?;
    cs.enforce(
        || "ensure year_diff - sub_one_year = age",
        |lc| lc + year_diff.get_variable() + &sub_one_year.lc(CS::one(), -Scalar::ONE),
        |lc| lc + CS::one(),
        |lc| lc + age.get_variable(),
    );

    // 7 bits of age accommodates 128 years
    range_check_num_conditional(
        cs.namespace(|| "check age fits in 7 bits"),
        &age,
        7,
        condition,
    )?;

    Ok(age)
}

// The delimiter byte in the Aadhaar QR code is 255.
// The dob_byte_index is the zero-based index of the first
// byte of the date of birth
pub(crate) fn delimiter_count_before_dob_is_correct<Scalar, CS>(
    mut cs: CS,
    a: &[Boolean],
    dob_byte_index: &AllocatedNum<Scalar>,
) -> Result<Boolean, SynthesisError>
where
    Scalar: PrimeFieldBits,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(a.len(), 2 * SHA256_BLOCK_LENGTH_BITS);
    range_check_num(
        cs.namespace(|| "Check that DoB byte index fits in 7 bits"),
        &dob_byte_index,
        DOB_INDEX_BIT_LENGTH,
    )?;

    let mut delimiter_byte_flags = vec![];

    for i in 0..2 * SHA256_BLOCK_LENGTH_BYTES {
        let mut all_ones = Boolean::Constant(true);

        for j in 0..8 {
            all_ones = Boolean::and(
                cs.namespace(|| format!("AND of bit {j} in byte {i}")),
                &all_ones,
                &a[8 * i + j],
            )?;
        }
        delimiter_byte_flags.push(all_ones);
    }

    let mut delim_count_lc = LinearCombination::<Scalar>::zero();
    let mut delim_count_value: Option<Scalar> = Some(Scalar::ZERO);
    for i in 0..2 * SHA256_BLOCK_LENGTH_BYTES {
        let current_byte_index = AllocatedNum::alloc_infallible(
            cs.namespace(|| format!("alloc byte index {i}")),
            || Scalar::from(i as u64),
        );
        let current_index_lt_dob_index = less_than(
            cs.namespace(|| format!("compare current index to DoB byte index {i}")),
            &current_byte_index,
            &dob_byte_index,
            DOB_INDEX_BIT_LENGTH,
        )?;
        let delimiter_before_dob = Boolean::and(
            cs.namespace(|| format!("delimiter before dob {i}")),
            &delimiter_byte_flags[i],
            &current_index_lt_dob_index,
        )?;
        delim_count_lc = delim_count_lc + &delimiter_before_dob.lc(CS::one(), Scalar::ONE);
        delim_count_value = delim_count_value.map(|v| match delimiter_before_dob.get_value() {
            Some(b) => {
                if b {
                    v + Scalar::ONE
                } else {
                    v
                }
            }
            None => v,
        });
    }

    let delim_count_num = AllocatedNum::alloc(cs.namespace(|| "alloc delimiter count"), || {
        delim_count_value.ok_or_else(|| SynthesisError::AssignmentMissing)
    })?;

    cs.enforce(
        || "check that LC and allocated num match",
        |lc| lc + delim_count_num.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + &delim_count_lc,
    );

    let res = alloc_num_equals_constant(
        cs.namespace(|| "Check that the number of delimiters before DoB is 4"),
        &delim_count_num,
        Scalar::from(NUM_DELIMITERS_BEFORE_DOB as u64),
    )?;

    Ok(res)
}

#[cfg(test)]
mod test {
    use bellpepper::gadgets::multipack::bytes_to_bits;
    use bellpepper_core::{boolean::AllocatedBit, test_cs::TestConstraintSystem};
    use pasta_curves::Fp;

    use super::*;

    fn u32_to_bits_be(x: u32) -> Vec<Boolean> {
        (0..32)
            .rev()
            .into_iter()
            .map(|j| Boolean::Constant(x & (1 << j) == (1 << j)))
            .collect::<Vec<_>>()
    }

    fn u32_to_bits_le(x: u32) -> Vec<Boolean> {
        let mut res = u32_to_bits_be(x);
        res.reverse();
        res
    }

    #[test]
    fn test_shift_left() {
        let mut cs = TestConstraintSystem::<Fp>::new();

        let x: u32 = 0xAABBCCDD;
        let x_bits = u32_to_bits_be(x);

        for i in 0..4u32 {
            let x_shift = x << 8 * i;
            let x_shift_bits = u32_to_bits_be(x_shift);
            let mut shift_bits = u32_to_bits_le(i);
            shift_bits.truncate(2);

            let calc_x_shift_bits = left_shift_bytes(
                cs.namespace(|| format!("testing shift {i}")),
                &x_bits,
                &shift_bits,
            )
            .unwrap();

            for j in 0..32 {
                assert_eq!(
                    x_shift_bits[j].get_value().unwrap(),
                    calc_x_shift_bits[j].get_value().unwrap()
                );
            }
        }
    }
    // // 7 bits of age accommodates 128 years. This also ensures that current_year >= year
    // range_check_num(
    //     cs.namespace(|| "check year difference fits in 7 bits"),
    //     &year_diff,
    //     7,
    // )?
    fn alloc_date<Scalar, CS>(mut cs: CS, date_bytes: &[u8]) -> Vec<Boolean>
    where
        Scalar: PrimeField,
        CS: ConstraintSystem<Scalar>,
    {
        assert_eq!(date_bytes.len(), 10);
        let date_bits_values = bytes_to_bits(date_bytes);
        let date_bits = date_bits_values
            .into_iter()
            .enumerate()
            .map(|(i, b)| {
                Boolean::from(
                    AllocatedBit::alloc(cs.namespace(|| format!("alloc bit {i}")), Some(b))
                        .unwrap(),
                )
            })
            .collect::<Vec<_>>();
        date_bits
    }

    #[test]
    fn test_get_day_month_year() {
        let mut cs = TestConstraintSystem::<Fp>::new();

        let date_bytes = b"21-11-1986";
        let date_bits = alloc_date(cs.namespace(|| "alloc date bits"), date_bytes);

        let res = get_day_month_year_conditional(
            cs.namespace(|| "get DD, MM, YYYY"),
            &date_bits,
            &Boolean::Constant(true),
        );
        assert!(res.is_ok());
        let (d, m, y) = res.unwrap();

        assert_eq!(d.get_value().unwrap(), Fp::from(21u64));
        assert_eq!(m.get_value().unwrap(), Fp::from(11u64));
        assert_eq!(y.get_value().unwrap(), Fp::from(1986u64));

        if !cs.is_satisfied() {
            println!("{:?}", cs.which_is_unsatisfied());
        }
        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 363);
    }

    #[test]
    fn test_calculate_age_in_years() {
        let mut cs = TestConstraintSystem::<Fp>::new();
        let date_bytes = b"01-01-2004";
        let curr_date_bytes = b"01-01-2024";
        let date_bits = alloc_date(cs.namespace(|| "alloc date bits"), date_bytes);
        let curr_date_bits = alloc_date(cs.namespace(|| "alloc curr_date bits"), curr_date_bytes);

        let res = get_day_month_year_conditional(
            cs.namespace(|| "get DD, MM, YYYY"),
            &date_bits,
            &Boolean::Constant(true),
        );
        assert!(res.is_ok());
        let (d, m, y) = res.unwrap();

        let res = get_day_month_year_conditional(
            cs.namespace(|| "get current DD, MM, YYYY"),
            &curr_date_bits,
            &Boolean::Constant(true),
        );
        assert!(res.is_ok());
        let (cd, cm, cy) = res.unwrap();

        let res = calculate_age_in_years(
            cs.namespace(|| "calc age"),
            &d,
            &m,
            &y,
            &cd,
            &cm,
            &cy,
            &Boolean::Constant(true),
        );
        assert!(res.is_ok());
        let age = res.unwrap();

        assert_eq!(age.get_value().unwrap(), Fp::from(20u64));

        if !cs.is_satisfied() {
            println!("{:?}", cs.which_is_unsatisfied());
        }
        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 807);
    }
}
