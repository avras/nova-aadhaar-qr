use bellpepper::gadgets::Assignment;
use bellpepper_core::{
    boolean::{AllocatedBit, Boolean},
    num::AllocatedNum,
    ConstraintSystem, LinearCombination, SynthesisError, Variable,
};
use bellpepper_nonnative::mp::bignat::BigNat;
use ff::{PrimeField, PrimeFieldBits};

use crate::rsa::BIGNAT_NUM_LIMBS;

/// Allocate a variable equal to a constant
pub fn alloc_constant<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: Scalar,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    let num = AllocatedNum::alloc(cs.namespace(|| "alloc num"), || Ok(value))?;

    cs.enforce(
        || "check allocated variable equals constant",
        |lc| lc + num.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + (value, CS::one()),
    );

    Ok(num)
}

// From Nova/src/gadgets/utils.rs with Boolean return value instead of AllocatedBit
/// Check that two numbers are equal and return a bit
pub(crate) fn alloc_num_equals<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    a: &AllocatedNum<Scalar>,
    b: &AllocatedNum<Scalar>,
) -> Result<Boolean, SynthesisError> {
    // Allocate and constrain `r`: result boolean bit.
    // It equals `true` if `a` equals `b`, `false` otherwise
    let r_value = match (a.get_value(), b.get_value()) {
        (Some(a), Some(b)) => Some(a == b),
        _ => None,
    };

    let r = AllocatedBit::alloc(cs.namespace(|| "r"), r_value)?;

    // Allocate t s.t. t=1 if z1 == z2 else 1/(z1 - z2)

    let t = AllocatedNum::alloc(cs.namespace(|| "t"), || {
        Ok(if *a.get_value().get()? == *b.get_value().get()? {
            Scalar::ONE
        } else {
            (*a.get_value().get()? - *b.get_value().get()?)
                .invert()
                .unwrap()
        })
    })?;

    cs.enforce(
        || "t*(a - b) = 1 - r",
        |lc| lc + t.get_variable(),
        |lc| lc + a.get_variable() - b.get_variable(),
        |lc| lc + CS::one() - r.get_variable(),
    );

    cs.enforce(
        || "r*(a - b) = 0",
        |lc| lc + r.get_variable(),
        |lc| lc + a.get_variable() - b.get_variable(),
        |lc| lc,
    );

    Ok(Boolean::from(r))
}

/// Check that an allocated number equals a constant and return a bit
pub(crate) fn alloc_num_equals_constant<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    a: &AllocatedNum<Scalar>,
    b: Scalar,
) -> Result<Boolean, SynthesisError> {
    // Allocate and constrain `r`: result boolean bit.
    // It equals `true` if `a` equals `b`, `false` otherwise
    let r_value = match a.get_value() {
        Some(a) => Some(a == b),
        _ => None,
    };

    let r = AllocatedBit::alloc(cs.namespace(|| "r"), r_value)?;

    // Allocate t s.t. t=1 if a == b else 1/(a - b)

    let t = AllocatedNum::alloc(cs.namespace(|| "t"), || {
        Ok(if *a.get_value().get()? == b {
            Scalar::ONE
        } else {
            (*a.get_value().get()? - b).invert().unwrap()
        })
    })?;

    cs.enforce(
        || "t*(a - b) = 1 - r",
        |lc| lc + t.get_variable(),
        |lc| lc + a.get_variable() - (b, CS::one()),
        |lc| lc + CS::one() - r.get_variable(),
    );

    cs.enforce(
        || "r*(a - b) = 0",
        |lc| lc + r.get_variable(),
        |lc| lc + a.get_variable() - (b, CS::one()),
        |lc| lc,
    );

    Ok(Boolean::from(r))
}

/// Checks that a implies b by checking if not(a) or b == true
pub(crate) fn boolean_implies<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    a: &Boolean,
    b: &Boolean,
) -> Result<(), SynthesisError> {
    // A => B is the same as not(A) OR B
    let a_implies_b = Boolean::or(cs.namespace(|| "not(a) OR b"), &a.not(), b)?;
    Boolean::enforce_equal(
        cs.namespace(|| "not(a) OR b == true"),
        &a_implies_b,
        &Boolean::Constant(true),
    )
}

// From Nova/src/gadgets/utils.rs
/// If condition return a otherwise b
pub(crate) fn conditionally_select<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    a: &AllocatedNum<Scalar>,
    b: &AllocatedNum<Scalar>,
    condition: &Boolean,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
        if *condition.get_value().get()? {
            Ok(*a.get_value().get()?)
        } else {
            Ok(*b.get_value().get()?)
        }
    })?;

    // a * condition + b*(1-condition) = c ->
    // a * condition - b*condition = c - b
    cs.enforce(
        || "conditional select constraint",
        |lc| lc + a.get_variable() - b.get_variable(),
        |_| condition.lc(CS::one(), Scalar::ONE),
        |lc| lc + c.get_variable() - b.get_variable(),
    );

    Ok(c)
}

// From Nova/src/gadgets/utils.rs
/// If condition return a otherwise b
pub(crate) fn conditionally_select_vec<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    a: &[AllocatedNum<Scalar>],
    b: &[AllocatedNum<Scalar>],
    condition: &Boolean,
) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
    a.iter()
        .zip(b.iter())
        .enumerate()
        .map(|(i, (a, b))| {
            conditionally_select(cs.namespace(|| format!("select_{i}")), a, b, condition)
        })
        .collect::<Result<Vec<AllocatedNum<Scalar>>, SynthesisError>>()
}

// if condition is true, select a vector. Otherwise, select b vector.
pub(crate) fn conditionally_select_boolean_vec<Scalar, CS>(
    mut cs: CS,
    a: &[Boolean],
    b: &[Boolean],
    condition: &Boolean,
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter())
        .enumerate()
        .map(|(i, (a, b))| {
            Boolean::sha256_ch(cs.namespace(|| format!("select {i}")), condition, a, b)
        })
        .collect::<Result<Vec<Boolean>, SynthesisError>>()
}

pub(crate) fn bignat_to_allocatednum_limbs<Scalar, CS>(
    cs: &mut CS,
    a: &BigNat<Scalar>,
) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let allocatednum_limbs = a
        .as_limbs::<CS>()
        .iter()
        .enumerate()
        .map(|(i, n)| {
            AllocatedNum::alloc(cs.namespace(|| format!("alloc limb {i}")), || {
                Ok(n.value.unwrap())
            })
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;

    for i in 0..BIGNAT_NUM_LIMBS {
        cs.enforce(
            || "check equality of allocated sig power limb {i} with num sig power limb",
            |lc| {
                lc + &a.as_limbs::<CS>()[i].num
                    - (Scalar::ONE, allocatednum_limbs[i].get_variable())
            },
            |lc| lc + CS::one(),
            |lc| lc,
        )
    }
    Ok(allocatednum_limbs)
}

/// Range check an AllocatedNum
///
/// Based on `fits_in_bits` of `bellperson-nonnative`
pub(crate) fn range_check_num<Scalar, CS>(
    mut cs: CS,
    a: &AllocatedNum<Scalar>,
    num_bits: usize,
) -> Result<(), SynthesisError>
where
    Scalar: PrimeFieldBits,
    CS: ConstraintSystem<Scalar>,
{
    let value_bits = a.get_value().map(|v| v.to_le_bits());

    // Allocate all but the first bit.
    let bits: Vec<Variable> = (1..num_bits)
        .map(|i| {
            cs.alloc(
                || format!("bit {i}"),
                || {
                    if let Some(bits) = &value_bits {
                        let r = if bits[i] { Scalar::ONE } else { Scalar::ZERO };
                        Ok(r)
                    } else {
                        Err(SynthesisError::AssignmentMissing)
                    }
                },
            )
        })
        .collect::<Result<_, _>>()?;

    for (i, v) in bits.iter().enumerate() {
        cs.enforce(
            || format!("bit {i} is bit"),
            |lc| lc + *v,
            |lc| lc + CS::one() - *v,
            |lc| lc,
        )
    }

    // Last bit
    cs.enforce(
        || "last bit of variable is a bit".to_string(),
        |mut lc| {
            let mut f = Scalar::ONE;
            lc = lc + a.get_variable();
            for v in bits.iter() {
                f = f.double();
                lc = lc - (f, *v);
            }
            lc
        },
        |mut lc| {
            lc = lc + CS::one();
            let mut f = Scalar::ONE;
            lc = lc - a.get_variable();
            for v in bits.iter() {
                f = f.double();
                lc = lc + (f, *v);
            }
            lc
        },
        |lc| lc,
    );

    Ok(())
}

/// Range check an AllocatedNum if `condition` is `true`
pub(crate) fn range_check_num_conditional<Scalar, CS>(
    mut cs: CS,
    a: &AllocatedNum<Scalar>,
    num_bits: usize,
    condition: &Boolean,
) -> Result<(), SynthesisError>
where
    Scalar: PrimeFieldBits,
    CS: ConstraintSystem<Scalar>,
{
    let a_bit_values = a.get_value().map(|v| v.to_le_bits());

    let a_bits = (0..num_bits)
        .map(|i| {
            AllocatedBit::alloc(
                cs.namespace(|| format!("alloc bit {i}")),
                a_bit_values.as_ref().map(|arr| arr[i]),
            )
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?
        .into_iter()
        .map(Boolean::from)
        .collect::<Vec<Boolean>>();

    let mut diff_lc = LinearCombination::<Scalar>::zero();
    let mut coeff = Scalar::ONE;
    // Recompose bits
    for b in a_bits.iter() {
        diff_lc = diff_lc + &b.lc(CS::one(), coeff);
        coeff = coeff.double();
    }
    // Subtract the allocated number
    diff_lc = diff_lc - a.get_variable();

    cs.enforce(
        || "Check recomposed value minus original value is zero if condition is true",
        |lc| lc + &diff_lc,
        |lc| lc + &condition.lc(CS::one(), Scalar::ONE),
        |lc| lc,
    );

    Ok(())
}

/// Decomposes an allocated number `a` to `n_bits` allocated
/// boolean values. Returns a little-endian vector of `Boolean`
///  variables if `a` is in the range `0` to `(1 << n_bits) - 1`.
/// Otherwise, it throws an error.
pub(crate) fn num_to_bits<Scalar, CS>(
    mut cs: CS,
    a: &AllocatedNum<Scalar>,
    n_bits: usize,
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: PrimeFieldBits,
    CS: ConstraintSystem<Scalar>,
{
    let a_bit_values = match a.get_value() {
        Some(a_val) => {
            let mut a_bools = a_val
                .to_le_bits()
                .iter()
                .map(|b| if *b { true } else { false })
                .collect::<Vec<bool>>();
            a_bools.truncate(n_bits);
            Some(a_bools)
        }
        None => None,
    };

    let a_bits = (0..n_bits)
        .map(|i| {
            AllocatedBit::alloc(
                cs.namespace(|| format!("alloc bit {i}")),
                a_bit_values.as_ref().map(|arr| arr[i]),
            )
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?
        .into_iter()
        .map(Boolean::from)
        .collect::<Vec<Boolean>>();

    let mut recompose_lc = LinearCombination::<Scalar>::zero();
    let mut coeff = Scalar::ONE;
    for b in a_bits.iter() {
        recompose_lc = recompose_lc + &b.lc(CS::one(), coeff);
        coeff = coeff.double();
    }
    cs.enforce(
        || "Check recomposed value equals original value",
        |lc| lc + &recompose_lc,
        |lc| lc + CS::one(),
        |lc| lc + a.get_variable(),
    );

    Ok(a_bits)
}

/// Takes two allocated numbers (a, b) that are assumed
/// to be in the range `0` to `(1 << n_bits) - 1`.
/// Returns an allocated `Boolean`` variable with value `true`
/// if the `a` and `b` are such that a is strictly less than b,
/// `false` otherwise. Implementation is based on LessThan in
/// circomlib https://github.com/iden3/circomlib/blob/master/circuits/comparators.circom
pub(crate) fn less_than<Scalar, CS>(
    mut cs: CS,
    a: &AllocatedNum<Scalar>,
    b: &AllocatedNum<Scalar>,
    n_bits: usize,
) -> Result<Boolean, SynthesisError>
where
    Scalar: PrimeFieldBits,
    CS: ConstraintSystem<Scalar>,
{
    assert!(n_bits < Scalar::CAPACITY as usize);
    let mut power_of_two = Scalar::ONE;
    for _ in 0..n_bits {
        power_of_two = power_of_two.double();
    }

    let offset_diff = AllocatedNum::alloc(cs.namespace(|| "alloc a + 2^n_bits - b"), || {
        match (a.get_value(), b.get_value()) {
            (Some(a_val), Some(b_val)) => Ok(a_val + power_of_two - b_val),
            (_, _) => Err(SynthesisError::AssignmentMissing),
        }
    })?;

    cs.enforce(
        || "check value of offset_diff",
        |lc| lc + offset_diff.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + a.get_variable() + (power_of_two, CS::one()) - b.get_variable(),
    );

    let offset_diff_bits = num_to_bits(
        &mut cs.namespace(|| "decompose offset_diff"),
        &offset_diff,
        n_bits + 1,
    )?;

    Ok(offset_diff_bits[n_bits].not())
}

// Takes two allocated numbers (a, b) that are assumed
/// to be in the range `0` to `(1 << n_bits) - 1`.
/// Returns an allocated `Boolean`` variable with value `true`
/// if the `a` and `b` are such that a is less than or equal to b,
/// `false` otherwise
pub(crate) fn less_than_or_equal<Scalar, CS>(
    mut cs: CS,
    a: &AllocatedNum<Scalar>,
    b: &AllocatedNum<Scalar>,
    n_bits: usize,
) -> Result<Boolean, SynthesisError>
where
    Scalar: PrimeFieldBits,
    CS: ConstraintSystem<Scalar>,
{
    let is_b_lt_a = less_than(cs.namespace(|| "b < a"), b, a, n_bits)?;
    Ok(is_b_lt_a.not())
}
