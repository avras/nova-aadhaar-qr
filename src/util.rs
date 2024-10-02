use bellpepper::gadgets::Assignment;
use bellpepper_core::{
    boolean::{AllocatedBit, Boolean},
    num::AllocatedNum,
    ConstraintSystem, SynthesisError,
};
use bellpepper_nonnative::mp::bignat::BigNat;
use ff::PrimeField;

use crate::rsa::BIGNAT_NUM_LIMBS;

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
