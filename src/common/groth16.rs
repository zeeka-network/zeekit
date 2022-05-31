use crate::BellmanFr;

use bellman::gadgets::boolean::{AllocatedBit, Boolean};
use bellman::gadgets::num::AllocatedNum;
use bellman::{ConstraintSystem, LinearCombination, SynthesisError};
use ff::{Field, PrimeFieldBits};
use std::ops::AddAssign;

pub fn bit_or<'a, CS: ConstraintSystem<BellmanFr>>(
    cs: &mut CS,
    a: &Boolean,
    b: &Boolean,
) -> Result<Boolean, SynthesisError> {
    Ok(Boolean::and(&mut *cs, &a.not(), &b.not())?.not())
}

// Check if a number is zero, 2 constraints
pub fn is_zero<'a, CS: ConstraintSystem<BellmanFr>>(
    cs: &mut CS,
    a: AllocatedNum<BellmanFr>,
) -> Result<AllocatedBit, SynthesisError> {
    let out = AllocatedBit::alloc(&mut *cs, a.get_value().map(|a| a.is_zero().into()))?;
    let inv = AllocatedNum::alloc(&mut *cs, || {
        a.get_value()
            .map(|a| {
                if a.is_zero().into() {
                    BellmanFr::zero()
                } else {
                    a.invert().unwrap()
                }
            })
            .ok_or(SynthesisError::AssignmentMissing)
    })?;
    cs.enforce(
        || "calc out",
        |lc| lc - a.get_variable(),
        |lc| lc + inv.get_variable(),
        |lc| lc + out.get_variable() - CS::one(),
    );
    cs.enforce(
        || "calc out",
        |lc| lc + out.get_variable(),
        |lc| lc + a.get_variable(),
        |lc| lc,
    );
    Ok(out)
}

// Check a == b, two constraints
pub fn is_equal<'a, CS: ConstraintSystem<BellmanFr>>(
    cs: &mut CS,
    a: AllocatedNum<BellmanFr>,
    b: AllocatedNum<BellmanFr>,
) -> Result<AllocatedBit, SynthesisError> {
    let out = AllocatedBit::alloc(&mut *cs, a.get_value().map(|a| a.is_zero().into()))?;
    let inv = AllocatedNum::alloc(&mut *cs, || {
        a.get_value()
            .map(|a| {
                if a.is_zero().into() {
                    BellmanFr::zero()
                } else {
                    a.invert().unwrap()
                }
            })
            .ok_or(SynthesisError::AssignmentMissing)
    })?;
    cs.enforce(
        || "calc out",
        |lc| lc - a.get_variable() + b.get_variable(),
        |lc| lc + inv.get_variable(),
        |lc| lc + out.get_variable() - CS::one(),
    );
    cs.enforce(
        || "calc out",
        |lc| lc + out.get_variable(),
        |lc| lc + a.get_variable() - b.get_variable(),
        |lc| lc,
    );
    Ok(out)
}

// Convert number to binary repr, bits + 1 constraints
pub fn to_bits<'a, CS: ConstraintSystem<BellmanFr>>(
    cs: &mut CS,
    a: AllocatedNum<BellmanFr>,
    num_bits: usize,
) -> Result<Vec<AllocatedBit>, SynthesisError> {
    let mut result = Vec::new();
    let mut coeff = BellmanFr::one();
    let mut all = LinearCombination::<BellmanFr>::zero();
    let bits: Option<Vec<bool>> = a
        .get_value()
        .map(|v| v.to_le_bits().iter().map(|b| *b).collect());
    for i in 0..num_bits {
        let bit = AllocatedBit::alloc(&mut *cs, bits.as_ref().map(|b| b[i]))?;
        all = all + (coeff, bit.get_variable());
        result.push(bit);
        coeff = coeff.double();
    }
    cs.enforce(
        || "check",
        |lc| lc + &all,
        |lc| lc + CS::one(),
        |lc| lc + a.get_variable(),
    );
    Ok(result)
}

// Convert number to binary repr and negate
pub fn to_bits_neg<'a, CS: ConstraintSystem<BellmanFr>>(
    cs: &mut CS,
    a: AllocatedNum<BellmanFr>,
    num_bits: usize,
) -> Result<Vec<AllocatedBit>, SynthesisError> {
    let mut result = Vec::new();
    let mut coeff = BellmanFr::one();
    let mut all = LinearCombination::<BellmanFr>::zero();
    let two_bits = BellmanFr::from(2).pow_vartime(&[num_bits as u64, 0, 0, 0]);
    let bits: Option<Vec<bool>> = a
        .get_value()
        .map(|v| (two_bits - v).to_le_bits().iter().map(|b| *b).collect());
    for i in 0..num_bits {
        let bit = AllocatedBit::alloc(&mut *cs, bits.as_ref().map(|b| b[i]))?;
        all = all + (coeff, bit.get_variable());
        result.push(bit);
        coeff = coeff.double();
    }
    let is_zero = is_zero(&mut *cs, a.clone())?;
    all = all + (two_bits, is_zero.get_variable());
    cs.enforce(
        || "neg check",
        |lc| lc + &all,
        |lc| lc + CS::one(),
        |lc| lc + (two_bits, CS::one()) - a.get_variable(),
    );
    Ok(result)
}

// Convert number to u64 and negate
pub fn sum_u64<'a, CS: ConstraintSystem<BellmanFr>>(
    cs: &mut CS,
    a: Vec<AllocatedBit>,
    b: Vec<AllocatedBit>,
) -> Result<AllocatedNum<BellmanFr>, SynthesisError> {
    let sum = AllocatedNum::alloc(&mut *cs, || {
        let mut result = BellmanFr::zero();
        let mut coeff = BellmanFr::one();
        for (a_bit, b_bit) in a.iter().zip(b.iter()) {
            if a_bit.get_value().ok_or(SynthesisError::AssignmentMissing)? {
                result.add_assign(&coeff);
            }
            if b_bit.get_value().ok_or(SynthesisError::AssignmentMissing)? {
                result.add_assign(&coeff);
            }
            coeff = coeff.double();
        }
        Ok(result)
    })?;
    let mut coeff = BellmanFr::one();
    let mut all = LinearCombination::<BellmanFr>::zero();
    for i in 0..64 {
        all = all + (coeff, a[i].get_variable());
        all = all + (coeff, b[i].get_variable());
        coeff = coeff.double();
    }
    cs.enforce(
        || "sum u64s check",
        |lc| lc + &all,
        |lc| lc + CS::one(),
        |lc| lc + sum.get_variable(),
    );
    Ok(sum)
}

pub fn bit_lt<'a, CS: ConstraintSystem<BellmanFr>>(
    cs: &mut CS,
    a: &Boolean,
    b: &Boolean,
) -> Result<Boolean, SynthesisError> {
    Boolean::and(&mut *cs, &a.not(), &b)
}

// ~200 constraints
pub fn lte<'a, CS: ConstraintSystem<BellmanFr>>(
    cs: &mut CS,
    a: AllocatedNum<BellmanFr>,
    b: AllocatedNum<BellmanFr>,
) -> Result<AllocatedBit, SynthesisError> {
    let a = to_bits(&mut *cs, a, 64)?;
    let b_neg = to_bits_neg(&mut *cs, b, 64)?;
    let c = sum_u64(&mut *cs, a, b_neg)?;
    let c_bits = to_bits(&mut *cs, c, 65)?;
    Ok(c_bits[63].clone())
}

pub fn assert_equal<'a, CS: ConstraintSystem<BellmanFr>>(
    cs: &mut CS,
    enabled: AllocatedBit,
    a: AllocatedNum<BellmanFr>,
    b: AllocatedNum<BellmanFr>,
) -> Result<(), SynthesisError> {
    let enabled_value = enabled.get_value();
    let enabled_in_a = cs.alloc(
        || "",
        || {
            enabled_value
                .map(|e| {
                    if e {
                        a.get_value()
                    } else {
                        Some(BellmanFr::zero())
                    }
                })
                .unwrap_or(None)
                .ok_or(SynthesisError::AssignmentMissing)
        },
    )?;
    cs.enforce(
        || "enabled * a == enabled_in_a",
        |lc| lc + enabled.get_variable(),
        |lc| lc + a.get_variable(),
        |lc| lc + enabled_in_a,
    );
    cs.enforce(
        || "enabled * b == enabled_in_a",
        |lc| lc + enabled.get_variable(),
        |lc| lc + b.get_variable(),
        |lc| lc + enabled_in_a,
    );
    Ok(())
}
