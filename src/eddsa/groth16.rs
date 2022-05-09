use crate::mimc;
use crate::BellmanFr;

use super::curve::{PointAffine, A, BASE, D, ORDER};

use bellman::gadgets::boolean::{AllocatedBit, Boolean};
use bellman::gadgets::num::AllocatedNum;
use bellman::{ConstraintSystem, SynthesisError};
use std::ops::*;

#[derive(Clone)]
pub struct AllocatedPoint {
    pub x: AllocatedNum<BellmanFr>,
    pub y: AllocatedNum<BellmanFr>,
}

pub fn add_point<'a, CS: ConstraintSystem<BellmanFr>>(
    cs: &mut CS,
    curve_a: AllocatedNum<BellmanFr>,
    curve_d: AllocatedNum<BellmanFr>,
    a: AllocatedPoint,
    b: AllocatedPoint,
) -> Result<AllocatedPoint, SynthesisError> {
    let sum_value =
        a.x.get_value()
            .zip(a.y.get_value())
            .zip(b.x.get_value().zip(b.y.get_value()))
            .map(|((a_x, a_y), (b_x, b_y))| {
                let mut sum = PointAffine(a_x.into(), a_y.into());
                sum.add_assign(&PointAffine(b_x.into(), b_y.into()));
                sum
            });
    let sum_x = AllocatedNum::alloc(&mut *cs, || {
        sum_value
            .map(|v| v.0.into())
            .ok_or(SynthesisError::AssignmentMissing)
    })?;
    let sum_y = AllocatedNum::alloc(&mut *cs, || {
        sum_value
            .map(|v| v.1.into())
            .ok_or(SynthesisError::AssignmentMissing)
    })?;

    let common = curve_d
        .mul(&mut *cs, &a.x)?
        .mul(&mut *cs, &b.x)?
        .mul(&mut *cs, &a.y)?
        .mul(&mut *cs, &b.y)?;

    let x_1 = a.x.mul(&mut *cs, &b.y)?;
    let x_2 = a.y.mul(&mut *cs, &b.x)?;
    cs.enforce(
        || "x_1 + x_2 == sum_x * (1 + common)",
        |lc| lc + CS::one() + common.get_variable(),
        |lc| lc + sum_x.get_variable(),
        |lc| lc + x_1.get_variable() + x_2.get_variable(),
    );

    let y_1 = a.y.mul(&mut *cs, &b.y)?;
    let y_2 = curve_a.mul(&mut *cs, &a.x)?.mul(&mut *cs, &b.x)?;
    cs.enforce(
        || "y_1 - y_2 == sum_y * (1 - common)",
        |lc| lc + CS::one() - common.get_variable(),
        |lc| lc + sum_y.get_variable(),
        |lc| lc + y_1.get_variable() - y_2.get_variable(),
    );

    Ok(AllocatedPoint { x: sum_x, y: sum_y })
}

pub fn mul_point<'a, CS: ConstraintSystem<BellmanFr>>(
    cs: &mut CS,
    curve_a: AllocatedNum<BellmanFr>,
    curve_d: AllocatedNum<BellmanFr>,
    base: AllocatedPoint,
    b: AllocatedNum<BellmanFr>,
) -> Result<AllocatedPoint, SynthesisError> {
    let bits = b.to_bits_le(&mut *cs)?;
    let mut result = AllocatedPoint {
        x: AllocatedNum::alloc(&mut *cs, || Ok(BellmanFr::zero()))?,
        y: AllocatedNum::alloc(&mut *cs, || Ok(BellmanFr::one()))?,
    };
    for bit in bits.iter().rev() {
        result = add_point(
            &mut *cs,
            curve_a.clone(),
            curve_d.clone(),
            result.clone(),
            result,
        )?;
        let result_plus_base = add_point(
            &mut *cs,
            curve_a.clone(),
            curve_d.clone(),
            result.clone(),
            base.clone(),
        )?;
        let (result_x, _) =
            AllocatedNum::conditionally_reverse(&mut *cs, &result.x, &result_plus_base.x, &bit)?;
        let (result_y, _) =
            AllocatedNum::conditionally_reverse(&mut *cs, &result.y, &result_plus_base.y, &bit)?;
        result = AllocatedPoint {
            x: result_x,
            y: result_y,
        };
    }
    Ok(result)
}

// Mul by 8
/*fn mul_cofactor(composer: &mut TurboComposer, mut point: Point) -> WitnessPoint {
    point = composer.component_add_point(point, point);
    point = composer.component_add_point(point, point);
    point = composer.component_add_point(point, point);
    point
}

fn mul(composer: &mut TurboComposer, scalar: Witness, point: WitnessPoint) -> WitnessPoint {
    let scalar_bits = composer.component_decomposition::<255>(scalar);

    let identity = composer.append_constant_identity();
    let mut result = identity;

    for bit in scalar_bits.iter().rev() {
        result = composer.component_add_point(result, result);

        let point_to_add = composer.component_select_identity(*bit, point);
        result = composer.component_add_point(result, point_to_add);
    }

    result
}

pub fn verify(
    composer: &mut TurboComposer,
    enabled: Witness,
    pk: WitnessPoint,
    msg: Witness,
    sig: WitnessSignature,
) {
    // h=H(R,A,M)
    let h = mimc::plonk::mimc(composer, &[*sig.r.x(), *sig.r.y(), *pk.x(), *pk.y(), msg]);

    let mut sb = composer.component_mul_generator(sig.s, *BASE);
    sb = mul_cofactor(composer, sb);

    let mut r_plus_ha = mul(composer, h, pk);
    r_plus_ha = composer.component_add_point(r_plus_ha, sig.r);
    r_plus_ha = mul_cofactor(composer, r_plus_ha);

    common::plonk::controllable_assert_eq(composer, enabled, *r_plus_ha.x(), *sb.x());
    common::plonk::controllable_assert_eq(composer, enabled, *r_plus_ha.y(), *sb.y());
}*/
