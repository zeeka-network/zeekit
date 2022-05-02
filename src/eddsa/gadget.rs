use super::{PointAffine, BASE};
use crate::{gadgets, mimc};
use dusk_plonk::prelude::*;

pub struct WitnessSignature {
    pub r: WitnessPoint,
    pub s: Witness,
}

impl Into<JubJubExtended> for PointAffine {
    fn into(self) -> JubJubExtended {
        JubJubExtended::from(JubJubAffine::from_raw_unchecked(
            self.0.into(),
            self.1.into(),
        ))
    }
}

// Mul by 8
fn mul_cofactor(composer: &mut TurboComposer, mut point: WitnessPoint) -> WitnessPoint {
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
    let mut inp = Vec::new();
    inp.push(*sig.r.x());
    inp.push(*sig.r.y());
    inp.push(*pk.x());
    inp.push(*pk.y());
    inp.push(msg);
    let h = mimc::gadget::mimc(composer, inp);

    let mut sb = composer.component_mul_generator(sig.s, *BASE);
    sb = mul_cofactor(composer, sb);

    let mut r_plus_ha = mul(composer, h, pk);
    r_plus_ha = composer.component_add_point(r_plus_ha, sig.r);
    r_plus_ha = mul_cofactor(composer, r_plus_ha);

    gadgets::controllable_assert_eq(composer, enabled, *r_plus_ha.x(), *sb.x());
    gadgets::controllable_assert_eq(composer, enabled, *r_plus_ha.y(), *sb.y());
}
