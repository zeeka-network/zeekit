use super::{PointAffine, BASE};
use crate::common;
use crate::mimc;
use dusk_plonk::prelude::*;

impl Into<JubJubAffine> for PointAffine {
    fn into(self) -> JubJubAffine {
        JubJubAffine::from_raw_unchecked(self.0.into(), self.1.into())
    }
}

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
    let h_rr = mimc::plonk::mimc(composer, *sig.r.x(), *sig.r.y());
    let h_pk = mimc::plonk::mimc(composer, *pk.x(), *pk.y());
    let h_rr_pk = mimc::plonk::mimc(composer, h_rr, h_pk);
    let h = mimc::plonk::mimc(composer, h_rr_pk, msg);

    let mut sb = composer.component_mul_generator(sig.s, *BASE);
    sb = mul_cofactor(composer, sb);

    let mut r_plus_ha = mul(composer, h, pk);
    r_plus_ha = composer.component_add_point(r_plus_ha, sig.r);
    r_plus_ha = mul_cofactor(composer, r_plus_ha);

    common::plonk::controllable_assert_eq(composer, enabled, *r_plus_ha.x(), *sb.x());
    common::plonk::controllable_assert_eq(composer, enabled, *r_plus_ha.y(), *sb.y());
}
