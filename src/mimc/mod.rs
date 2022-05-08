use crate::config::MIMC_PARAMS;
use crate::Fr;
use ff::Field;
use std::ops::*;

#[cfg(feature = "plonk")]
pub mod plonk;

#[cfg(feature = "groth16")]
pub mod groth16;

pub fn mimc(mut xl: Fr, mut xr: Fr) -> Fr {
    for c in MIMC_PARAMS.iter() {
        let mut tmp1 = xl;
        tmp1.add_assign(c);
        let mut tmp2 = tmp1.square();
        tmp2.mul_assign(&tmp1);
        tmp2.add_assign(&xr);
        xr = xl;
        xl = tmp2;
    }

    xl
}
