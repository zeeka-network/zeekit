use ff::PrimeField;
use num_bigint::BigUint;
use num_integer::Integer;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[cfg(feature = "plonk")]
use dusk_plonk::prelude::BlsScalar;

#[cfg(feature = "groth16")]
pub use bls12_381::{Bls12, G1Affine as BellmanG1, G2Affine as BellmanG2, Scalar as BellmanFr};

#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref FR_MODULUS: BigUint = BigUint::from_str(
        "52435875175126190479447740508185965837690552500527637822603658699938581184513"
    )
    .unwrap();
}

// Scalar field of Bls12-381
#[derive(PrimeField, Serialize, Deserialize)]
#[PrimeFieldModulus = "52435875175126190479447740508185965837690552500527637822603658699938581184513"]
#[PrimeFieldGenerator = "7"]
#[PrimeFieldReprEndianness = "little"]
pub struct Fr([u64; 4]);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Fp([u64; 6]);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Groth16VerifyingKey {
    alpha_g1: (Fp, Fp, bool),
    beta_g1: (Fp, Fp, bool),
    beta_g2: ((Fp, Fp), (Fp, Fp), bool),
    gamma_g2: ((Fp, Fp), (Fp, Fp), bool),
    delta_g1: (Fp, Fp, bool),
    delta_g2: ((Fp, Fp), (Fp, Fp), bool),
    ic: Vec<(Fp, Fp, bool)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Groth16Proof {
    a: (Fp, Fp, bool),
    b: ((Fp, Fp), (Fp, Fp), bool),
    c: (Fp, Fp, bool),
}

#[cfg(feature = "groth16")]
pub fn groth16_verify(
    vk: &Groth16VerifyingKey,
    prev_state: Fr,
    aux_data: Fr,
    next_state: Fr,
    proof: &Groth16Proof,
) -> bool {
    let (vk, proof) = unsafe {
        let alpha_g1 = std::mem::transmute::<(Fp, Fp, bool), BellmanG1>(vk.alpha_g1.clone());
        let beta_g1 = std::mem::transmute::<(Fp, Fp, bool), BellmanG1>(vk.beta_g1.clone());
        let beta_g2 =
            std::mem::transmute::<((Fp, Fp), (Fp, Fp), bool), BellmanG2>(vk.beta_g2.clone());
        let gamma_g2 =
            std::mem::transmute::<((Fp, Fp), (Fp, Fp), bool), BellmanG2>(vk.gamma_g2.clone());
        let delta_g1 = std::mem::transmute::<(Fp, Fp, bool), BellmanG1>(vk.delta_g1.clone());
        let delta_g2 =
            std::mem::transmute::<((Fp, Fp), (Fp, Fp), bool), BellmanG2>(vk.delta_g2.clone());
        let ic = vk
            .ic
            .iter()
            .cloned()
            .map(|p| std::mem::transmute::<(Fp, Fp, bool), BellmanG1>(p))
            .collect();
        let proof = bellman::groth16::Proof::<Bls12> {
            a: std::mem::transmute::<(Fp, Fp, bool), BellmanG1>(proof.a.clone()),
            b: std::mem::transmute::<((Fp, Fp), (Fp, Fp), bool), BellmanG2>(proof.b.clone()),
            c: std::mem::transmute::<(Fp, Fp, bool), BellmanG1>(proof.c.clone()),
        };
        let vk =
            bellman::groth16::prepare_verifying_key(&bellman::groth16::VerifyingKey::<Bls12> {
                alpha_g1,
                beta_g1,
                beta_g2,
                gamma_g2,
                delta_g1,
                delta_g2,
                ic,
            });
        (vk, proof)
    };
    bellman::groth16::verify_proof(
        &vk,
        &proof,
        &vec![prev_state.into(), aux_data.into(), next_state.into()],
    )
    .is_ok()
}

impl Fr {
    pub fn new(num_le: [u8; 32]) -> Self {
        let bts = BigUint::from_bytes_le(&num_le)
            .mod_floor(&FR_MODULUS)
            .to_bytes_le();
        let mut data = [0u8; 32];
        data[0..bts.len()].copy_from_slice(&bts);
        Fr::from_repr_vartime(FrRepr(data)).unwrap()
    }
}

#[cfg(feature = "plonk")]
impl Into<BlsScalar> for Fr {
    fn into(self) -> BlsScalar {
        BlsScalar(self.0)
    }
}

#[cfg(feature = "plonk")]
impl From<BlsScalar> for Fr {
    fn from(bls: BlsScalar) -> Fr {
        Fr(bls.0)
    }
}

#[cfg(feature = "groth16")]
impl Into<BellmanFr> for Fr {
    fn into(self) -> BellmanFr {
        unsafe { std::mem::transmute::<Fr, BellmanFr>(self) }
    }
}

#[cfg(feature = "groth16")]
impl From<BellmanFr> for Fr {
    fn from(bls: BellmanFr) -> Fr {
        unsafe { std::mem::transmute::<BellmanFr, Fr>(bls) }
    }
}

pub mod common;
mod config;
pub mod eddsa;
pub mod merkle;
pub mod mimc;
pub mod poseidon;
