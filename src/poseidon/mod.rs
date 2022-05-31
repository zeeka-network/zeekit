use hex;
use ff::PrimeField;
use crate::{Fr, FrRepr};

include!("constants.rs");

lazy_static! {
    static ref ROUND_CONSTANTS: [Fr; 340] = {
        ROUND_CONSTANTS_HEX.map(|c| {
            let mut m = [0u8; 32];
            hex::decode_to_slice(c, &mut m).unwrap();
            m.reverse();
            Fr::from_repr(FrRepr(m)).unwrap()
        })
    };

    static ref MDS_MATRIX: [[Fr; WIDTH]; WIDTH] = {
        MDS_MATRIX_HEX.map(|cr| {
            cr.map(|c| {
                let mut m = [0u8; 32];
                hex::decode_to_slice(c, &mut m).unwrap();
                m.reverse();
                Fr::from_repr(FrRepr(m)).unwrap()
            })
        })
    };
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Poseidon
{
    constants_offset: usize,
    present_elements: u64,
    elements: [Fr; WIDTH],
}

impl Default for Poseidon {
    fn default() -> Self {
        Poseidon {
            present_elements: 0u64,
            constants_offset: 0,
            elements: [Fr::from(0u64); WIDTH],
        }
    }
}

impl Poseidon {
    pub fn a4(a: Fr, b: Fr, c: Fr, d: Fr) -> Self {
        Self {
            present_elements: 0u64,
            constants_offset: 0,
            elements: [Fr::from(0u64), a, b, c, d],
        }
    }

    pub fn hash(&mut self) -> Fr {
        self.elements[0] = Fr::from(self.present_elements);

        // 20 consts (4 * 5)
        for _ in 0..ROUNDSF / 2 {
            self.full_round();
        }
        
        // 300 consts (60 * 5)
        for _ in 0..ROUNDSP {
            self.partial_round();
        }

        // 20 consts (4 * 50)
        for _ in 0..ROUNDSF / 2 {
            self.full_round();
        }

        self.elements[1]
    }

    pub fn full_round(&mut self) {
        // Every element of the merkle tree, plus the bitflag, is incremented by the round constants
        self.add_round_constants();

        // Apply the quintic S-Box to all elements
        self.elements.iter_mut().for_each(|l| quintic_s_box(l));

        // Multiply the elements by the constant MDS matrix
        self.product_mds();
    }

    pub fn partial_round(&mut self) {
        // Every element of the merkle tree, plus the bitflag, is incremented by the round constants
        self.add_round_constants();

        // Apply the quintic S-Box to the bitflags element
        quintic_s_box(&mut self.elements[0]);

        // Multiply the elements by the constant MDS matrix
        self.product_mds();
    }

    fn add_round_constants(&mut self)
    {
        let mut constants_offset = self.constants_offset;

        self.elements.iter_mut().for_each(|l| {
            *l += ROUND_CONSTANTS[constants_offset];
            constants_offset += 1;
        });

        self.constants_offset = constants_offset;
    }

    fn product_mds(&mut self)
    {
        let mut result = [Fr::from(0u64); WIDTH];

        for j in 0..WIDTH {
            for k in 0..WIDTH {
                result[j] += MDS_MATRIX[j][k] * self.elements[k];
            }
        }

        self.elements.copy_from_slice(&result);
    }
}

fn quintic_s_box<Fr: PrimeField>(l: &mut Fr) {
    let mut tmp = *l;
    tmp = tmp.square(); // l^2
    tmp = tmp.square(); // l^4
    l.mul_assign(&tmp); // l^5
}

pub fn poseidon(a: Fr, b: Fr, c: Fr, d: Fr) -> Fr {
    let mut h = Poseidon::a4(a, b, c, d);
    h.hash()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;

    #[test]
    fn hash_det() {
        let mut h = Poseidon::a4( Fr::one(), Fr::one(), Fr::one(), Fr::one());

        let mut h2 = h.clone();
        let result = h.hash();

        assert_eq!(result, h2.hash());
    }
}
