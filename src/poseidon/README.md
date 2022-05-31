# Poseidon Hash

## Constants

### Round numbers

Standard with security margin 128bit => Full rounds = 8, Partial rounds = 60

### Round Constants and MDS Matrix

using the reference implementation's generator: https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/version-1.1/code/generate_parameters_grain.sage

```
sage generate_parameters_grain.sage 1 0 255 5 8 60 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001 > consts_128_5.txt

head -3 consts_128_5.txt | tail -1 > ark_128_5.txt
head -15 consts_128_5.txt  | tail -1 > mds_128_5.txt
```

and then run the `generate_constants.py` to get the `.rs` file which can be used by the Poseidon hash module.

```
python generate_constants.py ark_128_5.txt mds_128_t.txt
```
