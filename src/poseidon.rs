use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeFieldBits;
use generic_array::typenum;
use neptune::{
    circuit2::Elt,
    poseidon::PoseidonConstants,
    sponge::{
        api::{IOPattern, SpongeAPI, SpongeOp},
        circuit::SpongeCircuit,
        vanilla::{Mode::Simplex, Sponge, SpongeTrait},
    },
};

pub struct PoseidonHasher<Scalar: PrimeFieldBits> {
    constants: PoseidonConstants<Scalar, typenum::U4>,
    io_pattern: IOPattern,
}

impl<Scalar: PrimeFieldBits> PoseidonHasher<Scalar> {
    pub fn new(num_absorbs: u32) -> Self {
        Self {
            constants: Sponge::<Scalar, typenum::U4>::api_constants(neptune::Strength::Standard),
            io_pattern: IOPattern(vec![SpongeOp::Absorb(num_absorbs), SpongeOp::Squeeze(1)]),
        }
    }

    pub fn hash(&self, values: &[Scalar]) -> Scalar {
        let acc = &mut ();

        let mut sponge = Sponge::new_with_constants(&self.constants, Simplex);
        sponge.start(self.io_pattern.clone(), None, acc);
        SpongeAPI::absorb(&mut sponge, values.len() as u32, &values, acc);
        let output = SpongeAPI::squeeze(&mut sponge, 1, acc).pop().unwrap();
        sponge.finish(acc).unwrap();
        output
    }

    pub(crate) fn hash_in_circuit<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        values: &[AllocatedNum<Scalar>],
    ) -> Result<AllocatedNum<Scalar>, SynthesisError> {
        let mut sponge = SpongeCircuit::new_with_constants(&self.constants, Simplex);
        let mut ns = cs.namespace(|| "Poseidon namespace");
        let acc = &mut ns;
        sponge.start(self.io_pattern.clone(), None, acc);

        let elts = values
            .iter()
            .map(|v| Elt::from(v.clone()))
            .collect::<Vec<_>>();
        SpongeAPI::absorb(&mut sponge, elts.len() as u32, &elts, acc);
        let output = SpongeAPI::squeeze(&mut sponge, 1, acc).pop().unwrap();
        sponge.finish(acc).unwrap();

        Ok(output.ensure_allocated(&mut ns, false).unwrap())
    }
}
