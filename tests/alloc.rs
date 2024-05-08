use std::borrow::Borrow;

use ark_ff::Field;
use ark_r1cs_std::{
    prelude::{AllocVar, AllocationMode},
    uint8::UInt8,
};

use ark_relations::r1cs::{Namespace, SynthesisError};

pub struct Sudoku<const N: usize, ConstraintF: Field>(pub [[UInt8<ConstraintF>; N]; N]);

pub struct Solution<const N: usize, ConstraintF: Field>(pub [[UInt8<ConstraintF>; N]; N]);

impl<const N: usize, F: Field> AllocVar<[[u8; N]; N], F> for Sudoku<N, F> {
    fn new_variable<T: Borrow<[[u8; N]; N]>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        let row = [(); N].map(|_| UInt8::constant(0));
        let mut puzzle = Sudoku([(); N].map(|_| row.clone()));
        let value = f().map_or([[0; N]; N], |f| *f.borrow());
        for (i, row) in value.into_iter().enumerate() {
            for (j, cell) in row.into_iter().enumerate() {
                puzzle.0[i][j] = UInt8::new_variable(cs.clone(), || Ok(cell), mode)?;
            }
        }
        Ok(puzzle)
    }
}

impl<const N: usize, F: Field> AllocVar<[[u8; N]; N], F> for Solution<N, F> {
    fn new_variable<T: Borrow<[[u8; N]; N]>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        let row = [(); N].map(|_| UInt8::constant(0));
        let mut solution = Solution([(); N].map(|_| row.clone()));
        let value = f().map_or([[0; N]; N], |f| *f.borrow());
        for (i, row) in value.into_iter().enumerate() {
            for (j, cell) in row.into_iter().enumerate() {
                solution.0[i][j] = UInt8::new_variable(cs.clone(), || Ok(cell), mode)?;
            }
        }
        Ok(solution)
    }
}
