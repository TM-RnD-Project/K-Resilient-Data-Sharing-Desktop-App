extern crate mcore;

use mcore::ed25519::big;
use std::vec::Vec;

pub struct Lagrange;

impl Lagrange {
    /// Computes the Lagrange interpolating polynomial at x = 0
    /// using the given x_values, y_values, and modulo order.
    pub fn interpolate_x(x_values: &Vec<big::BIG>, y_values: &Vec<big::BIG>, order: &big::BIG) -> big::BIG {
        let k = x_values.len();
        assert_eq!(k, y_values.len(), "Mismatched input lengths!");

        let mut result = big::BIG::new();

        for i in 0..k {
            let mut numerator = big::BIG::new_int(1);
            let mut denominator = big::BIG::new_int(1);

            for j in 0..k {
                if i != j {
                    let mut xj = x_values[j].clone();
                    let mut xi = x_values[i].clone();
                    let mut diff = big::BIG::modadd(&xj, &big::BIG::modneg(&xi, order), order); // (x_j - x_i) mod q
                    diff.invmodp(order); // Compute modular inverse

                    numerator = big::BIG::modmul(&numerator, &xj, order); // Multiply x_j terms
                    denominator = big::BIG::modmul(&denominator, &diff, order); // Multiply (x_j - x_i)^(-1)
                }
            }

            let mut term = big::BIG::modmul(&y_values[i], &numerator, order);
            term = big::BIG::modmul(&term, &denominator, order);
            result = big::BIG::modadd(&result, &term, order); // Accumulate result
        }

        result
    }
}
