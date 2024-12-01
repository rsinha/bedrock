use ark_ff::Field;

/// computes the Lagrange coefficient for the i-th point amongst the x-coordinates `xs`;
/// The output coefficient is the result of evaluating the Lagrange polynomial at the point `x`.
pub fn lagrange_coefficient<F: Field>(xs: &[F], i: usize, x: &F) -> F {
    // source: https://en.wikipedia.org/wiki/Lagrange_polynomial

    // the ith point must be within the range of the x-coordinates
    assert!(i < xs.len(), "index out of bounds");
    //assert that the x-coordinates are distinct
    assert_eq!(
        xs.iter().collect::<std::collections::HashSet<_>>().len(),
        xs.len(),
        "x-coordinates must be distinct"
    );

    let xi = xs[i];
    let mut numerator = F::one();
    let mut denominator = F::one();
    for (j, xj) in xs.iter().enumerate() {
        if i != j {
            numerator *= *x - xj;
            denominator *= xi - xj;
        }
    }
    numerator * denominator.inverse().unwrap()
}
