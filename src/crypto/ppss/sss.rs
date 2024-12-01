use std::vec;

use rand::SeedableRng;
use ark_ff::Field;
use ark_poly::{Polynomial, univariate::DensePolynomial};

use super::lagrange::*;

/// outputs a (t,n) Shamir secret sharing of the input secret, 
/// where t is the threshold and n is the number of shares.
/// Note: the threshold t indicates that any t shares can be combined
/// to recover the secret, and any subset of t-1 shares cannot.
/// The output shares are (x,y) coordinate pairs.
pub fn share<F: Field>(
    secret: F,
    threshold: usize,
    num_shares: usize,
) -> Vec<(F, F)> {
    let share_ids = (1..=(num_shares as u64)).map(F::from).collect::<Vec<F>>();

    // generate random x-coordinates
    let mut rng = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);

    // lets sample a random polynomial with a fixed point at x = 0
    // A t degree polynomial is defined by t + 1 coefficients: a_0, a_1, ..., a_t
    // such that p(x) = a_0 + a_1 * x + a_2 * x^2 + ... + a_t * x^t
    // here we want t = threshold - 1, so we have threshold number of coefficients
    let p = DensePolynomial { coeffs: {
        let mut coefficients = vec![secret]; // the secret is embedded at x = 0
        (1..threshold).for_each(|_| coefficients.push(F::rand(&mut rng)));
        coefficients
    }};

    // we skip over 0 because that's where the secret is embedded
    let xs = share_ids.to_vec();
    let ys = xs.iter().map(|x| p.evaluate(x)).collect::<Vec<F>>();

    // output is a vector of (x,y) coordinate pairs
    let shares = xs.iter().zip(ys.iter()).map(|(x, y)| (*x, *y)).collect();

    shares
}

/// recovers the secret given a subset of t shares,
/// where each share is a (x,y) coordinate pair.
/// Note that this will return a arbitrary value 
/// if the reconstruction threshold is not met
pub fn recover<F: Field>(
    shares: &[(F, F)],
) -> F {
    let xs = shares.iter().map(|(x, _)| *x).collect::<Vec<F>>();
    let ys = shares.iter().map(|(_, y)| *y).collect::<Vec<F>>();

    let λs: Vec<F> = (0..xs.len()).map(|i| {
        // each lagrange coefficient is computed with respect to x = 0,
        // since that's where we are embedding the secret in our entire
        // construction. So the ith coefficient is w.r.t. xs[i].
        let λ_i = lagrange_coefficient(&xs, i, &F::zero()); λ_i
    }).collect();

    // the reconstructed secret is a weighted sum of ys, 
    // with the lagrange coefficients as weights
    let secret = λs.iter().zip(ys.iter())
        .fold(F::zero(), |acc, (&λ_i, &y_i)| { acc + λ_i * y_i });

    secret
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    type F = ark_bls12_381::Fr;

    #[test]
    fn test_share_and_recover() {
        let secret = F::from(42u64);
        let threshold = 3;
        let num_shares = 5;

        let shares = share(secret, threshold, num_shares);

        assert_eq!(secret, recover(&shares[..threshold]));
        assert_eq!(secret, recover(&shares[1..4]));
        assert_eq!(secret, recover(&shares[2..5]));
        assert_eq!(secret, recover(&shares[..]));
        assert_eq!(secret, recover(vec![shares[0], shares[2], shares[4]].as_slice()));
    }

    // let's check if shares of shares can be recovered
    #[test]
    fn test_share_of_shares() {
        let secret = F::from(42u64);
        let threshold = 3;
        let num_parties = 5;

        // this is the first layer of shares
        let shares: Vec<(F,F)> = share(secret, threshold, num_parties);

        // this contains the shares of shares, indexed by the receiver id
        let mut incoming_shares: HashMap<F, Vec<(F,F)>> = HashMap::new();

        // each shareholder becomes a dealer in the next layer of shares
        for (dealer_id, share_value) in shares {

            let shares_of_shares = share(share_value, threshold, num_parties);

            for (receiver_id, share_of_share_value) in shares_of_shares {
                incoming_shares.entry(receiver_id).or_insert(Vec::new()).push((dealer_id, share_of_share_value));
            }
        }

        // now we have shares of shares, let's try to get a sharing of the original secret
        let mut reconstructed_shares: Vec<(F,F)> = Vec::new();
        for (receiver_id, shares_of_shares) in incoming_shares {
            let reconstructed_share = recover(&shares_of_shares[..threshold]);
            reconstructed_shares.push((receiver_id, reconstructed_share));
        }

        // we should be able to recover the original secret
        assert_eq!(secret, recover(&reconstructed_shares[..threshold]));

    }
}