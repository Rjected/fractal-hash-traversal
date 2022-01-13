use digest::{Digest, generic_array::GenericArray, FixedOutputReset, OutputSizeUser};
use sha2::Sha256;
use std::fmt::{self, Display, Debug};
use std::error::Error;

#[derive(Debug, Clone)]
struct ChainInitError {
    details: String,
}

impl ChainInitError {
    fn new(error_message: &str) -> ChainInitError {
        ChainInitError { details: error_message.to_string() }
    }
}

impl Display for ChainInitError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl Error for ChainInitError {
    fn description(&self) -> &str {
        &self.details
    }
}

#[derive(Clone)]
struct Pebble<H: OutputSizeUser> {
    start_incr: u64,
    dest_incr: u64,
    position: u64,
    destination: u64,
    value: GenericArray<u8, H::OutputSize>,
}

impl<H: OutputSizeUser> Display for Pebble<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value_bytes = self.value.as_slice();
        write!(f, "Pebble {{start_incr: {}, dest_incr: {}, position: {}, destination: {}, value: {}}}", self.start_incr, self.dest_incr, self.position, self.destination, hex::encode(value_bytes))
    }
}

impl<H: OutputSizeUser> Debug for Pebble<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value_bytes = self.value.as_slice();
        write!(f, "Pebble {{start_incr: {}, dest_incr: {}, position: {}, destination: {}, value: {}}}", self.start_incr, self.dest_incr, self.position, self.destination, hex::encode(value_bytes))
    }
}

const fn num_bits<T>() -> usize { std::mem::size_of::<T>() * 8 }

fn log_2(x: u64) -> u32 {
    assert!(x > 0);
    num_bits::<u64>() as u32 - x.leading_zeros() - 1
}

/// Return a mutable list of powers of two
fn create_powers(how_many: u32) -> Vec<u64> {
    let mut powers = Vec::<u64>::new();
    for p in 0..how_many {
        powers.push(2u64.pow(p+1));
    }
    powers
}

/// Creates the initial hash chain and outputs the pebbles which can be used to traverse the chain.
fn create_hash_chain<H: Digest + FixedOutputReset>(length: usize, seed: u64) -> Result<Vec<Pebble<H>>, ChainInitError>
where
    {
    // is length a power of two? Also catches zero
    if length == 0 || (length & (length - 1)) != 0 {
        return Err(ChainInitError::new("length not a power of two"));
    }

    // the number of pebbles is log_2(length)
    let num_pebbles = log_2(length.try_into().unwrap());

    // initialize the pebble list
    let mut pebbles = Vec::<Pebble<H>>::new();

    // initialize list of powers so we dont need to compute each time
    let powers = create_powers(num_pebbles);

    let mut hasher = H::new_with_prefix(seed.to_le_bytes());
    let mut output = hasher.finalize_reset();
    for i in 2u64..=length as u64 {
        digest::Digest::update(&mut hasher, output.as_ref());
        output = hasher.finalize_reset();
        if i.eq(powers.get(log_2(i) as usize - 1).unwrap()) {
            pebbles.push(Pebble{
                start_incr: 3*i,
                dest_incr: 2u64*i,
                position: i,
                destination: i,
                value: output.clone(),
            });

        }
    }

    Ok(pebbles)
}

/// Create hash chain without using pebbles. Warning: the resulting array will be very large,
/// specifically the length specified.
fn create_hash_chain_nopebble<H: Digest + FixedOutputReset>(length: usize, seed: u64) -> Vec<GenericArray<u8, H::OutputSize>> {
    let mut chain = Vec::<GenericArray<u8, H::OutputSize>>::new();
    let mut hasher = H::new_with_prefix(seed.to_le_bytes());
    let mut output = hasher.finalize_reset();
    chain.push(output.clone());
    for _ in 2u64..=length as u64 {
        digest::Digest::update(&mut hasher, output.as_ref());
        output = hasher.finalize_reset();
        chain.push(output.clone());
    }
    chain
}

#[test]
fn test_chain_init() {
    let len = 128;
    let pebbles = create_hash_chain::<Sha256>(len, 0).unwrap();
    println!("Here are the pebbles: {:?}", pebbles);
    assert_eq!(pebbles.len(), log_2(len.try_into().unwrap()).try_into().unwrap());
}

#[test]
fn test_create_powers_small() {
    let powers = create_powers(3);
    assert_eq!(powers, vec![2, 4, 8]);
}

#[test]
fn test_create_chain_small() {
    let len = 128;
    let chain = create_hash_chain_nopebble::<Sha256>(len, 0);
    assert_eq!(len, chain.len());
}
