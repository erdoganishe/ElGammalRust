extern crate num_bigint;
extern crate num_traits;
extern crate num_primes;
extern crate rand;
extern crate modinverse;
extern crate num_bigint_dig;
extern crate crypto_hash;
use crate::num_traits::Num;

use crypto_hash::hex_digest;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use num_primes::Generator;
use std::{str::FromStr, usize};
use num_bigint_dig::algorithms::mod_inverse;
use std::borrow::Cow;


// Генерація простого числа заданої довжини в бітах
fn generate_prime(bits: usize) -> BigUint {
   let prime = Generator::new_prime(bits);
   let tmp = prime.to_string();
   return BigUint::from_str(&tmp).unwrap();
}


fn is_primitive_root(candidate: &BigUint, p: &BigUint) -> bool {
    let one = BigUint::one();

    // Знаходимо фактори p-1
    let mut factors = p.clone() - one.clone();
    let d = factors.clone();

    // Розкладаємо p-1 на прості множники
    let mut factorization: Vec<BigUint> = Vec::new();
    let mut i = BigUint::from(2u32);

    while i.clone() * i.clone() <= factors {
        while factors.clone() % i.clone() == Zero::zero() {
            factors /= i.clone();
            factorization.push(i.clone());
        }
        i += one.clone();
    }

    if factors > one {
        factorization.push(factors.clone());
    }

    // Перевіряємо примітивність кандидата
    for factor in factorization {
        if candidate.modpow(&(d.clone() / &factor.clone()), p) == one {
            return false;
        }
    }

    true
}

fn find_primitive_root(p: &BigUint, bits: usize) -> BigUint {
    loop {
        let random_tmp = Generator::new_prime(bits-1);

        let tmp = random_tmp.to_string();

        let candidate = BigUint::from_str(&tmp).unwrap();
        if is_primitive_root(&candidate, &p) {
            return candidate;
        }
    }
    
}


// // Генерація ключів
fn generate_keys(bits: usize) -> (BigUint, BigUint, BigUint, BigUint) {
    let p = generate_prime(bits);
    let g = find_primitive_root(&p, bits);
    let random_tmp = Generator::new_uint(bits-1);
    let tmp = random_tmp.to_string();
    let private_key = BigUint::from_str(&tmp).unwrap();
    let public_key = g.modpow(&private_key, &p);
    (p, g, public_key, private_key)
}


// Підписання повідомлення
fn sign(message: &str, p: &BigUint, g: &BigUint, private_key: &BigUint, bits: usize) -> (BigUint, BigUint) {
    let one = BigUint::one();
    let p_minus_one = p - &one;
    let random_tmp = Generator::new_uint(bits-1);
    let tmp = random_tmp.to_string();
    let k = BigUint::from_str(&tmp).unwrap();
    let r = g.modpow(&k, p);
    let k_num_bigint_dig:num_bigint_dig::BigUint = tmp.parse().unwrap();
    let p_num_bigint_dig:num_bigint_dig::BigUint = p.to_str_radix(10).parse().unwrap();
    let k_cow = Cow::Borrowed(&k_num_bigint_dig);
    let p_cow = Cow::Borrowed(&p_num_bigint_dig);
    let k_inverse_big_int = mod_inverse(k_cow, p_cow).unwrap();
    let k_inverse_dig =  k_inverse_big_int.to_biguint().unwrap();
    let k_inverse = BigUint::from_str(k_inverse_dig.to_str_radix(10).as_str()).unwrap();
    let hash_message = hex_digest(crypto_hash::Algorithm::SHA256, &message.as_bytes().to_vec());
    let h =  BigUint::from_str_radix(hash_message.as_str(), 16).unwrap();
    let s = (h - private_key * r.clone()) * k_inverse % (p_minus_one);

    (r, s)
}

// Перевірка підпису
fn verify(message: &str, signature: &(BigUint, BigUint), p: &BigUint, g: &BigUint, public_key: &BigUint) -> bool {
    let (r, s) = signature;
    let one = BigUint::one();
    let p_minus_one = p - &one;

    let b_num_bigint_dig:num_bigint_dig::BigUint = public_key.to_str_radix(10).parse().unwrap();
    let p_num_bigint_dig:num_bigint_dig::BigUint = p.to_str_radix(10).parse().unwrap();
    let s_num_bigint_dig:num_bigint_dig::BigUint = s.to_str_radix(10).parse().unwrap();
    let b_cow = Cow::Borrowed(&b_num_bigint_dig);
    let p_cow = Cow::Borrowed(&p_num_bigint_dig);
    let s_cow = Cow::Borrowed(&s_num_bigint_dig);

    let y_inverse_big_int = mod_inverse(b_cow, p_cow.clone()).unwrap();
    let w_inverse_big_int = mod_inverse(s_cow, p_cow.clone()).unwrap();
    let y_inverse_dig =  y_inverse_big_int.to_biguint().unwrap();
    let y = BigUint::from_str(y_inverse_dig.to_str_radix(10).as_str()).unwrap();
    let w_inverse_dig =  w_inverse_big_int.to_biguint().unwrap();
    let w = BigUint::from_str(w_inverse_dig.to_str_radix(10).as_str()).unwrap();


    if r >= p || s >= &p_minus_one {
        return false;
    }


    let hash_message = hex_digest(crypto_hash::Algorithm::SHA256, &message.as_bytes().to_vec());
    let h =  BigUint::from_str_radix(hash_message.as_str(), 16).unwrap();

    let u1 = (h * w.clone()) % p;
    let u2 = (r * w.clone()) % p;

    let v = (g.modpow(&u1, p) * y.modpow(&u2, p)) % p ;

    v == *r
}
fn encrypt(message: &BigUint, k: &BigUint, b: &BigUint, g: &BigUint, p: &BigUint) -> (BigUint, BigUint) {
    let x = g.modpow(k, p);
    let y = (b.modpow(k, p) * message) % p;

    (x, y)
}

fn decrypt(ciphertext: &(BigUint, BigUint), a: &BigUint, p: &BigUint) -> BigUint {
    let (x, y) = ciphertext;
    let s = x.modpow(a, p);

    let s_num_bigint_dig:num_bigint_dig::BigUint = s.to_str_radix(10).parse().unwrap();
    let s_cow = Cow::Borrowed(&s_num_bigint_dig);
   
    let p_num_bigint_dig:num_bigint_dig::BigUint = p.to_str_radix(10).parse().unwrap();
    let p_cow = Cow::Borrowed(&p_num_bigint_dig);

    let s_inverse_big_int = mod_inverse(s_cow, p_cow.clone()).unwrap();

    let s_inverse_dig =  s_inverse_big_int.to_biguint().unwrap();
    let s_inverse = BigUint::from_str(s_inverse_dig.to_str_radix(10).as_str()).unwrap();

    let message = (y * &s_inverse) % p;

    message
}

fn main() {
    let bits = 64;
    println!("Bits: {}", bits);
    let (p, g, public_key, private_key) = generate_keys(bits);

    let message = "Hello, ElGamal!";

    let (x,y) = encrypt(&BigUint::from_bytes_be(&message.as_bytes()), &private_key, &public_key, &g, &p);
    let decrypted = decrypt(&(x.clone(),y.clone()), &private_key, &p); 
    let message_as_bytes = BigUint::from_bytes_be(&message.as_bytes());

    println!("Message as Uint: {}", message_as_bytes % p.clone());
    println!("Encrypted message: ({},{})", x, y);
    println!("Decrypted message: {}", decrypted);

    let (r, s) = sign(message, &p, &g, &private_key, bits);
    let is_valid = verify(message, &(r.clone(), s.clone()), &p, &g, &public_key);

    println!("Message: {}", message);
    println!("Public Key: {}", public_key);
    println!("Public Key: {}", private_key);
    println!("Signature: ({}, {})", r, s);
    println!("Signature is valid: {}", is_valid);
}
