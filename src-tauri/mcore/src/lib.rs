/*
 * Copyright (c) 2012-2020 MIRACL UK Ltd.
 *
 * This file is part of MIRACL Core
 * (see https://github.com/miracl/core).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// comment out if debugging with print macros !!!
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_memcpy)]
#![allow(clippy::new_without_default)]
pub mod aes;
pub mod arch;
pub mod dilithium;
pub mod gcm;
pub mod hash256;
pub mod hash384;
pub mod hash512;
pub mod hmac;
pub mod kyber;
pub mod nhs;
pub mod rand;
pub mod sha3;
pub mod share;
pub mod x509;
pub mod ed25519;
pub mod c25519;
pub mod nist256;
pub mod brainpool;
pub mod anssi;
pub mod hifive;
pub mod ed448;
pub mod nist384;
pub mod c41417;
pub mod nist521;
pub mod nums256w;
pub mod nums256e;
pub mod nums384w;
pub mod nums384e;
pub mod nums512w;
pub mod nums512e;
pub mod secp256k1;
pub mod sm2;
pub mod c13318;
pub mod jubjub;
pub mod x448;
pub mod secp160r1;
pub mod c1174;
pub mod c1665;
pub mod mdc;
pub mod tweedledum;
pub mod tweedledee;
pub mod bn254;
pub mod bn254cx;
pub mod bls12383;
pub mod bls12381;
pub mod fp256bn;
pub mod fp512bn;
pub mod bls12443;
pub mod bls12461;
pub mod bn462;
pub mod bls24479;
pub mod bls48556;
pub mod bls48581;
pub mod bls48286;
pub mod bn158;
pub mod rsa2048;
pub mod rsa3072;
pub mod rsa4096;
