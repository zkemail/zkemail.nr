use dep::std::{
    meta::unquote,
    collections::umap::UHashMap,
    hash::{BuildHasherDefault, poseidon2::Poseidon2Hasher},
};

pub type DeriveFunction = fn(StructDefinition) -> Quoted;

comptime mut global HANDLERS: UHashMap<TraitDefinition, DeriveFunction, BuildHasherDefault<Poseidon2Hasher>> = UHashMap::default();
// comptime mut global 

// #[varargs]
comptime fn zkemail(s: StructDefinition) -> Quoted {
    // setup the dkim check
    derive_dkim_check(s)


    // // check the 
    // let should_check_body = s.has_named_attribute("check_body");
    // let should_partial_hash = s.has_named_attribute("partial_hash");
    // if should_check_body {
    //     // check it does not also have the partial_hash attribute
    //     assert(!should_partial_hash, "Cannot have both check_body and partial_hash attributes");
    //     let _ = s.add_generic("let MAX_EMAIL_BODY_LENGTH: u32");
    // } else if should_partial_hash {
    //     // check it does not also have the check_body attribute
    //     let _ = s.add_generic("let MAX_EMAIL_BODY_LENGTH: u32");
    // }

    // no matter what, add verify signature
    // derive_dkim_check(s)
    // quote {}
}   

comptime fn derive_dkim_check(s: StructDefinition) -> Quoted {
    // set fields
    let mut fields = s.fields();
    // let x = quote { BoundedVec<u8, MAX_EMAIL_HEADER_LENGTH> }.as_type()
    // fields.push_back((quote { header }, ));
    let typ = s.as_type();
    let impl_generics = s.generics().map(|g| quote { $g }).join(quote {,});
    let x = quote {
        impl<$impl_generics> VerifyDKIM<$impl_generics> for $typ {
            fn verify_dkim_signature(self) {
                println("something else");
            }
        }
    };
    println(x);
    // quote {}
    x
    
}

pub comptime fn register_handlers(t: TraitDefinition, f: DeriveFunction) {
    HANDLERS.insert(t, f);
}

pub trait BodyCheck<let MAX_EMAIL_BODY_LENGTH: u32> {
    fn check_body(self);
}

pub trait PartialHash<let MAX_EMAIL_BODY_LENGTH: u32> {
    fn partial_hash(self);
}

#[register_handlers(derive_dkim_check)]
pub trait VerifyDKIM<let MAX_EMAIL_HEADER_LENGTH: u32, let KEY_LIMBS: u32> {
    fn verify_dkim_signature(self);
}

// #[register_handlers(derive_do_nothing)]
// pub trait DoNothing<let HEADER_LEN: u32, let KEY_LIMBS: u32> {
//     fn do_nothing(self);
// }

use crate::dkim::RSAPubkey;
use crate::{KEY_BYTES_2048, KEY_LIMBS_2048};

#[derive_dkim_check]
struct input<let MAX_EMAIL_HEADER_LEN: u32, let KEY_BYTES: u32> {
    header: BoundedVec<u8, MAX_EMAIL_HEADER_LEN>,
    pubkey: RSAPubkey<KEY_BYTES>,
    signature: [Field; KEY_BYTES],
}

global HEADER_LEN: u32 = 1024;

#[test]
pub fn test_fn() {
    let header: BoundedVec<u8, HEADER_LEN> = BoundedVec::new();
    let signature: [Field; KEY_LIMBS_2048] = [0; KEY_LIMBS_2048];
    let pubkey = RSAPubkey::<KEY_LIMBS_2048> { modulus: [0; KEY_LIMBS_2048], redc: [0; KEY_LIMBS_2048] };
    let i: input<HEADER_LEN, KEY_LIMBS_2048> = input{ header, pubkey, signature };
    i.verify_dkim_signature();
    // i.do_nothing();
}

// comptime fn derive_do_nothing(s: StructDefinition) -> Quoted {
//         // This is simplified since we don't handle generics or where clauses!
//         // In a real example we'd likely also need to introduce each of
//         // `s.generics()` as well as a trait constraint for each generic
//         // to ensure they also implement the trait.
//         let typ = s.
//         println(typ);
//         // quote {
//         //     impl<let HEADER_LEN: u32, let KEY_LIMBS: u32> DoNothing for $typ where HEADER_LEN: u32, KEY_LIMBS: u32 {
//         //         fn do_nothing(self) {
//         //             // Traits can't tell us what to do
//         //             println("something");
//         //         }
//         //     }
//         // }
//         quote {}
//     }


// impl<MAX_EMAIL_HEADER_LENGTH, KEY_LIMBS> for input where MAX_EMAIL_HEADER_LENGTH: u32, KEY_LIMBS: u32 {
//     fn check_body(self) {
//         // check the body and header lengths are within bounds
//         assert(header.len() <= MAX_EMAIL_HEADER_LENGTH);
//     }
// }

// // this doesn't work so making demo of it not working

// #[derive_do_something_else]
// #[derive_do_something]
// struct MyStruct<let N: u32> {
//     data: BoundedVec<u8, N>
// }

// trait DoSomething {
//     fn do_something(self);
// }

// trait DoSomethingElse<let N: u32> {
//     fn do_something_else(self);
// }

// comptime fn derive_do_something(s: StructDefinition) -> Quoted {
//     let typ = s.as_type();
//     let impl_generics = s.generics().map(|g| quote { $g }).join(quote {,});
//     let x = quote {
//         impl<$impl_generics> DoSomething for $typ {
//             fn do_something(self) {
//                 println("something");
//             }
//         }
//     };
//     println(x);
//     x
// }

// comptime fn derive_do_something_else(s: StructDefinition) -> Quoted {
//     let typ = s.as_type();
//     let impl_generics = s.generics().map(|g| quote { $g }).join(quote {,});
//     let x = quote {
//         impl<$impl_generics> DoSomethingElse<N> for $typ {
//             fn do_something_else(self) {
//                 println("something else");
//             }
//         }
//     };
//     println(x);
//     // quote {}
//     x
// }

// #[test]
// fn test_fn() {
//     let x = MyStruct::<10> { data: BoundedVec::new() };
//     x.do_something_else();
// }