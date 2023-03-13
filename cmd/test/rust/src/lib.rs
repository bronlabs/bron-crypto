#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi::CStr;
use std::os::raw::c_void;
// include!("./bindings.rs");
include!("./try.rs");


struct DKGParticipant {
    particP: Option<*mut c_void>
}

impl DKGParticipant {

    new:: {


    round1() {

    }
}

}

fn foo() -> () {
    unsafe {
        let alice_identity_key = DKG_FROST_CreateIdentity();
        let bob_identity_key = DKG_FROST_CreateIdentity();
        let charlie_identity_key = DKG_FROST_CreateIdentity();
        let d_identity_key = DKG_FROST_CreateIdentity();

        let cohort_config = DKG_FROST_CreateCohortConfig(alice_identity_key, bob_identity_key, charlie_identity_key);

        // let alice = DKG_FROST_NewDKGParticipant(alice_identity_key, cohort_config);
        // let bob = DKG_FROST_NewDKGParticipant(bob_identity_key, cohort_config);
        // let charlie = DKG_FROST_NewDKGParticipant(charlie_identity_key, cohort_config);

        let aliceR = DKG_FROST_NewDKGParticipant(alice_identity_key, cohort_config);
        let bobR = DKG_FROST_NewDKGParticipant(bob_identity_key, cohort_config);
        let charlieR = DKG_FROST_NewDKGParticipant(charlie_identity_key, cohort_config);
        let dR = DKG_FROST_NewDKGParticipant(d_identity_key, cohort_config);

        let alice = aliceR.r0;
        let bob = bobR.r0;
        let charlie = charlieR.r0;

        let see_err = CStr::from_ptr(dR.r1);
        let err = String::from_utf8_lossy(see_err.to_bytes()).to_string();
        println!("{}", err);

        let alice_round_1 = DKG_FROST_Round1(alice);
        let bob_round_1 = DKG_FROST_Round1(bob);
        let charlie_round_1 = DKG_FROST_Round1(charlie);

        let alice_round_2 = DKG_FROST_Round2(alice, bob_identity_key, charlie_identity_key, bob_round_1, charlie_round_1);
        let bob_round_2 = DKG_FROST_Round2(bob, alice_identity_key, charlie_identity_key, alice_round_1, charlie_round_1);
        let charlie_round_2 = DKG_FROST_Round2(charlie, alice_identity_key, bob_identity_key, alice_round_1, bob_round_1);

        let alice_round_3 = DKG_FROST_Round3(
            alice,
            bob_identity_key,
            charlie_identity_key,
            bob_round_2.broadcast,
            charlie_round_2.broadcast,
            bob_round_2.p2p,
            charlie_round_2.p2p
        );

        let bob_round_3 = DKG_FROST_Round3(
            bob,
            alice_identity_key,
            charlie_identity_key,
            alice_round_2.broadcast,
            charlie_round_2.broadcast,
            alice_round_2.p2p,
            charlie_round_2.p2p
        );

        let charlie_round_3 = DKG_FROST_Round3(
            charlie,
            bob_identity_key,
            alice_identity_key,
            bob_round_2.broadcast,
            alice_round_2.broadcast,
            bob_round_2.p2p,
            alice_round_2.p2p
        );


        let alice_public_key = CStr::from_ptr(alice_round_3);
        let bob_public_key = CStr::from_ptr(bob_round_3);
        let charlie_public_key = CStr::from_ptr(charlie_round_3);
        let s1 = String::from_utf8_lossy(alice_public_key.to_bytes()).to_string();
        let s2 = String::from_utf8_lossy(bob_public_key.to_bytes()).to_string();
        let s3 = String::from_utf8_lossy(charlie_public_key.to_bytes()).to_string();
        UnrefString(alice_round_3);
        UnrefString(bob_round_3);
        UnrefString(charlie_round_3);

        UnrefPointer(alice_identity_key);
        UnrefPointer(bob_identity_key);

        println!("{}", s1);
        println!("{}", s2);
        println!("{}", s3);
    }
}

#[test]
fn testTry() {
    foo()
}
