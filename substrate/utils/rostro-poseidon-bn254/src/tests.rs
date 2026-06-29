use super::*;

fn hex(f: &Fr) -> alloc::string::String {
    use core::fmt::Write;
    let mut s = alloc::string::String::new();
    for b in fr_to_bytes_le(f) {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

// Fixed KAT inputs. Stable, arbitrary small field elements.
fn kat_inputs() -> (Fr, Fr, Fr, Fr, Fr, Fr) {
    (
        Fr::from(42u64),   // s
        Fr::from(1000u64), // expiry_block
        Fr::from(7u64),    // scope
        Fr::from(3u64),    // epoch
        Fr::from(11u64),   // node left
        Fr::from(22u64),   // node right
    )
}

/// Run with `--nocapture` to print the role-hash outputs that the `kats`
/// test pins. Re-run and re-bake only if the instance intentionally
/// changes; an accidental drift must fail `kats`, not silently re-pin.
#[test]
fn emit_kats() {
    let p = params();
    let (s, expiry, scope, epoch, l, r) = kat_inputs();
    let idc = id_commitment(&p, s);
    extern crate std;
    std::println!("id_commitment = {}", hex(&idc));
    std::println!("hash_node     = {}", hex(&hash_node(&p, l, r)));
    std::println!("hash_leaf     = {}", hex(&hash_leaf(&p, idc, expiry, scope)));
    std::println!("nullifier     = {}", hex(&nullifier(&p, s, epoch)));
}

fn from_hex(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

/// Pinned outputs of the canonical instance for [`kat_inputs`]. These are
/// the contract every consumer (phone, runtime, circuit) must reproduce.
/// A change here means the instance changed; that must be deliberate, and
/// every consumer re-pinned in lockstep. Captured from `emit_kats`.
#[test]
fn kats() {
    let p = params();
    let (s, expiry, scope, epoch, l, r) = kat_inputs();
    let idc = id_commitment(&p, s);

    assert_eq!(
        fr_to_bytes_le(&idc),
        from_hex("013e9afec060c939cc215f1cc2c6f419b9e28a5496145c4bdf633485ab12c00b"),
        "id_commitment KAT drift",
    );
    assert_eq!(
        fr_to_bytes_le(&hash_node(&p, l, r)),
        from_hex("00a7e5069273dc206e9f16709b9f462d0ac1a224e5543f7d9845748597049326"),
        "hash_node KAT drift",
    );
    assert_eq!(
        fr_to_bytes_le(&hash_leaf(&p, idc, expiry, scope)),
        from_hex("5dc9ea5002e5fb21d4291ad46cfc3b1ac66074520d0b6bab51e55c10d4a1862d"),
        "hash_leaf KAT drift",
    );
    assert_eq!(
        fr_to_bytes_le(&nullifier(&p, s, epoch)),
        from_hex("8da31b465bfdea71149d80055cf73b9ff2a4bfa0d2aa19010ec02316f4334f19"),
        "nullifier KAT drift",
    );
}

#[test]
fn params_are_deterministic() {
    let (s, ..) = kat_inputs();
    assert_eq!(id_commitment(&params(), s), id_commitment(&params(), s));
    // Config dimensions match the declared instance.
    let p = params();
    assert_eq!(p.full_rounds, FULL_ROUNDS);
    assert_eq!(p.partial_rounds, PARTIAL_ROUNDS);
    assert_eq!(p.ark.len(), FULL_ROUNDS + PARTIAL_ROUNDS);
    assert_eq!(p.mds.len(), RATE + CAPACITY);
    assert_eq!(p.ark[0].len(), RATE + CAPACITY);
}

#[test]
fn bytes_roundtrip_and_reject_noncanonical() {
    let p = params();
    let f = id_commitment(&p, Fr::from(123456789u64));
    let bytes = fr_to_bytes_le(&f);
    assert_eq!(fr_from_canonical_bytes_le(&bytes), Some(f));
    // 0xFF..FF is larger than the BN254 scalar modulus -> rejected.
    assert_eq!(fr_from_canonical_bytes_le(&[0xFFu8; 32]), None);
}

#[test]
fn domain_separation_holds() {
    let p = params();
    let x = Fr::from(99u64);
    let y = Fr::from(0u64);
    // Same field inputs, different roles -> different outputs.
    assert_ne!(id_commitment(&p, x), nullifier(&p, x, y));
    assert_ne!(hash_node(&p, x, y), hash_leaf(&p, x, y, Fr::from(0u64)));
    assert_ne!(id_commitment(&p, x), hash_node(&p, x, y));
}

#[cfg(feature = "gadget")]
#[test]
fn native_matches_gadget() {
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::eq::EqGadget;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;

    let p = params();
    let (s, expiry, scope, epoch, l, r) = kat_inputs();
    let idc = id_commitment(&p, s);

    let cs = ConstraintSystem::<Fr>::new_ref();
    let w = |v: Fr| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap();
    let (sv, ev, scv, epv, lv, rv, idcv) =
        (w(s), w(expiry), w(scope), w(epoch), w(l), w(r), w(idc));

    let g_idc = gadget::id_commitment_var(cs.clone(), &p, &sv).unwrap();
    let g_node = gadget::hash_node_var(cs.clone(), &p, &lv, &rv).unwrap();
    let g_leaf = gadget::hash_leaf_var(cs.clone(), &p, &idcv, &ev, &scv).unwrap();
    let g_null = gadget::nullifier_var(cs.clone(), &p, &sv, &epv).unwrap();

    assert_eq!(g_idc.value().unwrap(), idc);
    assert_eq!(g_node.value().unwrap(), hash_node(&p, l, r));
    assert_eq!(g_leaf.value().unwrap(), hash_leaf(&p, idc, expiry, scope));
    assert_eq!(g_null.value().unwrap(), nullifier(&p, s, epoch));

    // The witnessed native value and the in-circuit value agree as a
    // constraint, and the whole system is satisfiable.
    g_idc.enforce_equal(&w(idc)).unwrap();
    assert!(cs.is_satisfied().unwrap());
}
