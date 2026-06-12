use pangs_pir::{fsa_compatible, AbiClass, Param, Signature};

fn sig(ret: AbiClass, params: Vec<Param>) -> Signature {
    Signature {
        ret,
        params,
        vararg: false,
        cc: "ccc".to_string(),
    }
}

#[test]
fn integer_and_pointer_class_punning_is_wide() {
    let site = sig(AbiClass::Void, vec![Param::Integer]);
    let callee = sig(AbiClass::Integer, vec![Param::Integer]);
    assert!(fsa_compatible(&site, &callee));
}

#[test]
fn sse_does_not_match_integer() {
    let site = sig(AbiClass::Void, vec![Param::Sse]);
    let callee = sig(AbiClass::Void, vec![Param::Integer]);
    assert!(!fsa_compatible(&site, &callee));
}

#[test]
fn byval_size_must_match() {
    let site = sig(AbiClass::Void, vec![Param::Byval { size: 8 }]);
    let callee = sig(AbiClass::Void, vec![Param::Byval { size: 16 }]);
    assert!(!fsa_compatible(&site, &callee));
}
