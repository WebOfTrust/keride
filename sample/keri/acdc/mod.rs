pub(crate) mod endorsement;
pub(crate) mod event;
pub(crate) mod message;
pub(crate) mod schemer;
pub(crate) mod tel;
pub(crate) mod verification;

use super::KeriStore;
use crate::error::{err, Error, Result};
use cesride::{
    counter,
    data::{dat, Value},
    Counter, Matter, Sadder, Seqner, Serder,
};

#[allow(clippy::too_many_arguments)]
pub fn issue_acdc(
    store: &impl KeriStore,
    status: &str, // public management tel registry identifier
    issuer: &str, // controlled identifier label
    schema: &str,
    data: &str,
    recipient: Option<&str>,
    private: Option<bool>,
    source: Option<&str>,
    rules: Option<&str>,
) -> Result<(String, String, String, String)> {
    let value: serde_json::Value = serde_json::from_str(data)?;
    let data = Value::from(&value);

    let acdc = if source.is_some() && rules.is_some() {
        let value: serde_json::Value = serde_json::from_str(source.unwrap())?;
        let source = Value::from(&value);
        let source = Some(&source);
        let value: serde_json::Value = serde_json::from_str(rules.unwrap())?;
        let rules = Value::from(&value);
        let rules = Some(&rules);
        event::create(
            schema,
            issuer,
            &data,
            recipient,
            private,
            None,
            Some(status),
            source,
            rules,
            None,
            None,
        )?
    } else if source.is_some() {
        let value: serde_json::Value = serde_json::from_str(source.unwrap())?;
        let source = Value::from(&value);
        let source = Some(&source);
        event::create(
            schema,
            issuer,
            &data,
            recipient,
            private,
            None,
            Some(status),
            source,
            None,
            None,
            None,
        )?
    } else if rules.is_some() {
        let value: serde_json::Value = serde_json::from_str(rules.unwrap())?;
        let rules = Value::from(&value);
        let rules = Some(&rules);
        event::create(
            schema,
            issuer,
            &data,
            recipient,
            private,
            None,
            Some(status),
            None,
            rules,
            None,
            None,
        )?
    } else {
        event::create(
            schema,
            issuer,
            &data,
            recipient,
            private,
            None,
            Some(status),
            None,
            None,
            None,
            None,
        )?
    };

    // println!("{}", std::str::from_utf8(&acdc.raw())?);

    let mut sigers = vec![];
    let mut k: Vec<Value> = vec![];

    let acdc_said = acdc.said()?;
    let (iss_said, iss) = tel::vc::issue(&acdc_said, status)?;

    let sn = store.count_key_events(issuer)? as u128;
    let dig = store.get_latest_key_event_said(issuer)?;
    let data = dat!([{
        "i": &acdc_said,
        "s": "0",
        "d": &iss_said,
    }]);
    let key_set = store.get_current_keys(issuer)?;
    for verfer in &key_set.verfers()? {
        k.push(dat!(&verfer.qb64()?));
    }
    sigers.append(&mut key_set.sign(&acdc.raw(), None)?);
    let (ixn_said, ixn) = super::kmi::interact(&key_set, issuer, &dig, sn, &data)?;
    drop(key_set);

    let counter = Counter::new_with_code_and_count(counter::Codex::SealSourceCouples, 1)?;
    let seqner = Seqner::new_with_sn(sn)?;
    let iss = iss + &counter.qb64()? + &seqner.qb64()? + &ixn_said;

    let (said, sn) = store.get_latest_establishment_event_said(issuer)?;
    let seqner = Seqner::new_with_sn(sn)?;
    let proof = endorsement::ratify_creder(issuer, seqner, &said, &sigers)?;
    let signed_acdc = message::messagize_creder(&acdc, &proof)?;

    Ok((acdc_said, ixn, iss, signed_acdc))
}

pub fn revoke_acdc(
    store: &impl KeriStore,
    status: &str,
    issuer: &str,
    said: &str,
) -> Result<(String, String)> {
    let priors = store.get_tel(said)?;
    if priors.len() != 1 {
        return err!(Error::Value);
    }
    let serder = Serder::new_with_raw(priors[0].as_bytes())?;

    let (rev_said, rev) = tel::vc::revoke(said, status, &serder.said()?)?;

    let sn = store.count_key_events(issuer)? as u128;
    let dig = store.get_latest_key_event_said(issuer)?;
    let data = dat!([{
        "i": said,
        "s": "1",
        "d": &rev_said,
    }]);
    let key_set = store.get_current_keys(issuer)?;
    let (ixn_said, ixn) = super::kmi::interact(&key_set, issuer, &dig, sn, &data)?;
    drop(key_set);

    let counter = Counter::new_with_code_and_count(counter::Codex::SealSourceCouples, 1)?;
    let seqner = Seqner::new_with_sn(sn)?;
    let rev = rev + &counter.qb64()? + &seqner.qb64()? + &ixn_said;

    Ok((ixn, rev))
}
