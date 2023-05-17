use super::{kmi, KeriStore};
use crate::error::{err, Error, Result};

use cesride::{common::Ilkage, data::Value, Matter, Sadder, Saider, Seqner, Serder};
use parside::{CesrGroup, MessageList};

use std::collections::HashSet;

pub(crate) fn extract_registry_from_serder(ilk: &str, serder: &Serder) -> Result<String> {
    match ilk {
        Ilkage::vcp => serder.pre(),
        Ilkage::iss | Ilkage::rev => serder.ked()["ri"].to_string(),
        _ => err!(Error::Decoding),
    }
}

pub(crate) fn verify_ked_labels(ked: &Value, labels: &[&str]) -> Result<bool> {
    let map = ked.to_map()?;
    for label in labels {
        if !map.contains_key(&label.to_string()) {
            return Ok(false);
        }
    }

    Ok(true)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_anchor(
    store: &impl KeriStore,
    anchor_pre: &str,
    seqner: &Seqner,
    saider: &Saider,
    serder: &Serder,
    deep: Option<bool>,
    verifying: Option<&mut HashSet<String>>,
    _indent: usize,
) -> Result<bool> {
    let mut backing_set = HashSet::new();
    let verifying = verifying.unwrap_or(&mut backing_set);

    let event = store.get_key_event(anchor_pre, seqner.sn()? as u32)?;
    let aserder = Serder::new_with_raw(event.as_bytes())?;
    if aserder.said()? != saider.qb64()? {
        return Ok(false);
    }

    let seals = aserder.ked()["a"].to_vec()?;
    if seals.len() != 1 {
        return Ok(false);
    }

    let seal = &seals[0];

    let spre = seal["i"].to_string()?;
    let ssn = seal["s"].to_string()?;
    let sdig = seal["d"].to_string()?;

    if deep.unwrap_or(false) && !verifying.contains(&aserder.said()?) {
        verifying.insert(aserder.said()?);

        let (_, message_list) =
            MessageList::from_stream_bytes(event[aserder.raw().len()..].as_bytes())?;
        let group = message_list.messages[0].cesr_group()?;

        match group {
            CesrGroup::AttachedMaterialQuadletsVariant { value } => {
                kmi::verification::verify_key_event(
                    store,
                    &aserder,
                    value,
                    deep,
                    Some(verifying),
                    _indent,
                )?;
            }
            _ => return err!(Error::Decoding),
        }
    }

    if ssn == serder.ked()["s"].to_string()? && spre == serder.pre()? && sdig == serder.said()? {
        return Ok(true);
    }

    Ok(false)
}
