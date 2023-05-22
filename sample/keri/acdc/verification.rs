use crate::error::{err, Error, Result};

use cesride::{
    common::{Ids, Ilkage, Serialage},
    Bext, Creder, Indexer, Matter, Sadder, Saider, Serder,
};
use parside::{message::AttachedMaterialQuadlets, CesrGroup, Group, MessageList};

use super::super::{kmi, KeriStore};
use super::schemer::cache as schema_cache;

use std::collections::HashSet;

const DEFAULT_CREDENTIAL_EXPIRY_SECONDS: i64 = 36000000000;

pub(crate) fn verify_acdc(
    store: &impl KeriStore,
    creder: &Creder,
    quadlets: &AttachedMaterialQuadlets,
    deep: Option<bool>,
    verifying: Option<&mut HashSet<String>>,
    _indent: usize,
) -> Result<bool> {
    let mut backing_set = HashSet::new();
    let verifying = verifying.unwrap_or(&mut backing_set);

    if creder.status()?.is_none() {
        return err!(Error::Validation);
    };

    let vcid = creder.said()?;
    let schema = creder.schema()?;
    let prov = creder.chains()?;

    let saider = Saider::new_with_qb64(&vcid)?;
    if !saider.verify(&creder.crd(), Some(false), Some(true), Some(Serialage::JSON), None, None)? {
        return err!(Error::Verification);
    }

    let event = store.get_latest_transaction_event(&vcid)?;
    let state = Serder::new_with_raw(event.as_bytes())?;
    let dtnow = chrono::Utc::now();
    let dte = chrono::DateTime::parse_from_rfc3339(&state.ked()["dt"].to_string()?)?
        .with_timezone(&chrono::Utc);
    if (dtnow - dte).num_seconds() > DEFAULT_CREDENTIAL_EXPIRY_SECONDS {
        return err!(Error::Validation);
    }

    if deep.unwrap_or(true) && !verifying.contains(&state.said()?) {
        verifying.insert(state.said()?);

        let (_, message_list) =
            MessageList::from_stream_bytes(event[state.raw().len()..].as_bytes())?;
        let group = message_list.messages[0].cesr_group()?;

        match group {
            CesrGroup::SealSourceCouplesVariant { value } => {
                super::tel::verification::verify_transaction_event(
                    store,
                    &state,
                    value,
                    deep,
                    Some(verifying),
                    _indent + 2,
                )?;
            }
            _ => return err!(Error::Decoding),
        }
    }

    // added brv here for safety even though unimplemented
    if [Ilkage::rev, Ilkage::brv].contains(&state.ked()[Ids::t].to_string()?.as_str()) {
        return err!(Error::Validation);
    }

    if !schema_cache().verify(&schema, std::str::from_utf8(&creder.raw())?)? {
        return err!(Error::Validation);
    }

    let mut rooted = false;

    for group in quadlets.value() {
        match group {
            CesrGroup::SadPathSigVariant { value } => {
                for sad_path_sig in value.value() {
                    if sad_path_sig.pather.bext()? != "-" {
                        continue;
                    }

                    rooted = true;

                    let event = store.get_key_event(
                        &sad_path_sig.prefixer.qb64()?,
                        sad_path_sig.seqner.sn()? as u32,
                    )?;
                    let serder = Serder::new_with_raw(event.as_bytes())?;
                    if serder.said()? != sad_path_sig.saider.qb64()? {
                        return err!(Error::Verification);
                    }

                    if deep.unwrap_or(true) && !verifying.contains(&serder.said()?) {
                        verifying.insert(serder.said()?);

                        let (_, message_list) =
                            MessageList::from_stream_bytes(event[serder.raw().len()..].as_bytes())?;
                        let group = message_list.messages[0].cesr_group()?;

                        match group {
                            CesrGroup::AttachedMaterialQuadletsVariant { value } => {
                                kmi::verification::verify_key_event(
                                    store,
                                    &serder,
                                    value,
                                    deep,
                                    Some(verifying),
                                    _indent + 2,
                                )?;
                            }
                            _ => return err!(Error::Decoding),
                        }
                    }

                    let verfers = serder.verfers()?;
                    let mut sigers = vec![];
                    for controller_idx_sig in sad_path_sig.sigers.value() {
                        let siger = &controller_idx_sig.siger;
                        if !sigers.contains(siger) {
                            sigers.push(siger.clone())
                        }
                    }

                    let mut verified_indices = vec![];
                    for siger in sigers {
                        if siger.index() as usize > verfers.len() {
                            return err!(Error::Verification);
                        }

                        if verfers[siger.index() as usize].verify(&siger.raw(), &creder.raw())? {
                            verified_indices.push(siger.index());
                        }
                    }

                    if let Some(tholder) = serder.tholder()? {
                        if !tholder.satisfy(&verified_indices)? {
                            return err!(Error::Verification);
                        }
                    } else {
                        return err!(Error::Verification);
                    }
                }
            }
            _ => return err!(Error::Decoding),
        }
    }

    if !rooted {
        return err!(Error::Verification);
    }

    let edges = if prov.to_map().is_ok() {
        vec![prov]
    } else if prov.to_vec().is_ok() {
        prov.to_vec()?
    } else {
        return err!(Error::Verification);
    };

    for edge in &edges {
        for (label, node) in edge.to_map()? {
            if [Ids::d, "o"].contains(&label.as_str()) {
                continue;
            }

            let map = node.to_map()?;

            let node_said = map["n"].to_string()?;
            let message = store.get_acdc(&node_said)?;
            let pacdc = Creder::new_with_raw(message.as_bytes())?;

            if map.contains_key("s") {
                let node_schema = map["s"].to_string()?;
                if !schema_cache().verify(&node_schema, std::str::from_utf8(&pacdc.raw())?)? {
                    return err!(Error::Validation);
                }
            }

            let mut operators = if map.contains_key("o") {
                let result = map["o"].to_string();
                if result.is_ok() {
                    vec![result?]
                } else {
                    map["o"].to_vec()?.iter().map(|o| o.to_string().unwrap()).collect()
                }
            } else {
                vec![]
            };

            // capture not, and remove everything but unary operators
            let not = operators.contains(&"NOT".to_string());
            if not {
                return err!(Error::Value);
            }
            let mut indices = vec![];
            for (i, value) in operators.iter().enumerate() {
                if value == "NOT" || !["I2I", "NI2I", "DI2I"].contains(&value.as_str()) {
                    indices.push(i);
                }
            }
            indices.reverse();
            for index in indices {
                operators.remove(index);
            }

            // if we have nothing left, add defaults
            let node_subject = pacdc.subject().to_map()?;
            if operators.is_empty() {
                if node_subject.contains_key(&"i".to_string()) {
                    operators.push("I2I".to_string());
                } else {
                    operators.push("NI2I".to_string());
                }
            }

            // if the programmer specified two unary operators, we have a problem
            if operators.len() != 1 {
                return err!(Error::Validation);
            }

            // actual validation logic
            match operators[0].as_str() {
                "I2I" => {
                    if node_subject["i"].to_string()? != creder.issuer()? {
                        return err!(Error::Validation);
                    }
                }
                "NI2I" => {}
                "DI2I" => unimplemented!(),
                _ => return err!(Error::Validation),
            }

            // here we need to default to true
            if deep.unwrap_or(true) && !verifying.contains(&node_said) {
                verifying.insert(node_said);

                let (_, message_list) =
                    MessageList::from_stream_bytes(message[pacdc.raw().len()..].as_bytes())?;
                let group = message_list.messages[0].cesr_group()?;

                match group {
                    CesrGroup::AttachedMaterialQuadletsVariant { value } => {
                        verify_acdc(store, &pacdc, value, deep, Some(verifying), _indent + 2)?;
                    }
                    _ => return err!(Error::Decoding),
                }
            }
        }
    }

    let result = store.get_acdc(&vcid);
    let existing = result.is_ok();
    if existing {
        let message = result.unwrap();
        let eacdc = Creder::new_with_raw(message.as_bytes())?;

        // this seems very bad, it means something is in the database that shouldn't be there. how did it get there?
        if vcid != eacdc.said()? {
            return err!(Error::Programmer);
        }
    }

    // println!("successfully verified acdc {vcid}");
    // println!("a {}{vcid}", ' '.to_string().repeat(_indent));

    Ok(existing)
}
