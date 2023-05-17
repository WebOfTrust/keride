use crate::error::{err, Error, Result};

use cesride::{
    common::{Identage, Ilkage},
    Creder, Sadder, Serder,
};
use parside::{message::GroupItem, CesrGroup, MessageList};

use super::{acdc, kmi, KeriStore};

use std::collections::HashSet;

fn seen_said(store: &impl KeriStore, said: &str) -> bool {
    store.get_sad(said).is_ok()
}

pub fn ingest_messages(
    store: &mut impl KeriStore,
    messages: &str,
    deep: Option<bool>,
    verify: Option<bool>,
) -> Result<()> {
    let mut verifying = HashSet::new();

    let (_, message_list) = MessageList::from_stream_bytes(messages.as_bytes())?;
    let mut messages = message_list.messages.iter();

    loop {
        let sadder = messages.next();
        if let Some(sadder) = sadder {
            let payload = sadder.payload()?;
            let raw_string = payload.value.to_string();
            let raw_message = raw_string.as_bytes();
            let result = cesride::common::sniff(raw_message)?;

            // println!("{:?}", verifying);

            if result.ident == Identage::KERI {
                let serder = Serder::new_with_raw(raw_message)?;
                let said = serder.said()?;

                let message = messages.next();
                if let Some(message) = message {
                    let group = message.cesr_group()?;
                    match serder.ked()["t"].to_string()?.as_str() {
                        Ilkage::icp | Ilkage::rot | Ilkage::ixn => {
                            match group {
                                CesrGroup::AttachedMaterialQuadletsVariant { value } => {
                                    let existing =
                                        if verify.unwrap_or(true) && !verifying.contains(&said) {
                                            verifying.insert(said);
                                            kmi::verification::verify_key_event(
                                                store,
                                                &serder,
                                                value,
                                                deep,
                                                Some(&mut verifying),
                                                0,
                                            )?
                                        } else {
                                            seen_said(store, &said)
                                        };

                                    if !existing {
                                        let event = String::from_utf8(serder.raw())?;
                                        store.insert_key_event(
                                            &serder.pre()?,
                                            &(event + &group.qb64()?),
                                        )?;
                                    }
                                }
                                _ => return err!(Error::Decoding), // we only accept pipelined input at present
                            }
                        }
                        Ilkage::vcp | Ilkage::iss | Ilkage::rev => match group {
                            CesrGroup::SealSourceCouplesVariant { value } => {
                                let existing =
                                    if verify.unwrap_or(true) && !verifying.contains(&said) {
                                        verifying.insert(said);
                                        acdc::tel::verification::verify_transaction_event(
                                            store,
                                            &serder,
                                            value,
                                            deep,
                                            Some(&mut verifying),
                                            0,
                                        )?
                                    } else {
                                        seen_said(store, &said)
                                    };

                                if !existing {
                                    let event = String::from_utf8(serder.raw())?;
                                    store.insert_transaction_event(
                                        &serder.pre()?,
                                        &(event + &group.qb64()?),
                                    )?;
                                }
                            }
                            _ => return err!(Error::Decoding),
                        },
                        _ => return err!(Error::Decoding),
                    }
                } else {
                    return err!(Error::Decoding);
                }
            } else if result.ident == Identage::ACDC {
                let creder = Creder::new_with_raw(raw_message)?;
                let said = creder.said()?;

                let message = messages.next();
                if let Some(message) = message {
                    let group = message.cesr_group()?;
                    match group {
                        CesrGroup::AttachedMaterialQuadletsVariant { value } => {
                            let existing = if verify.unwrap_or(true) && !verifying.contains(&said) {
                                verifying.insert(said);
                                acdc::verification::verify_acdc(
                                    store,
                                    &creder,
                                    value,
                                    deep,
                                    Some(&mut verifying),
                                    0,
                                )?
                            } else {
                                seen_said(store, &said)
                            };

                            if !existing {
                                let acdc = String::from_utf8(creder.raw())?;
                                store.insert_acdc(&(acdc + &group.qb64()?))?;
                            }
                        }
                        _ => return err!(Error::Decoding), // we only accept pipelined input at present
                    };
                } else {
                    return err!(Error::Decoding);
                }
            } else {
                return err!(Error::Decoding);
            }
        } else {
            break;
        }
    }

    Ok(())
}
