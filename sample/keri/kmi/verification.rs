use crate::error::{err, Error, Result};

use cesride::{common::Ilkage, Diger, Indexer, Matter, Prefixer, Sadder, Serder};
use parside::{message::AttachedMaterialQuadlets, CesrGroup, Group, MessageList};

use super::super::{labels, verification, KeriStore};

use std::collections::HashSet;

pub(crate) fn verify_key_event(
    store: &impl KeriStore,
    serder: &Serder,
    quadlets: &AttachedMaterialQuadlets,
    deep: Option<bool>,
    verifying: Option<&mut HashSet<String>>,
    _indent: usize,
) -> Result<bool> {
    let mut backing_set = HashSet::new();
    let verifying = verifying.unwrap_or(&mut backing_set);

    // println!("{:?}", verifying);

    let pre = serder.pre()?;
    let ked = serder.ked();

    // see if code is supported
    let prefixer = Prefixer::new_with_qb64(&pre)?;

    let sn = serder.sn()?;
    let ilk = ked["t"].to_string()?;
    let said = serder.said()?;

    let mut existing = false;

    let inceptive = ilk == Ilkage::icp;
    let key_event_count = store.count_key_events(&pre)?;
    if inceptive {
        if !prefixer.verify(&serder.ked(), Some(true))? {
            return err!(Error::Verification);
        }

        if sn != 0 {
            // must be 0
            return err!(Error::Decoding);
        }

        if said != serder.pre()? {
            return err!(Error::Verification);
        }

        if key_event_count != 0 {
            existing = true;
        }
    } else {
        if !serder.saider().verify(&serder.ked(), Some(inceptive), Some(true), None, None, None)? {
            return err!(Error::Verification);
        }

        if sn < 1 {
            return err!(Error::Validation);
        }

        let sno = key_event_count as u128;

        if sn > sno {
            // escrow here
            return err!(Error::OutOfOrder);
        }

        if sn != sno {
            existing = true;
        }
    }

    let (verfers, tholder) = if serder.est()? {
        let tholder = if let Some(tholder) = serder.tholder()? {
            tholder
        } else {
            return err!(Error::Decoding);
        };

        (serder.verfers()?, tholder)
    } else {
        let (raw, _) = store.get_latest_establishment_event_as_of_sn(&pre, sn as u32 - 1)?;
        let serder = Serder::new_with_raw(raw.as_bytes())?;

        let tholder = if let Some(tholder) = serder.tholder()? {
            tholder
        } else {
            return err!(Error::Decoding);
        };

        (serder.verfers()?, tholder)
    };

    let mut verified_indices = vec![];
    let mut verified_prior_next_indices = vec![];
    for group in quadlets.value() {
        match group {
            CesrGroup::ControllerIdxSigsVariant { value } => {
                for controller_idx_sig in value.value() {
                    let siger = &controller_idx_sig.siger;

                    if siger.index() as usize > verfers.len() {
                        return err!(Error::Verification);
                    }

                    if verfers[siger.index() as usize].verify(&siger.raw(), &serder.raw())? {
                        verified_indices.push(siger.index());
                        verified_prior_next_indices.push(siger.ondex());
                    }
                }
            }
            _ => return err!(Error::Decoding),
        }
    }

    if !tholder.satisfy(&verified_indices)? {
        return err!(Error::Verification);
    }

    let labels = match ilk.as_str() {
        Ilkage::icp => &labels::ICP_LABELS,
        Ilkage::rot => &labels::ROT_LABELS,
        Ilkage::ixn => &labels::IXN_LABELS,
        _ => return err!(Error::Decoding),
    };
    if !verification::verify_ked_labels(&ked, labels)? {
        return err!(Error::Validation);
    }

    if !inceptive {
        // this sn implementation will become a problem at around 4 billion events
        let event = store.get_key_event(&pre, sn as u32 - 1)?;
        let pserder = Serder::new_with_raw(event.as_bytes())?;
        if pserder.said()? != serder.ked()["p"].to_string()? {
            return err!(Error::Validation);
        }

        if serder.est()? {
            let (digers, ntholder) = if pserder.est()? {
                (pserder.digers()?, pserder.ntholder()?.unwrap_or_default())
            } else {
                let (event, _) =
                    store.get_latest_establishment_event_as_of_sn(&pre, sn as u32 - 1)?;
                let serder = Serder::new_with_raw(event.as_bytes())?;
                (serder.digers()?, serder.ntholder()?.unwrap_or_default())
            };

            let mut prior_next_indices = vec![];
            for (i, index) in verified_indices.iter().enumerate() {
                let prior_next_index = verified_prior_next_indices[i];
                if (prior_next_index as usize) < digers.len() {
                    let verfer = &verfers[*index as usize];
                    let diger = Diger::new_with_ser(&verfer.qb64b()?, None)?;
                    if diger.qb64()? == digers[prior_next_index as usize].qb64()? {
                        prior_next_indices.push(prior_next_index);
                    }
                }
            }

            if !ntholder.satisfy(&prior_next_indices)? {
                println!("{prior_next_indices:?}, {verified_indices:?}");
                return err!(Error::Validation);
            }
        }

        if deep.unwrap_or(false) && !verifying.contains(&pserder.said()?) {
            verifying.insert(pserder.said()?);

            let (_, message_list) =
                MessageList::from_stream_bytes(event[pserder.raw().len()..].as_bytes())?;
            let group = message_list.messages[0].cesr_group()?;

            match group {
                CesrGroup::AttachedMaterialQuadletsVariant { value } => {
                    verify_key_event(store, &pserder, value, deep, Some(verifying), _indent + 2)?;
                }
                _ => return err!(Error::Decoding),
            }
        }
    }

    if existing {
        let event = store.get_key_event(&pre, sn as u32)?;
        let eserder = Serder::new_with_raw(event.as_bytes())?;

        // this seems very bad, it means something is in the database that shouldn't be there. how did it get there?
        if said != eserder.said()? {
            return err!(Error::Programmer);
        }
    }

    Ok(existing)
}
