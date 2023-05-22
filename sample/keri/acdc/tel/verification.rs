use crate::error::{err, Error, Result};

use cesride::{common::Ilkage, Prefixer, Sadder, Serder};
use parside::{message::SealSourceCouples, CesrGroup, Group, MessageList};

use super::super::super::{labels, verification, KeriStore};

use std::collections::HashSet;

pub(crate) fn verify_transaction_event(
    store: &impl KeriStore,
    serder: &Serder,
    seal_source_couples: &SealSourceCouples,
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
    let ri = verification::extract_registry_from_serder(&ilk, serder)?;

    let mut existing = false;

    if seal_source_couples.value.len() != 1 {
        return err!(Error::Decoding);
    }
    let source_saider = &seal_source_couples.value()[0].saider;
    let source_seqner = &seal_source_couples.value()[0].seqner;

    let labels = match ilk.as_str() {
        Ilkage::vcp => &labels::VCP_LABELS,
        Ilkage::iss => &labels::ISS_LABELS,
        Ilkage::rev => &labels::REV_LABELS,
        _ => return err!(Error::Decoding),
    };
    if !verification::verify_ked_labels(&ked, labels)? {
        return err!(Error::Validation);
    }

    let inceptive = ilk == Ilkage::vcp || ilk == Ilkage::iss;
    let transaction_event_count = store.count_transaction_events(&pre)?;

    let apre = match ilk.as_str() {
        Ilkage::vcp => {
            if !prefixer.verify(&ked, Some(true))? {
                return err!(Error::Verification);
            }

            ked["ii"].to_string()?
        }
        Ilkage::iss | Ilkage::rev => {
            if !serder.saider().verify(&ked, Some(false), Some(true), None, None, None)? {
                return err!(Error::Verification);
            }

            let rievent = store.get_transaction_event(&ri, 0)?;
            let riserder = Serder::new_with_raw(rievent.as_bytes())?;

            riserder.ked()["ii"].to_string()?
        }
        _ => return err!(Error::Decoding),
    };

    if !verification::verify_anchor(
        store,
        &apre,
        source_seqner,
        source_saider,
        serder,
        deep,
        Some(verifying),
        _indent + 2,
    )? {
        return err!(Error::Verification);
    }

    if inceptive {
        if sn != 0 {
            // must be 0
            return err!(Error::Decoding);
        }

        if transaction_event_count != 0 {
            existing = true;
        }
    } else {
        if sn < 1 {
            return err!(Error::Validation);
        }

        let sno = transaction_event_count as u128;

        if sn > sno {
            // escrow here
            return err!(Error::OutOfOrder);
        }

        if sn != sno {
            existing = true;
        }

        // this sn implementation will become a problem at around 4 billion events
        let event = store.get_transaction_event(&pre, sn as u32 - 1)?;
        let pserder = Serder::new_with_raw(event.as_bytes())?;

        if deep.unwrap_or(true) && !verifying.contains(&pserder.said()?) {
            verifying.insert(pserder.said()?);

            let (_, message_list) =
                MessageList::from_stream_bytes(event[pserder.raw().len()..].as_bytes())?;
            let group = message_list.messages[0].cesr_group()?;

            match group {
                CesrGroup::SealSourceCouplesVariant { value } => {
                    verify_transaction_event(
                        store,
                        &pserder,
                        value,
                        deep,
                        Some(verifying),
                        _indent + 2,
                    )?;
                }
                _ => return err!(Error::Decoding),
            }
        }

        if pserder.said()? != serder.ked()["p"].to_string()? {
            return err!(Error::Verification);
        }
    }

    if existing {
        let event = store.get_transaction_event(&pre, sn as u32)?;
        let eserder = Serder::new_with_raw(event.as_bytes())?;

        // this seems very bad, it means something is in the database that shouldn't be there. how did it get there?
        if said != eserder.said()? {
            return err!(Error::Programmer);
        }
    }

    // println!("successfully verified transaction event [{pre}, {said}]");
    // println!("t {}{said}", ' '.to_string().repeat(_indent));

    Ok(existing)
}
