use crate::error::{err, Error, Result};
use cesride::{common::Ids, counter, data::Value, Cigar, Counter, Indexer, Matter, Seqner, Siger};

#[derive(Debug, Clone)]
pub(crate) struct Seal {
    value: Value,
    last: bool,
}

impl Seal {
    #[allow(dead_code)]
    pub fn new(value: &Value, last: bool) -> Self {
        Seal { value: value.clone(), last }
    }

    pub fn value(&self) -> Value {
        self.value.clone()
    }

    pub fn last(&self) -> bool {
        self.last
    }
}

pub(crate) fn endorse_serder(
    sigers: Option<&[Siger]>,
    seal: Option<&Seal>,
    wigers: Option<&[Siger]>,
    cigars: Option<&[Cigar]>,
) -> Result<String> {
    let mut atc = "".to_string();

    if sigers.is_none() && wigers.is_none() && cigars.is_none() {
        return err!(Error::Value);
    }

    if let Some(sigers) = sigers {
        if let Some(seal) = seal {
            if seal.last() {
                atc += &Counter::new_with_code_and_count(counter::Codex::TransLastIdxSigGroups, 1)?
                    .qb64()?;
                atc += &seal.value()[Ids::i].to_string()?;
            } else {
                atc += &Counter::new_with_code_and_count(counter::Codex::TransIdxSigGroups, 1)?
                    .qb64()?;
                atc += &seal.value()[Ids::i].to_string()?;
                atc += &Seqner::new_with_snh(&seal.value()[Ids::s].to_string()?)?.qb64()?;
                atc += &seal.value()[Ids::d].to_string()?;
            }
        }

        atc += &Counter::new_with_code_and_count(
            counter::Codex::ControllerIdxSigs,
            sigers.len() as u32,
        )?
        .qb64()?;
        for siger in sigers {
            atc += &siger.qb64()?;
        }
    }

    if let Some(wigers) = wigers {
        atc +=
            &Counter::new_with_code_and_count(counter::Codex::WitnessIdxSigs, wigers.len() as u32)?
                .qb64()?;
        for wiger in wigers {
            if wiger.verfer().transferable() {
                return err!(Error::Encoding);
            }

            atc += &wiger.qb64()?;
        }
    }

    if let Some(cigars) = cigars {
        atc += &Counter::new_with_code_and_count(
            counter::Codex::NonTransReceiptCouples,
            cigars.len() as u32,
        )?
        .qb64()?;
        for cigar in cigars {
            if cigar.verfer().transferable() {
                return err!(Error::Encoding);
            }

            atc += &cigar.qb64()?;
        }
    }

    Ok(atc)
}
