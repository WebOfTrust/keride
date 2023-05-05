use crate::{
    cesr::core::{
        cigar::Cigar,
        counter::{tables as counter, Counter},
        indexer::Indexer,
        sadder::Sadder,
        serder::Serder,
        siger::Siger,
    },
    error::{err, Error, Result},
    seal::Seal,
};

fn messagize(
    serder: &Serder,
    sigers: Option<&[Siger]>,
    seal: Option<&Seal>,
    wigers: Option<&[Siger]>,
    cigars: Option<&[Cigar]>,
) -> Result<String> {
    let message = String::from_utf8(serder.raw())?;
    let mut atc = "".to_string();

    if sigers.is_none() && wigers.is_none() && cigars.is_none() {
        return err!(Error::Value("missing attached signatures".to_string()));
    }

    if let Some(sigers) = sigers {
        if let Some(seal) = seal {
            if seal.last {
                atc += &Counter::new_with_code_and_count(counter::Codex::TransLastIdxSigGroups, 1)?
                    .qb64()?;
                atc += &seal.i();
            } else {
                atc += &Counter::new_with_code_and_count(counter::Codex::TransIdxSigGroups, 1)?
                    .qb64()?;
                atc += &seal.i();
                atc += &seal.s()?;
                atc += &seal.d();
            }
        }

        atc += &Counter::new_with_code_and_count(
            counter::Codex::ControllerIdxSigs,
            sigers.len() as u32,
        )?
        .qb64()?;
        for siger in sigers {
            atc += &(*siger).qb64()?;
        }
    }

    if let Some(wigers) = wigers {
        atc +=
            &Counter::new_with_code_and_count(counter::Codex::WitnessIdxSigs, wigers.len() as u32)?
                .qb64()?;
        for wiger in wigers {
            // todo: deny non-transferable
            atc += &(*wiger).qb64()?;
        }
    }

    // todo: complete this

    Ok(message + &atc)
}
