use crate::error::Result;
use cesride::{counter, data::dat, Counter, Indexer, Matter, Pather, Seqner, Siger};

pub(crate) fn ratify_creder(
    prefix: &str,
    seqner: Seqner,
    said: &str,
    sigers: &[Siger],
) -> Result<String> {
    let sad_path_sig = Counter::new_with_code_and_count(counter::Codex::SadPathSig, 1)?;
    let path = dat!([]);
    let pather = Pather::new_with_path(&path)?;

    let mut proof = "".to_string();
    proof += &sad_path_sig.qb64()?;
    proof += &pather.qb64()?;

    let counter = Counter::new_with_code_and_count(counter::Codex::TransIdxSigGroups, 1)?;
    proof += &counter.qb64()?;
    proof += prefix;
    proof += &seqner.qb64()?;
    proof += said;

    let counter =
        Counter::new_with_code_and_count(counter::Codex::ControllerIdxSigs, sigers.len() as u32)?;
    proof += &counter.qb64()?;
    for siger in sigers {
        proof += &siger.qb64()?;
    }

    Ok(proof)
}
