use crate::error::{err, Error, Result};
use cesride::{
    common::{versify, Ilkage, Serialage, Version, CURRENT_VERSION},
    counter,
    data::dat,
    Counter, Number, Sadder, Serder,
};

pub(crate) fn messagize_serder(
    serder: &Serder,
    endorsement: &str,
    pipelined: Option<bool>,
) -> Result<String> {
    let message = String::from_utf8(serder.raw())?;

    let pipeline_glue = if pipelined.unwrap_or(false) {
        if endorsement.len() % 4 != 0 {
            return err!(Error::Value);
        }

        Counter::new_with_code_and_count(
            counter::Codex::AttachedMaterialQuadlets,
            (endorsement.len() / 4) as u32,
        )?
        .qb64()?
    } else {
        "".to_string()
    };

    Ok(message + &pipeline_glue + endorsement)
}

#[allow(dead_code)]
pub(crate) fn receipt(
    pre: &str,
    sn: u128,
    said: &str,
    version: Option<&Version>,
    kind: Option<&str>,
) -> Result<Serder> {
    let version = version.unwrap_or(CURRENT_VERSION);
    let kind = kind.unwrap_or(Serialage::JSON);

    let vs = versify(None, Some(version), Some(kind), Some(0))?;
    let ilk = Ilkage::rct;

    let sner = Number::new_with_num(sn)?;

    let ked = dat!({
        "v": &vs,
        "t": ilk,
        "d": said,
        "i": pre,
        "s": &sner.numh()?
    });

    Serder::new_with_ked(&ked, None, None)
}
