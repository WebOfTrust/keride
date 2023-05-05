use crate::{
    cesr::{
        common::{versify, Ilkage, Serialage, Version, CURRENT_VERSION},
        core::serder::Serder,
        Number,
    },
    dat,
    error::Result,
};

fn receipt(
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
