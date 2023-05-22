use crate::error::Result;
use cesride::{
    common::{versify, Ilkage, Serialage, CURRENT_VERSION},
    data::dat,
    matter, Matter, Prefixer, Sadder, Serder,
};

pub(crate) fn incept(issuer: &str) -> Result<(String, String)> {
    let vs = versify(None, Some(CURRENT_VERSION), Some(Serialage::JSON), Some(0))?;

    let mut ted = dat!({
        "v": &vs,
        "t": Ilkage::vcp,
        "d": "",
        "i": "",
        "ii": issuer,
        "s": "0",
        "c": ["NB"],
        "bt": "0",
        "b": [],
    });

    let prefixer = Prefixer::new_with_ked(&ted, None, Some(matter::Codex::Blake3_256))?;
    let prefix = prefixer.qb64()?;
    ted["i"] = dat!(&prefix);
    ted["d"] = dat!(&prefix);

    let serder = Serder::new_with_ked(&ted, None, None)?;

    Ok((prefix, String::from_utf8(serder.raw())?))
}
