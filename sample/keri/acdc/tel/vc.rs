use crate::error::Result;
use cesride::{
    common::{versify, Ilkage, Serialage, CURRENT_VERSION},
    data::dat,
    Matter, Sadder, Saider, Salter, Serder,
};

pub(crate) fn issue(said: &str, ri: &str) -> Result<(String, String)> {
    let vs = versify(None, Some(CURRENT_VERSION), Some(Serialage::JSON), Some(0))?;

    let nonce = Salter::new_with_defaults(None)?.signer(None, Some(false), None, None, None)?;
    let ted = dat!({
        "v": &vs,
        "t": Ilkage::iss,
        "d": "",
        "i": said,
        "s": "0",
        "ri": ri,
        "dt": dat!(&chrono::Utc::now().format("%+").to_string()),
        "n": &nonce.qb64()?,
    });

    let (_, ted) = Saider::saidify(&ted, None, None, None, None)?;
    let serder = Serder::new_with_ked(&ted, None, None)?;

    Ok((serder.said()?, String::from_utf8(serder.raw())?))
}

pub(crate) fn revoke(said: &str, ri: &str, prior: &str) -> Result<(String, String)> {
    let vs = versify(None, Some(CURRENT_VERSION), Some(Serialage::JSON), Some(0))?;

    let nonce = Salter::new_with_defaults(None)?.signer(None, Some(false), None, None, None)?;
    let ted = dat!({
        "v": &vs,
        "t": Ilkage::rev,
        "d": "",
        "i": said,
        "s": "1",
        "ri": ri,
        "p": prior,
        "dt": dat!(&chrono::Utc::now().format("%+").to_string()),
        "n": &nonce.qb64()?,
    });

    let (_, ted) = Saider::saidify(&ted, None, None, None, None)?;
    let serder = Serder::new_with_ked(&ted, None, None)?;

    Ok((serder.said()?, String::from_utf8(serder.raw())?))
}
