use crate::error::{err, Error, Result};
use cesride::{
    data::{dat, Value},
    matter, Sadder,
};

use super::KeySet;

pub(crate) mod endorsement;
pub(crate) mod event;
pub(crate) mod message;
pub(crate) mod verification;

#[derive(Debug, PartialEq, Eq)]
pub enum KeyKind {
    Ed25519,
    Secp256k1,
    Secp256r1,
}

impl KeyKind {
    pub fn to_cesr_code(&self) -> &str {
        match self {
            Self::Ed25519 => matter::Codex::Ed25519_Seed,
            Self::Secp256k1 => matter::Codex::ECDSA_256k1_Seed,
            Self::Secp256r1 => matter::Codex::ECDSA_256r1_Seed,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn incept_partial(
    code: Option<&str>,
    scount: Option<usize>,
    rcount: Option<usize>, // count of keys to keep in reserve for rotation
    transferable: Option<bool>,
    pcode: Option<&str>,
    tier: Option<&str>,
    salt: Option<&[u8]>,
    next_keys: Option<&[&str]>,
    next_sith: Option<&str>,
) -> Result<(String, KeySet, String)> {
    let scount = scount.unwrap_or(2);
    let mut rcount = rcount.unwrap_or(3);
    let sn = 0u128;

    #[cfg(not(test))]
    let temp: Option<bool> = None;
    #[cfg(test)]
    let temp: Option<bool> = Some(true);

    let ckeys = KeySet::generate(code, Some(scount), 0, transferable, &sn.to_string(), tier, temp)?;
    let keys = ckeys.verfers_qb64()?;

    let ndigs = if let Some(next_keys) = next_keys {
        rcount = next_keys.len();
        next_keys.iter().map(|s| s.to_string()).collect()
    } else if let Some(salt) = salt {
        if transferable.unwrap_or(false) {
            let nkeys = KeySet::generate_from_salt(
                salt,
                code,
                Some(rcount),
                0,
                transferable,
                &(sn + 1).to_string(),
                tier,
                temp,
            )?;

            nkeys.digers_qb64()?
        } else {
            vec![]
        }
    } else {
        return err!(Error::Programmer);
    };

    let mut sith = vec![];
    for _ in 0..scount {
        sith.push(dat!(&format!("1/{scount}")));
    }
    let sith = dat!([dat!(sith.as_slice())]);

    let nsith: Value = if let Some(next_sith) = next_sith {
        let value: serde_json::Value = serde_json::from_str(next_sith)?;
        Value::from(&value)
    } else {
        let mut nsith = vec![];
        for _ in 0..rcount {
            nsith.push(dat!(&format!("1/{rcount}")));
        }
        dat!([dat!(nsith.as_slice())])
    };

    let serder = event::incept(
        &keys,
        Some(&sith),
        Some(&ndigs),
        Some(&nsith),
        Some(0),
        None, // Some(&wits),
        None,
        None,
        None,
        None,
        pcode,
        None,
        None,
    )?;

    let sigers = ckeys.sign(&serder.raw(), None)?;
    let endorsement = endorsement::endorse_serder(Some(&sigers), None, None, None)?;
    let event = message::messagize_serder(&serder, &endorsement, Some(true))?;

    Ok((serder.pre()?, ckeys, event))
}

#[allow(clippy::too_many_arguments)]
pub fn incept(
    code: Option<&str>,
    count: Option<usize>,
    sith: Option<&Value>,
    ncode: Option<&str>,
    ncount: Option<usize>,
    nsith: Option<&Value>,
    wcount: Option<usize>,
    transferable: Option<bool>,
    pcode: Option<&str>,
    tier: Option<&str>,
) -> Result<(String, Vec<KeySet>, String)> {
    #[cfg(not(test))]
    let temp: Option<bool> = None;
    #[cfg(test)]
    let temp: Option<bool> = Some(true);

    let ckeys = KeySet::generate(code, count, 0, transferable, "0", tier, temp)?;
    let keys = ckeys.verfers_qb64()?;

    let (ndigs, nkeys) = if transferable.unwrap_or(false) {
        let keys = KeySet::generate(ncode, ncount, 0, transferable, "0", tier, temp)?;
        (keys.digers_qb64()?, Some(keys))
    } else {
        (vec![], None)
    };

    let wcount = wcount.map(|wcount| wcount as u128);
    let serder = event::incept(
        &keys,
        sith,
        Some(&ndigs),
        nsith,
        wcount,
        None, // Some(&wits),
        None,
        None,
        None,
        None,
        pcode,
        None,
        None,
    )?;

    let sigers = ckeys.sign(&serder.raw(), None)?;
    let endorsement = endorsement::endorse_serder(Some(&sigers), None, None, None)?;
    let event = message::messagize_serder(&serder, &endorsement, Some(true))?;

    let mut result = vec![ckeys];
    if let Some(nkeys) = nkeys {
        result.push(nkeys);
    }

    Ok((serder.pre()?, result, event))
}

#[allow(clippy::too_many_arguments)]
pub fn rotate_partial(
    pre: &str,
    dig: &str,
    sn: u128,
    key_sn: u128,
    code: Option<&str>,
    scount: Option<usize>,
    rcount: Option<usize>,
    tier: Option<&str>,
    salt: Option<&[u8]>,
    next_salt: Option<&[u8]>,
    current_rotation_keys: Option<&[&str]>,
    next_keys: Option<&[&str]>,
    next_sith: Option<&str>,
) -> Result<(String, KeySet, String)> {
    let scount = scount.unwrap_or(2);
    let mut rcount = rcount.unwrap_or(3);
    let mut ccount = rcount;

    #[cfg(not(test))]
    let temp: Option<bool> = None;
    #[cfg(test)]
    let temp: Option<bool> = Some(true);

    let (mut public_keys, ndigs, ckeys) = if let Some(salt) = salt {
        if current_rotation_keys.is_some() || next_keys.is_some() || next_sith.is_some() {
            return err!(Error::Value);
        }

        let next_salt = if let Some(next_salt) = next_salt {
            next_salt
        } else {
            return err!(Error::Value);
        };

        let ckeys = KeySet::generate_from_salt(
            salt,
            code,
            Some(ccount),
            0,
            Some(true),
            &key_sn.to_string(),
            tier,
            temp,
        )?;
        let rkeys = KeySet::generate_from_salt(
            next_salt,
            code,
            Some(rcount),
            0,
            Some(true),
            &(key_sn + 1).to_string(),
            tier,
            temp,
        )?;

        (ckeys.verfers_qb64()?, rkeys.digers_qb64()?, Some(ckeys))
    } else {
        if current_rotation_keys.is_none() || next_keys.is_none() || next_sith.is_none() {
            return err!(Error::Value);
        }
        if salt.is_some() || next_salt.is_some() {
            return err!(Error::Value);
        }

        let public_keys: Vec<String> =
            current_rotation_keys.unwrap().iter().map(|s| s.to_string()).collect();
        let next_keys: Vec<String> = next_keys.unwrap().iter().map(|s| s.to_string()).collect();

        ccount = public_keys.len();
        rcount = next_keys.len();

        (public_keys, next_keys, None)
    };

    let skeys =
        KeySet::generate(code, Some(scount), ccount, Some(true), &key_sn.to_string(), tier, temp)?;
    public_keys.append(&mut skeys.verfers_qb64()?);

    let mut sith = vec![];
    for _ in 0..ccount {
        sith.push(dat!("0"));
    }
    for _ in 0..scount {
        sith.push(dat!(&format!("1/{scount}")));
    }
    let sith = dat!([dat!(sith.as_slice())]);

    let nsith = if let Some(next_sith) = next_sith {
        let value: serde_json::Value = serde_json::from_str(next_sith)?;
        Value::from(&value)
    } else {
        let mut nsith = vec![];
        for _ in 0..rcount {
            nsith.push(dat!(&format!("1/{rcount}")));
        }
        dat!([dat!(nsith.as_slice())])
    };

    let serder = event::rotate(
        pre,
        &public_keys,
        dig,
        None,
        sn,
        Some(&sith),
        Some(&ndigs),
        Some(&nsith),
        Some(0),
        None, // Some(&wits),
        None,
        None,
        None,
        None,
        None,
        None,
    )?;

    if next_sith.is_some() {
        return Ok((serder.said()?, skeys, String::from_utf8(serder.raw())?));
    }

    if let Some(ckeys) = ckeys {
        let mut sigers = ckeys.sign(&serder.raw(), None)?;
        sigers.append(&mut skeys.sign(&serder.raw(), None)?);
        let endorsement = endorsement::endorse_serder(Some(&sigers), None, None, None)?;
        let event = message::messagize_serder(&serder, &endorsement, Some(true))?;

        Ok((serder.said()?, skeys, event))
    } else {
        err!(Error::Programmer)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn rotate(
    pre: &str,
    ckeys: &KeySet,
    dig: &str,
    sn: u128,
    sith: Option<&Value>,
    ncode: Option<&str>,
    ncount: Option<usize>,
    nsith: Option<&Value>,
    wcount: Option<usize>,
    tier: Option<&str>,
) -> Result<(String, KeySet, String)> {
    #[cfg(not(test))]
    let temp: Option<bool> = None;
    #[cfg(test)]
    let temp: Option<bool> = Some(true);

    let nkeys = KeySet::generate(ncode, ncount, 0, Some(true), &sn.to_string(), tier, temp)?;

    let ndigs = nkeys.digers_qb64()?;
    let public_keys = ckeys.verfers_qb64()?;

    let wcount = wcount.map(|wcount| wcount as u128);
    let serder = event::rotate(
        pre,
        &public_keys,
        dig,
        None,
        sn,
        sith,
        Some(&ndigs),
        nsith,
        wcount,
        None, // Some(&wits),
        None,
        None,
        None,
        None,
        None,
        None,
    )?;

    let sigers = ckeys.sign(&serder.raw(), None)?;
    let endorsement = endorsement::endorse_serder(Some(&sigers), None, None, None)?;
    let event = message::messagize_serder(&serder, &endorsement, Some(true))?;

    Ok((serder.said()?, nkeys, event))
}

pub(crate) fn interact(
    keys: &KeySet, // current signing keys
    pre: &str,     // identifier prefix
    dig: &str,     // previous event said
    sn: u128,      // sequence number
    data: &Value,  // seals
) -> Result<(String, String)> {
    let serder = event::interact(pre, dig, Some(sn), Some(data), None, None)?;
    let sigers = keys.sign(&serder.raw(), None)?;
    let endorsement = endorsement::endorse_serder(Some(&sigers), None, None, None)?;
    let event = message::messagize_serder(&serder, &endorsement, Some(true))?;

    Ok((serder.said()?, event))
}
