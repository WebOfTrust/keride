use crate::error::{err, Error, Result};
use cesride::{
    data::{dat, Value},
    matter, Diger, Matter, Sadder, Salter,
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
) -> Result<(String, Vec<String>, String)> {
    let scount = scount.unwrap_or(2);
    let mut rcount = rcount.unwrap_or(3);
    let sn = 0u128;

    #[cfg(not(test))]
    let temp: Option<bool> = None;
    #[cfg(test)]
    let temp: Option<bool> = Some(true);

    let salter = Salter::new_with_defaults(tier)?;
    let signers0 = salter.signers(
        Some(scount),
        None,
        Some(&sn.to_string()),
        code,
        transferable,
        None,
        temp,
    )?;
    let mut keys = vec![];
    for signer in &signers0 {
        keys.push(signer.verfer().qb64()?);
    }

    let mut ndigs = vec![];
    if let Some(next_keys) = next_keys {
        for key in next_keys {
            ndigs.push(key.to_string());
        }
        rcount = ndigs.len();
    } else {
        let signers1 = if transferable.unwrap_or(false) {
            if let Some(salt) = salt {
                let salter = Salter::new(tier, None, Some(salt), None, None, None)?;
                salter.signers(
                    Some(rcount),
                    None,
                    Some(&(sn + 1).to_string()),
                    code,
                    transferable,
                    None,
                    temp,
                )?
            } else {
                return err!(Error::Programmer);
            }
        } else {
            vec![]
        };
        for signer in &signers1 {
            ndigs.push(Diger::new_with_ser(&signer.verfer().qb64b()?, None)?.qb64()?);
        }
    }

    // println!("{:?}", signers1.iter().map(|signer| signer.verfer().qb64().unwrap()).collect::<Vec<String>>());

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

    let mut privates = vec![];
    for signer in &signers0 {
        privates.push(signer.qb64()?);
    }

    let mut sigers = vec![];
    for (index, signer) in signers0.iter().enumerate() {
        let siger = signer.sign_indexed(&serder.raw(), false, index as u32, None)?;
        sigers.push(siger);
    }

    let endorsement = endorsement::endorse_serder(Some(&sigers), None, None, None)?;
    let event = message::messagize_serder(&serder, &endorsement, Some(true))?;

    Ok((serder.pre()?, privates, event))
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
) -> Result<(String, Vec<Vec<String>>, String)> {
    let salter = Salter::new_with_defaults(tier)?;

    #[cfg(not(test))]
    let temp: Option<bool> = None;
    #[cfg(test)]
    let temp: Option<bool> = Some(true);

    let signers0 = salter.signers(count, None, Some("0"), code, transferable, None, temp)?;
    let mut keys = vec![];
    for signer in &signers0 {
        keys.push(signer.verfer().qb64()?);
    }

    let signers1 = if transferable.unwrap_or(false) {
        salter.signers(ncount, None, Some("1"), ncode, transferable, None, temp)?
    } else {
        vec![]
    };
    let mut ndigs = vec![];
    for signer in &signers1 {
        ndigs.push(Diger::new_with_ser(&signer.verfer().qb64b()?, None)?.qb64()?);
    }

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

    let mut result = vec![];

    for signers in &[signers0.clone(), signers1] {
        let mut privates = vec![];
        for signer in signers {
            privates.push(signer.qb64()?);
        }
        result.push(privates);
    }

    let mut sigers = vec![];
    for (index, signer) in signers0.iter().enumerate() {
        let siger = signer.sign_indexed(&serder.raw(), false, index as u32, None)?;
        sigers.push(siger);
    }

    let endorsement = endorsement::endorse_serder(Some(&sigers), None, None, None)?;
    let event = message::messagize_serder(&serder, &endorsement, Some(true))?;

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
) -> Result<(String, usize, Vec<String>, String)> {
    let scount = scount.unwrap_or(2);
    let mut rcount = rcount.unwrap_or(3);
    let mut ccount = rcount;

    #[cfg(not(test))]
    let temp: Option<bool> = None;
    #[cfg(test)]
    let temp: Option<bool> = Some(true);

    let salter = Salter::new_with_defaults(tier)?;
    let mut ssigners = salter.signers(
        Some(scount),
        None,
        Some(&key_sn.to_string()),
        code,
        Some(true),
        None,
        temp,
    )?;

    let mut keys = vec![];
    let (public_keys, ndigs, signers) = if let Some(salt) = salt {
        if current_rotation_keys.is_some() || next_keys.is_some() || next_sith.is_some() {
            return err!(Error::Value);
        }

        let next_salt = if let Some(next_salt) = next_salt {
            next_salt
        } else {
            return err!(Error::Value);
        };

        let salter = Salter::new(tier, None, Some(salt), None, None, None)?;
        let mut signers = salter.signers(
            Some(rcount),
            None,
            Some(&key_sn.to_string()),
            code,
            Some(true),
            None,
            temp,
        )?;
        let salter = Salter::new(tier, None, Some(next_salt), None, None, None)?;
        let nsigners = salter.signers(
            Some(rcount),
            None,
            Some(&(key_sn + 1).to_string()),
            code,
            Some(true),
            None,
            temp,
        )?;

        signers.append(&mut ssigners);

        let mut public_keys = vec![];
        for signer in &signers {
            keys.push(signer.qb64()?);
            public_keys.push(signer.verfer().qb64()?);
        }

        let mut ndigs = vec![];
        for nsigner in &nsigners {
            ndigs.push(Diger::new_with_ser(&nsigner.verfer().qb64b()?, None)?.qb64()?);
        }

        (public_keys, ndigs, signers)
    } else {
        if current_rotation_keys.is_none() || next_keys.is_none() || next_sith.is_none() {
            return err!(Error::Value);
        }
        if salt.is_some() || next_salt.is_some() {
            return err!(Error::Value);
        }

        let mut public_keys: Vec<String> =
            current_rotation_keys.unwrap().iter().map(|s| s.to_string()).collect();
        let next_keys: Vec<String> = next_keys.unwrap().iter().map(|s| s.to_string()).collect();

        ccount = public_keys.len();
        rcount = next_keys.len();

        for signer in &ssigners {
            keys.push(signer.qb64()?);
            public_keys.push(signer.verfer().qb64()?);
        }

        (public_keys, next_keys, ssigners)
    };

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
        return Ok((serder.said()?, ccount, keys, String::from_utf8(serder.raw())?));
    }

    let mut sigers = vec![];
    for (index, signer) in signers.iter().enumerate() {
        let siger = signer.sign_indexed(&serder.raw(), false, index as u32, None)?;
        sigers.push(siger);
    }

    let endorsement = endorsement::endorse_serder(Some(&sigers), None, None, None)?;
    let event = message::messagize_serder(&serder, &endorsement, Some(true))?;

    Ok((serder.said()?, ccount, keys, event))
}

#[allow(clippy::too_many_arguments)]
pub fn rotate(
    pre: &str,
    key_set: &KeySet,
    dig: &str,
    sn: u128,
    sith: Option<&Value>,
    ncode: Option<&str>,
    ncount: Option<usize>,
    nsith: Option<&Value>,
    wcount: Option<usize>,
    tier: Option<&str>,
) -> Result<(String, Vec<String>, String)> {
    let salter = Salter::new_with_defaults(tier)?;
    // this can give us the same witnesses as inception
    // let fixed_salter = Salter::new_with_raw(b"0000000000000000", None, Some(Tierage::low))?;

    #[cfg(not(test))]
    let temp: Option<bool> = None;
    #[cfg(test)]
    let temp: Option<bool> = Some(true);

    let nsigners =
        salter.signers(ncount, None, Some(&sn.to_string()), ncode, Some(true), None, temp)?;

    let mut result = vec![];
    let mut digers = vec![];
    for nsigner in &nsigners {
        result.push(nsigner.qb64()?);
        digers.push(Diger::new_with_ser(&nsigner.verfer().qb64b()?, None)?);
    }

    let mut ndigs = vec![];
    for diger in &digers {
        ndigs.push(diger.qb64()?);
    }

    let mut public_keys = vec![];
    for verfer in &key_set.verfers()? {
        public_keys.push(verfer.qb64()?);
    }

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

    let sigers = key_set.sign(&serder.raw(), Some(&digers))?;
    let endorsement = endorsement::endorse_serder(Some(&sigers), None, None, None)?;
    let event = message::messagize_serder(&serder, &endorsement, Some(true))?;

    Ok((serder.said()?, result, event))
}

pub(crate) fn interact(
    key_set: &KeySet, // current signing keys
    pre: &str,        // identifier prefix
    dig: &str,        // previous event said
    sn: u128,         // sequence number
    data: &Value,     // seals
) -> Result<(String, String)> {
    let serder = event::interact(pre, dig, Some(sn), Some(data), None, None)?;
    let sigers = key_set.sign(&serder.raw(), None)?;
    let endorsement = endorsement::endorse_serder(Some(&sigers), None, None, None)?;
    let event = message::messagize_serder(&serder, &endorsement, Some(true))?;

    Ok((serder.said()?, event))
}
