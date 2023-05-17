use crate::error::{err, Error, Result};
use cesride::{
    common::{versify, Ids, Ilkage, Serialage, Version, CURRENT_VERSION},
    data::{dat, Value},
    matter, Matter, Number, Prefixer, Saider, Serder, Tholder,
};

use super::endorsement::Seal;

#[allow(clippy::too_many_arguments)]
pub(crate) fn incept(
    keys: &[String],           // current keys public qb64
    sith: Option<&Value>,      // current signing threshold
    ndigs: Option<&[String]>,  // next keys public digest qb64
    nsith: Option<&Value>,     // next signing threshold
    toad: Option<u128>,        // witness threshold number
    wits: Option<&[String]>,   // witness identifier prefixes qb64
    cnfg: Option<&[&str]>,     // configuration traits from traiter::Codex
    data: Option<&[Seal]>,     // seal dicts
    version: Option<&Version>, // protocol version
    kind: Option<&str>,        // serder serialization kind
    code: Option<&str>,        // serder code
    intive: Option<bool>,      // sith, nsith and toad are ints, not hex when numeric
    delpre: Option<&str>,      // delegator identifier prefix
) -> Result<Serder> {
    let version = version.unwrap_or(CURRENT_VERSION);
    let kind = kind.unwrap_or(Serialage::JSON);
    let intive = intive.unwrap_or(false);

    let vs = &versify(None, Some(version), Some(kind), Some(0))?;
    let ilk = if delpre.is_none() { Ilkage::icp } else { Ilkage::dip };
    let sner = Number::new_with_num(0)?;

    let sith = if let Some(sith) = sith {
        sith.clone()
    } else {
        let mut s: i64 = (keys.len() as i64 + 1) / 2;
        s = if s > 1 { s } else { 1 };
        dat!(s)
    };

    let tholder = Tholder::new_with_sith(&sith)?;
    if tholder.num()?.unwrap_or(1) < 1 {
        return err!(Error::Value);
    }
    if tholder.size() as usize > keys.len() {
        return err!(Error::Value);
    }

    let empty_string_vec: Vec<String> = vec![];
    let ndigs = ndigs.unwrap_or(&empty_string_vec);
    let nsith = if let Some(nsith) = nsith {
        nsith.clone()
    } else {
        let mut s: i64 = (ndigs.len() as i64 + 1) / 2;
        s = if s > 0 { s } else { 0 };
        dat!(s)
    };

    let ntholder = Tholder::new_with_sith(&nsith)?;
    if ntholder.size() as usize > ndigs.len() {
        return err!(Error::Value);
    }

    let wits = wits.unwrap_or(&[]);
    let mut unique = wits.to_vec();
    unique.sort_unstable();
    unique.dedup();
    if wits.len() != unique.len() {
        return err!(Error::Value);
    }

    let toader = if let Some(toad) = toad {
        Number::new_with_num(toad)?
    } else if wits.is_empty() {
        Number::new_with_num(0)?
    } else {
        let toad = ample(wits.len() as u128, None, None)?;
        Number::new_with_num(toad)?
    };

    if !wits.is_empty() {
        if toader.num()? < 1 || toader.num()? > wits.len() as u128 {
            return err!(Error::Value);
        }
    } else if toader.num()? != 0 {
        return err!(Error::Value);
    }

    let cnfg = cnfg.unwrap_or(&[]);
    let data: Vec<Value> = data.unwrap_or(&[]).iter().map(|seal| seal.value()).collect();

    let kt = if let Some(n) = tholder.num()? {
        if intive && n < u32::MAX {
            dat!(n)
        } else {
            tholder.sith()?
        }
    } else {
        tholder.sith()?
    };

    let nt = if let Some(n) = ntholder.num()? {
        if intive && n < u32::MAX {
            dat!(n)
        } else {
            ntholder.sith()?
        }
    } else {
        ntholder.sith()?
    };

    let toad = if intive && toader.num()? < u32::MAX as u128 {
        dat!(toader.num()? as i64)
    } else {
        dat!(&toader.numh()?)
    };

    let keys: Vec<Value> = keys.iter().map(|key| dat!(key)).collect();
    let ndigs: Vec<Value> = ndigs.iter().map(|dig| dat!(dig)).collect();
    let wits: Vec<Value> = wits.iter().map(|wit| dat!(wit)).collect();
    let cnfg: Vec<Value> = cnfg.iter().map(|cfg| dat!(*cfg)).collect();

    let mut ked = dat!({
        "v": vs,
        "t": ilk,
        "d": "",
        "i": "",
        "s": &sner.numh()?,
        "kt": kt,
        "k": keys.as_slice(),
        "nt": nt,
        "n": ndigs.as_slice(),
        "bt": toad,
        "b": wits.as_slice(),
        "c": cnfg.as_slice(),
        "a": data.as_slice(),
    });

    let code = if let Some(delpre) = delpre {
        let label = Ids::di;
        ked[label] = dat!(delpre);
        Some(code.unwrap_or(matter::Codex::Blake3_256))
    } else {
        code
    };

    let prefixer = if delpre.is_none() && code.is_none() && keys.len() == 1 {
        let prefixer = Prefixer::new_with_qb64(&keys[0].to_string()?)?;
        if prefixer.digestive() {
            return err!(Error::Value);
        }
        prefixer
    } else {
        let prefixer = Prefixer::new_with_ked(&ked, None, code)?;
        if delpre.is_some() && !prefixer.digestive() {
            return err!(Error::Value);
        }
        prefixer
    };

    let label = Ids::i;
    ked[label] = dat!(&prefixer.qb64()?);
    let ked = if prefixer.digestive() {
        let label = Ids::d;
        ked[label] = dat!(&prefixer.qb64()?);
        ked
    } else {
        let (_, ked) = Saider::saidify(&ked, None, None, None, None)?;
        ked
    };

    Serder::new_with_ked(&ked, None, None)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn rotate(
    pre: &str,                // prefix of identifier
    keys: &[String],          // current signing keys
    dig: &str,                // said of previous estabishment event
    ilk: Option<&str>,        // must be 'rot' or 'drt'
    sn: u128,                 // sequence number
    sith: Option<&Value>,     // current signing sith (must match previous event's next sith?)
    ndigs: Option<&[String]>, // next keys' digests
    nsith: Option<&Value>,    // next signing sith
    toad: Option<u128>,       // witness threshold number
    wits: Option<&[String]>,  // witness prefixes
    cuts: Option<&[String]>,  // witnesses prefixes to cut
    adds: Option<&[String]>,  // witnesses prefixes to add
    data: Option<&[Seal]>,    // seals
    version: Option<&Version>,
    kind: Option<&str>,
    intive: Option<bool>,
) -> Result<Serder> {
    let ilk = ilk.unwrap_or(Ilkage::rot);
    let version = version.unwrap_or(CURRENT_VERSION);
    let kind = kind.unwrap_or(Serialage::JSON);
    let intive = intive.unwrap_or(false);

    let vs = versify(None, Some(version), Some(kind), None)?;
    if ![Ilkage::rot, Ilkage::drt].contains(&ilk) {
        return err!(Error::Value);
    }

    let sner = Number::new_with_num(sn)?;
    if sner.num()? < 1 {
        return err!(Error::Value);
    }

    let sith = if let Some(sith) = sith {
        sith.clone()
    } else {
        let mut s: i64 = (keys.len() as i64 + 1) / 2;
        s = if s > 1 { s } else { 1 };
        dat!(s)
    };

    let tholder = Tholder::new_with_sith(&sith)?;
    let num = tholder.num()?;
    if let Some(num) = num {
        if num < 1 {
            return err!(Error::Value);
        }
    }
    if tholder.size() as usize > keys.len() {
        return err!(Error::Value);
    }

    let empty_string_vec: Vec<String> = vec![];
    let ndigs = ndigs.unwrap_or(&empty_string_vec);
    let nsith = if let Some(nsith) = nsith {
        nsith.clone()
    } else {
        let mut s: i64 = (ndigs.len() as i64 + 1) / 2;
        s = if s > 0 { s } else { 0 };
        dat!(s)
    };

    let ntholder = Tholder::new_with_sith(&nsith)?;
    let num = ntholder.num()?;
    if let Some(num) = num {
        if num < 1 {
            return err!(Error::Value);
        }
    }
    if ntholder.size() as usize > ndigs.len() {
        return err!(Error::Value);
    }

    let wits = wits.unwrap_or(&empty_string_vec);
    let mut unique = wits.to_vec();
    unique.sort_unstable();
    unique.dedup();
    if wits.len() != unique.len() {
        return err!(Error::Value);
    }

    let cuts = cuts.unwrap_or(&empty_string_vec);
    let mut unique = cuts.to_vec();
    unique.sort_unstable();
    unique.dedup();
    if cuts.len() != unique.len() {
        return err!(Error::Value);
    }

    let adds = adds.unwrap_or(&empty_string_vec);
    let mut unique = adds.to_vec();
    unique.sort_unstable();
    unique.dedup();
    if adds.len() != unique.len() {
        return err!(Error::Value);
    }

    for cut in cuts {
        if adds.contains(cut) {
            return err!(Error::Value);
        }
    }

    for wit in wits {
        if adds.contains(wit) {
            return err!(Error::Value);
        }
    }

    let mut newits = wits.to_vec();
    let mut to_remove = vec![0usize; 0];
    for (index, wit) in newits.iter().enumerate() {
        if cuts.contains(wit) {
            to_remove.push(index);
        }
    }
    to_remove.iter().for_each(|index| {
        newits.remove(*index);
    });

    for add in adds {
        newits.push(add.clone());
    }

    let toader = if let Some(toad) = toad {
        Number::new_with_num(toad)?
    } else {
        let toad = if newits.is_empty() { 0 } else { ample(newits.len() as u128, None, None)? };

        Number::new_with_num(toad)?
    };

    if newits.is_empty() {
        if toader.num()? != 0 {
            return err!(Error::Value);
        }
    } else if toader.num()? < 1 || toader.num()? > newits.len() as u128 {
        return err!(Error::Value);
    }

    let data: Vec<Value> = data.unwrap_or(&[]).iter().map(|seal| seal.value()).collect();

    let kt = if let Some(n) = tholder.num()? {
        if intive && n < u32::MAX {
            dat!(n)
        } else {
            tholder.sith()?
        }
    } else {
        tholder.sith()?
    };

    let nt = if let Some(n) = ntholder.num()? {
        if intive && n < u32::MAX {
            dat!(n)
        } else {
            ntholder.sith()?
        }
    } else {
        ntholder.sith()?
    };

    let toad = if intive && toader.num()? < u32::MAX as u128 {
        dat!(toader.num()? as i64)
    } else {
        dat!(&toader.numh()?)
    };

    let keys: Vec<Value> = keys.iter().map(|key| dat!(key)).collect();
    let ndigs: Vec<Value> = ndigs.iter().map(|dig| dat!(dig)).collect();
    let cuts: Vec<Value> = cuts.iter().map(|wit| dat!(wit)).collect();
    let adds: Vec<Value> = adds.iter().map(|wit| dat!(wit)).collect();

    let ked = dat!({
        "v": &vs,
        "t": ilk,
        "d": "",
        "i": pre,
        "s": &sner.numh()?,
        "p": dig,
        "kt": kt,
        "k": keys.as_slice(),
        "nt": nt,
        "n": ndigs.as_slice(),
        "bt": toad,
        "br": cuts.as_slice(),
        "ba": adds.as_slice(),
        "a": data.as_slice()
    });
    let (_, ked) = Saider::saidify(&ked, None, None, None, None)?;

    Serder::new_with_ked(&ked, None, None)
}

pub(crate) fn interact(
    pre: &str,
    dig: &str,
    sn: Option<u128>,
    data: Option<&Value>,
    version: Option<&Version>,
    kind: Option<&str>,
) -> Result<Serder> {
    let sn = sn.unwrap_or(1);
    let version = version.unwrap_or(CURRENT_VERSION);
    let kind = kind.unwrap_or(Serialage::JSON);

    let vs = versify(None, Some(version), Some(kind), Some(0))?;
    let ilk = Ilkage::ixn;
    let sner = Number::new_with_num(sn)?;

    if sner.num()? < 1 {
        return err!(Error::Value);
    }

    let empty_list = dat!([]);
    let data = data.unwrap_or(&empty_list);

    let ked = dat!({
        "v": &vs,
        "t": ilk,
        "d": "",
        "i": pre,
        "s": &sner.numh()?,
        "p": dig,
        "a": data.clone()
    });

    let (_, ked) = Saider::saidify(&ked, None, None, None, None)?;

    Serder::new_with_ked(&ked, None, None)
}

fn ample(n: u128, f: Option<u128>, weak: Option<bool>) -> Result<u128> {
    let weak = weak.unwrap_or(true);
    let n = if n > 0 { n } else { 0 };
    if let Some(f) = f {
        let f = if f > 0 { f } else { 0 };
        let m1 = (n + f + 2) / 2;
        let m2 = if n - f > 0 { n - f } else { 0 };

        if m2 < m1 && n > 0 {
            return err!(Error::Value);
        }

        if weak {
            match [n, m1, m2].iter().min() {
                Some(x) => Ok(*x),
                None => unreachable!(),
            }
        } else {
            Ok(std::cmp::min(n, std::cmp::max(m1, m2)))
        }
    } else {
        let f1 = std::cmp::max(1, std::cmp::max(0, n - 1) / 3);
        let f2 = std::cmp::max(1, (std::cmp::max(0, n - 1) + 2) / 3);

        if weak {
            match [n, (n + f1 + 3) / 2, (n + f2 + 3) / 2].iter().min() {
                Some(x) => Ok(*x),
                None => unreachable!(),
            }
        } else {
            match [0, n - f1, (n + f1 + 3) / 2].iter().max() {
                Some(x) => Ok(std::cmp::min(n, *x)),
                None => unreachable!(),
            }
        }
    }
}
