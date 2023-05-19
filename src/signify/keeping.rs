use anyhow::Ok;

use crate::cesr::common::Tierage;
use crate::cesr::Salter;

use crate::cesr::core::matter::tables as matter;
use crate::error::Result;
use crate::signing::Signer;

pub const STEM: &str = "signify:aid";

// pub trait Keeper: Default {
//     fn new(
//         salter: Salter,
//         pidx: u32,
//         kidx: u32,
//         tier: &str,
//         transferable: bool,
//         stem: Option<&str>,
//         code: Option<&str>,
//         count: u32,
//         icodes: Vec<&str>,
//         ncode: Option<&str>,
//         ncount: u32,
//         ncodes: Vec<&str>,
//         dcode: Option<&str>,
//     ) -> Result<Self> {
//         Ok(())
//     }
// }

/// Creating a key pair based on algorithm.
pub trait Creator: Default {
    #[allow(clippy::too_many_arguments)]
    fn create(
        &self,
        codes: Option<Vec<&str>>,
        count: Option<u16>,
        code: Option<&str>,
        pidx: Option<u16>,
        ridx: Option<u16>,
        kidx: Option<u16>,
        stem: Option<&str>,
        transferable: bool,
        temp: bool,
    ) -> Vec<Signer>;
    fn salt(&self) -> String;
    fn stem(&self) -> String;
    fn tier(&self) -> String;
}

pub struct SaltyCreator {
    salt: String,
    stem: String,
    tier: String,
    salter: Salter,
}

impl SaltyCreator {
    pub fn new(
        salt: Option<&str>,
        stem: Option<&str>,
        tier: Option<&str>,
        salter: Option<Salter>,
    ) -> Result<Self> {
        let mut salty_creator = Self::default();

        if let Some(stm) = stem {
            salty_creator.stem = stm.to_string();
        }

        if let Some(s) = salter {
            salty_creator.salter = s;
        } else {
            salty_creator.salter = Salter::new(tier, None, None, None, salt, None).unwrap();
        }

        Ok(salty_creator)
    }

    fn set_salt(&mut self, salt: &str) {
        self.salt = salt.to_string();
    }

    fn set_stem(&mut self, stem: &str) {
        self.stem = stem.to_string();
    }

    fn set_tier(&mut self, tier: &str) {
        self.tier = tier.to_string();
    }
}

impl Default for SaltyCreator {
    fn default() -> Self {
        SaltyCreator {
            salt: "".to_string(),
            stem: "".to_string(),
            tier: "".to_string(),
            salter: Salter::new(Some(Tierage::low), None, None, None, Some(""), None).unwrap(),
        }
    }
}

impl Creator for SaltyCreator {
    #[allow(clippy::too_many_arguments)]
    fn create(
        &self,
        codes: Option<Vec<&str>>,
        count: Option<u16>,
        code: Option<&str>,
        pidx: Option<u16>,
        ridx: Option<u16>,
        kidx: Option<u16>,
        stem: Option<&str>,
        transferable: bool,
        temp: bool,
    ) -> Vec<Signer> {
        let code = code.unwrap_or(matter::Codex::Ed25519_Seed);
        let count = count.unwrap_or(1);
        let mut codes = codes.unwrap_or(vec![]);
        let pidx = pidx.unwrap_or(0);
        let ridx = ridx.unwrap_or(0);
        let kidx = kidx.unwrap_or(0);
        // let stem = stem.unwrap_or_else(|| &format!("{}", &pidx));
        let ps = format!("{}", pidx.to_owned());
        let stem = if let Some(stem) = stem { Some(stem) } else { Some(ps.as_str()) }.unwrap();

        if codes.is_empty() {
            let mut cs = vec![];
            for _ in 0..count {
                cs.push(code);
            }
            codes = cs;
        }

        let mut signers = vec![];
        for (i, c) in codes.iter().enumerate() {
            let path = format!("{:?}{}{}", stem, &ridx, kidx + i as u16);
            signers.push(self.salter.signer(
                Some(c),
                Some(transferable),
                Some(&path),
                Some(&self.tier),
                Some(temp),
            ));
        }
        let v: Vec<Signer> = Vec::new();
        v
    }

    fn salt(&self) -> String {
        self.salt.clone()
    }

    fn stem(&self) -> String {
        self.stem.clone()
    }

    fn tier(&self) -> String {
        self.tier.clone()
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn convenience() {
        let foo = "sx";
        print!("{:?}", foo);
        let array: [&str; 3] = [foo; 3];
        print!("{:?}", array);
    }
}
