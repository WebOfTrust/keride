use crate::{
    cesr::core::{matter::Matter, seqner::Seqner},
    error::Result,
};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Seal {
    pub i: String,
    pub s: String,
    pub d: String,
    pub last: bool,
}

impl Seal {
    pub fn new(i: &str, s: &str, d: &str, last: Option<bool>) -> Self {
        let last = last.unwrap_or(false);

        Self { i: i.to_string(), s: s.to_string(), d: d.to_string(), last }
    }

    pub fn i(&self) -> String {
        self.i.clone()
    }

    pub fn s(&self) -> Result<String> {
        Seqner::new_with_snh(&self.s)?.qb64()
    }

    pub fn d(&self) -> String {
        self.d.clone()
    }
}
