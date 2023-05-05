pub trait Keeper: Default {
    const stem: &str = "signify:aid";

    fn new(
        salter: Salter,
        pidx: u32,
        kidx: u32,
        tier: Tierage,
        transferable: bool,
        stem: Option<&str>,
        code: Option<&str>,
        count: u32,
        icodes: Vec<&str>,
        ncode: Option<&str>,
        ncount: u32,
        ncodes: Vec<&str>,
        dcode: Option<&str>,
    ) -> Result<Self> {
    }
}
