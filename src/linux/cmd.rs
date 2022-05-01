use neli::{consts::genl::Cmd, impl_var};

// https://github.com/WireGuard/WireGuard/blob/62b335b56cc99312ccedfa571500fbef3756a623/src/uapi/wireguard.h#L137
impl_var!(
    pub WgCmd, u8,
    GetDevice => 0,
    SetDevice => 1
);

impl Cmd for WgCmd {}
