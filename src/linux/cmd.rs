use neli::consts::Cmd;
use neli::{impl_var, impl_var_base, impl_var_trait};

// https://github.com/WireGuard/WireGuard/blob/62b335b56cc99312ccedfa571500fbef3756a623/src/uapi/wireguard.h#L137
impl_var_trait!(
    WgCmd, u8, Cmd,
    GetDevice => 0,
    SetDevice => 1
);
