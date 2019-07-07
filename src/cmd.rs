use buffering::copy::{StreamReadBuffer, StreamWriteBuffer};
use neli::consts::Cmd;
use neli::err::{DeError, SerError};
use neli::Nl;
use neli::{impl_var, impl_var_base, impl_var_trait};
use std::mem;

// https://github.com/WireGuard/WireGuard/blob/62b335b56cc99312ccedfa571500fbef3756a623/src/uapi/wireguard.h#L137
impl_var_trait!(
    WgCmd, u8, Cmd,
    GetDevice => 0,
    SetDevice => 1
);
