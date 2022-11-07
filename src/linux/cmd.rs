use neli::consts::genl::Cmd;
use neli::neli_enum;

// https://github.com/WireGuard/WireGuard/blob/62b335b56cc99312ccedfa571500fbef3756a623/src/uapi/wireguard.h#L137
#[neli_enum(serialized_type = "u8")]
pub enum WgCmd {
    GetDevice = 0,
    SetDevice = 1,
}

impl Cmd for WgCmd {}
