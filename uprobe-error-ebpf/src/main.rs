#![no_std]
#![no_main]

use aya_bpf::{
    macros::uprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

#[uprobe(name="uprobe_error")]
pub fn uprobe_error(ctx: ProbeContext) -> u32 {
    match try_uprobe_error(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_uprobe_error(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function SSL_read called by liboringssl.so");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
