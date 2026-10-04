//! `net policy` — is the packet policy in force?
//!
//! The packet layers of PNP are executed by NTFE, the kernel's filtering
//! engine, which re-reads `Machine\System\Network` a moment after every
//! change. A registry write that has returned is delivered, not enforced;
//! this asks the engine which it is. The answer is two counters in the
//! engine's status: every change it has noted (counted before the write
//! that made it returns) and the count its last finished re-walk started
//! from. A writer is in force once the second reaches what the first read
//! after its write.
//!
//! The status ioctl of `/dev/peios-ntfe` is the whole interface used here;
//! the layout is `struct peios_ntfe_status` (pkm/uapi/pkm/ntfe.h), read as
//! the array of u64 it is.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::process::ExitCode;
use std::time::{Duration, Instant};

const DEVICE: &str = "/dev/peios-ntfe";
const ABI: u64 = 5;
const WORDS: usize = 46;
/// _IOR('N', 1, struct peios_ntfe_status)
const IOC_STATUS: libc::c_ulong =
    (2 << 30) | ((WORDS as libc::c_ulong * 8) << 16) | ((b'N' as libc::c_ulong) << 8) | 1;

const ABI_WORD: usize = 0;
const GENERATION: usize = 1;
const ENFORCING: usize = 2;
const LAST_INGEST_ERROR: usize = 21;
const CHANGES_NOTED: usize = 42;
const CHANGES_WALKED: usize = 43;
const CONTEXTS: usize = 44;

struct Engine(File);

impl Engine {
    fn open() -> Result<Self, String> {
        File::open(DEVICE)
            .map(Self)
            .map_err(|e| format!("cannot open {DEVICE}: {e}"))
    }

    fn status(&self) -> Result<[u64; WORDS], String> {
        let mut words = [0u64; WORDS];
        // SAFETY: the ioctl writes exactly the WORDS * 8 bytes its number
        // encodes into the buffer, which is that size and outlives the call.
        let rc = unsafe { libc::ioctl(self.0.as_raw_fd(), IOC_STATUS, words.as_mut_ptr()) };
        if rc != 0 {
            return Err(format!(
                "{DEVICE}: status: {}",
                std::io::Error::last_os_error()
            ));
        }
        if words[ABI_WORD] != ABI {
            return Err(format!(
                "{DEVICE}: engine speaks ABI {}, this net speaks {ABI}",
                words[ABI_WORD]
            ));
        }
        Ok(words)
    }
}

fn fail(e: &str) -> ExitCode {
    eprintln!("net: {e}");
    ExitCode::FAILURE
}

pub fn show() -> ExitCode {
    let s = match Engine::open().and_then(|e| e.status()) {
        Ok(s) => s,
        Err(e) => return fail(&e),
    };
    let pending = s[CHANGES_NOTED].saturating_sub(s[CHANGES_WALKED]);
    println!(
        "engine      {}",
        if s[ENFORCING] != 0 {
            "enforcing"
        } else {
            "not enforcing (no policy published)"
        }
    );
    println!("generation  {}", s[GENERATION]);
    if pending == 0 {
        println!("changes     in force");
    } else {
        println!("changes     {pending} not yet walked");
    }
    if s[LAST_INGEST_ERROR] != 0 {
        println!(
            "last walk   REFUSED (errno {}): the previous generation stands",
            s[LAST_INGEST_ERROR]
        );
    }
    println!("contexts    {}", s[CONTEXTS]);
    ExitCode::SUCCESS
}

/// Waits until every change the engine had noted when this was called has
/// been walked. Success means the walk published (or found nothing to
/// change); a refused walk is a failure, because what was written is not
/// what is enforced.
pub fn wait(timeout: Duration) -> ExitCode {
    let engine = match Engine::open() {
        Ok(e) => e,
        Err(e) => return fail(&e),
    };
    let target = match engine.status() {
        Ok(s) => s[CHANGES_NOTED],
        Err(e) => return fail(&e),
    };
    let deadline = Instant::now() + timeout;
    loop {
        let s = match engine.status() {
            Ok(s) => s,
            Err(e) => return fail(&e),
        };
        if s[CHANGES_WALKED] >= target {
            if s[LAST_INGEST_ERROR] != 0 {
                return fail(&format!(
                    "the policy was refused (errno {}); generation {} stands",
                    s[LAST_INGEST_ERROR], s[GENERATION]
                ));
            }
            return ExitCode::SUCCESS;
        }
        if Instant::now() >= deadline {
            return fail("timed out waiting for the policy to be in force");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
