//! Node settings for the confined compiler and the largest accepted upload.
use super::*;
use fenders_node_protocol::model::MAX_UPLOAD_CEILING;

const MIB: u64 = 1024 * 1024;

/// The confined compile worker's ceilings. Defaults are the qualified values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompilerLimits {
    pub memory_mib: u64,
    pub cpu_percent: u64,
    pub cpu_seconds: u64,
    pub wall_seconds: u64,
}
impl Default for CompilerLimits {
    fn default() -> Self {
        Self {
            memory_mib: 1024,
            cpu_percent: 100,
            cpu_seconds: 45,
            wall_seconds: 60,
        }
    }
}
impl CompilerLimits {
    fn validate(&self) -> Result<()> {
        if !(256..=16_384).contains(&self.memory_mib)
            || !(10..=800).contains(&self.cpu_percent)
            || !(5..=3600).contains(&self.cpu_seconds)
            || !(5..=3600).contains(&self.wall_seconds)
        {
            return Err(Error::invalid(
                "compiler limits must be 256–16384 MiB, 10–800% CPU and 5–3600 s",
            ));
        }
        Ok(())
    }
    /// Compile threads: one per whole CPU the ceiling grants, so a raised
    /// ceiling shortens a compile instead of idling.
    pub fn threads(&self) -> u64 {
        self.cpu_percent.div_ceil(100)
    }
    /// The address-space ceiling leaves room for mappings the cgroup does not charge.
    pub fn address_space_mib(&self) -> u64 {
        self.memory_mib + 512
    }
    pub(super) fn apply(&self, cgroup: &Path) -> Result<()> {
        fs::write(
            cgroup.join("memory.max"),
            (self.memory_mib * MIB).to_string(),
        )?;
        fs::write(
            cgroup.join("cpu.max"),
            format!("{} 100000", self.cpu_percent * 1000),
        )?;
        Ok(())
    }
}
impl Node {
    pub fn with_compiler_limits(mut self, limits: CompilerLimits) -> Result<Self> {
        limits.validate()?;
        limits.apply(&self.compiler_cgroup)?;
        self.compiler_limits = limits;
        Ok(self)
    }
    pub fn with_max_upload_mib(mut self, mib: u64) -> Result<Self> {
        let bytes = usize::try_from(mib * MIB).map_err(|_| Error::internal())?;
        if mib == 0 || bytes > MAX_UPLOAD_CEILING {
            return Err(Error::invalid("upload cap must be 1–128 MiB"));
        }
        self.max_upload = bytes;
        Ok(self)
    }
    /// How much compiled code the node keeps (64 MiB to 1 TiB). Entries in
    /// use, or used within the hour, stay; a full cache refuses new uploads.
    pub fn with_artifact_cache_mib(mut self, mib: u64) -> Result<Self> {
        if !(64..=1_048_576).contains(&mib) {
            return Err(Error::invalid("artifact cache must be 64 MiB to 1 TiB"));
        }
        self.artifact_cache_bytes = mib * MIB;
        Ok(self)
    }
    /// How much the per-function compile cache keeps: 0 to turn it off, or
    /// 64 MiB to 1 TiB. Least recently used scopes go first.
    pub fn with_compile_cache_mib(mut self, mib: u64) -> Result<Self> {
        if mib != 0 && !(64..=1_048_576).contains(&mib) {
            return Err(Error::invalid(
                "compile cache must be 0, or 64 MiB to 1 TiB",
            ));
        }
        self.compile_cache_bytes = mib * MIB;
        Ok(self)
    }
    pub fn compiler_limits(&self) -> CompilerLimits {
        self.compiler_limits
    }
    pub fn max_upload(&self) -> usize {
        self.max_upload
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn limits_outside_their_ranges_are_refused() {
        assert!(CompilerLimits::default().validate().is_ok());
        for limits in [
            CompilerLimits {
                memory_mib: 128,
                ..Default::default()
            },
            CompilerLimits {
                cpu_percent: 900,
                ..Default::default()
            },
            CompilerLimits {
                cpu_seconds: 1,
                ..Default::default()
            },
            CompilerLimits {
                wall_seconds: 7200,
                ..Default::default()
            },
        ] {
            assert!(limits.validate().is_err(), "accepted {limits:?}");
        }
    }
    #[test]
    fn the_compiler_gets_a_thread_per_granted_cpu() {
        for (cpu_percent, threads) in [(10, 1), (100, 1), (150, 2), (400, 4), (800, 8)] {
            let limits = CompilerLimits {
                cpu_percent,
                ..Default::default()
            };
            assert_eq!(limits.threads(), threads, "{cpu_percent}%");
        }
    }
}
