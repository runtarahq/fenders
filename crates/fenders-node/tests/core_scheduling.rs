//! Two processes that each ask for a core of their own hold different
//! core-scheduling cookies, and a child holds its parent's. Says so and
//! passes where the host has no sibling hardware threads to keep apart.

/// A child that asks for its own cookie and then waits to be looked at.
fn alone() -> libc::pid_t {
    let mut ends = [0; 2];
    assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        // Only system calls from here: this is a forked test process.
        let made = unsafe { libc::prctl(62, 1, 0, 1, 0) } == 0;
        unsafe {
            libc::write(ends[1], [made as u8].as_ptr().cast(), 1);
            loop {
                libc::pause();
            }
        }
    }
    let mut made = [0u8];
    assert_eq!(
        unsafe { libc::read(ends[0], made.as_mut_ptr().cast(), 1) },
        1
    );
    unsafe {
        libc::close(ends[0]);
        libc::close(ends[1]);
    }
    assert_eq!(made[0], 1);
    pid
}

#[test]
fn each_run_has_a_core_of_its_own() {
    let smt = std::fs::read_to_string("/sys/devices/system/cpu/smt/active")
        .is_ok_and(|active| active.trim() == "1");
    // In a thread of its own: the cookie is this test's, not the harness's.
    let made = std::thread::spawn(|| fenders_node::confinement::core_alone().unwrap())
        .join()
        .unwrap();
    if !smt || !made {
        println!("skipped: no sibling hardware threads, or a kernel without core scheduling");
        return;
    }
    let (one, other) = (alone(), alone());
    let cookies = [one, other].map(|pid| fenders_node::confinement::core_cookie(pid).unwrap());
    for pid in [one, other] {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
    }
    assert!(cookies[0] != 0 && cookies[1] != 0 && cookies[0] != cookies[1]);
}
