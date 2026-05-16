import os

from monitor.security import (
    SecurityConfig,
    check_dangerous_env,
    classify_argv_mismatch,
    classify_exe_deleted_or_memfd,
    classify_exe_path,
    classify_kthread_impersonation,
    compute_flags,
    config_from_toml,
    invalidate_env_cache,
    paranoid_scan,
)


def test_suspicious_tmp_path_fires():
    cfg = SecurityConfig()
    f = classify_exe_path("/tmp/dropper", cfg)
    assert f is not None
    assert f["id"] == "exe_suspicious_path"
    assert f["severity"] == "high"
    assert "/tmp/dropper" in f["evidence"]


def test_flatpak_is_allowlisted():
    cfg = SecurityConfig()
    # Real flatpak paths under tmpfs.
    assert classify_exe_path("/var/lib/flatpak/app/foo/x", cfg) is None
    assert classify_exe_path("/tmp/flatpak-runtime-xyz/bin/app", cfg) is None
    # AppImages mount under /tmp/.mount_*
    assert classify_exe_path("/tmp/.mount_FooAppImage/AppRun", cfg) is None


def test_run_user_without_flatpak_fires():
    cfg = SecurityConfig()
    f = classify_exe_path("/run/user/1000/.cache/evil", cfg)
    assert f and f["id"] == "exe_suspicious_path"


def test_system_path_does_not_fire():
    cfg = SecurityConfig()
    assert classify_exe_path("/usr/bin/python3", cfg) is None


def test_deleted_exe_fires():
    f = classify_exe_deleted_or_memfd("/tmp/x (deleted)")
    assert f and f["id"] == "exe_deleted"


def test_memfd_exe_fires():
    f = classify_exe_deleted_or_memfd("/memfd:cache (deleted)")
    assert f and f["id"] == "exe_memfd"


def test_normal_exe_no_deleted_memfd_flag():
    assert classify_exe_deleted_or_memfd("/usr/bin/bash") is None


def test_kthread_impersonation_real_kthread_clean():
    # Real kworker: comm in brackets, ppid 2, no exe link.
    assert classify_kthread_impersonation("[kworker/0:1]", 2, None) is None


def test_kthread_impersonation_with_exe_link():
    # Userspace process pretending to be a kernel thread.
    f = classify_kthread_impersonation("[kworker]", 1000, "/tmp/evil")
    assert f and f["id"] == "kthread_impersonation"


def test_kthread_impersonation_with_wrong_ppid():
    # comm looks kthread-y, ppid is not 2/0 — suspicious even without exe.
    f = classify_kthread_impersonation("[kworker]", 1, None)
    assert f and f["id"] == "kthread_impersonation"


def test_normal_process_not_kthread():
    assert classify_kthread_impersonation("bash", 1, "/bin/bash") is None


def test_compute_flags_self_clean():
    # The test process lives under /usr/bin or /home — should be clean.
    flags = compute_flags(os.getpid(), "python3", os.getppid(), SecurityConfig())
    # No flags should fire on the test runner.
    assert flags == [] or all(f["id"] != "exe_suspicious_path" for f in flags)


def test_config_from_toml_overrides_defaults():
    cfg = config_from_toml(
        {
            "suspicious_prefixes": ["/opt/badspot/"],
            "allowlist_substrings": ["mybuild"],
        }
    )
    assert cfg.suspicious_prefixes == ("/opt/badspot/",)
    assert cfg.allowlist_substrings == ("mybuild",)
    # Defaults no longer apply.
    assert classify_exe_path("/tmp/foo", cfg) is None
    assert classify_exe_path("/opt/badspot/foo", cfg) is not None


def test_config_from_toml_empty_uses_defaults():
    cfg = config_from_toml({})
    assert "/tmp/" in cfg.suspicious_prefixes


# ─── B5 argv[0] mismatch ──────────────────────────────────────────────────


def test_argv_mismatch_clean_match():
    cfg = SecurityConfig()
    assert classify_argv_mismatch(["/usr/bin/bash"], "/usr/bin/bash", cfg) is None


def test_argv_mismatch_login_shell_dash_prefix():
    cfg = SecurityConfig()
    # Login shells set argv[0]="-bash"; basename strip should match "bash".
    assert classify_argv_mismatch(["-bash"], "/usr/bin/bash", cfg) is None


def test_argv_mismatch_python_with_script():
    cfg = SecurityConfig()
    # Python entrypoint scripts often re-set argv[0] to the script path.
    # The interpreter allowlist should cover this.
    assert (
        classify_argv_mismatch(
            ["/usr/local/bin/uvicorn", "app:main"], "/usr/bin/python3.12", cfg
        )
        is None
    )


def test_argv_mismatch_classic_masquerade():
    cfg = SecurityConfig()
    f = classify_argv_mismatch(["/usr/sbin/sshd"], "/var/lib/something/x", cfg)
    assert f and f["id"] == "argv_exe_mismatch"


def test_argv_mismatch_suppressed_when_b1_fires():
    cfg = SecurityConfig()
    # exe is in /tmp → B1 territory; B5 stays quiet to avoid double-flag.
    assert classify_argv_mismatch(["/usr/sbin/sshd"], "/tmp/evil", cfg) is None


def test_argv_mismatch_busybox_allowlist():
    cfg = SecurityConfig()
    # busybox legitimately runs as /bin/ls etc.
    assert classify_argv_mismatch(["/bin/ls"], "/bin/busybox", cfg) is None


def test_argv_mismatch_string_cmdline_accepted():
    cfg = SecurityConfig()
    # scanner stores cmd as a space-joined string.
    f = classify_argv_mismatch("/usr/sbin/sshd -D", "/tmp/x", cfg)
    # /tmp/x suppresses by B1 logic, no flag.
    assert f is None
    f = classify_argv_mismatch("/usr/sbin/sshd -D", "/var/lib/y", cfg)
    assert f and f["id"] == "argv_exe_mismatch"


def test_argv_mismatch_empty_argv0_skipped():
    cfg = SecurityConfig()
    assert classify_argv_mismatch([], "/usr/bin/bash", cfg) is None
    assert classify_argv_mismatch([""], "/usr/bin/bash", cfg) is None


def test_argv_mismatch_proc_self_exe_chromium_pattern():
    cfg = SecurityConfig()
    # VS Code / Electron / Chromium utility procs re-exec via /proc/self/exe.
    assert (
        classify_argv_mismatch(
            ["/proc/self/exe", "--type=utility"], "/usr/share/code/code", cfg
        )
        is None
    )
    assert (
        classify_argv_mismatch(
            ["/proc/3087/exe", "--type=renderer"], "/usr/share/code/code", cfg
        )
        is None
    )


def test_argv_mismatch_comm_match_for_versioned_exe():
    cfg = SecurityConfig()
    # Claude installs binaries under ~/.local/share/claude/versions/2.1.143.
    # Basename is "2.1.143" — strips to "" — but comm="claude" matches argv[0].
    assert (
        classify_argv_mismatch(
            ["/home/x/.local/share/claude/bin/claude"],
            "/home/x/.local/share/claude/versions/2.1.143",
            cfg,
            comm="claude",
        )
        is None
    )
    # Without comm passed, it would still flag — that's expected, the comm
    # rescue is opt-in by the caller (the scanner always supplies it).
    f = classify_argv_mismatch(
        ["/home/x/.local/share/claude/bin/claude"],
        "/home/x/.local/share/claude/versions/2.1.143",
        cfg,
    )
    assert f and f["id"] == "argv_exe_mismatch"


def test_dangerous_env_suppressed_under_snap():
    cfg = SecurityConfig()
    # Pre-populate cache; suppression check runs before the cache lookup.
    cfg._env_cache[(99, 0.0)] = ["LD_PRELOAD"]
    assert (
        check_dangerous_env(99, 0.0, cfg, exe_link="/snap/firefox/8106/usr/lib/firefox/firefox")
        is None
    )
    # Without the snap path it still fires.
    assert check_dangerous_env(99, 0.0, cfg, exe_link="/usr/bin/somebin") is not None


# ─── B3 dangerous env (cached) ────────────────────────────────────────────


def test_dangerous_env_cache_hit_uses_stored_result(tmp_path, monkeypatch):
    cfg = SecurityConfig()
    # Pre-populate the cache so the actual /proc isn't touched.
    cfg._env_cache[(12345, 100.0)] = ["LD_PRELOAD"]
    f = check_dangerous_env(12345, 100.0, cfg)
    assert f and f["id"] == "dangerous_env"
    assert "LD_PRELOAD" in f["evidence"]


def test_dangerous_env_cache_empty_returns_none():
    cfg = SecurityConfig()
    cfg._env_cache[(12345, 100.0)] = []
    assert check_dangerous_env(12345, 100.0, cfg) is None


def test_invalidate_env_cache_drops_pid_entries():
    cfg = SecurityConfig()
    cfg._env_cache[(1, 100.0)] = ["LD_PRELOAD"]
    cfg._env_cache[(1, 200.0)] = []
    cfg._env_cache[(2, 100.0)] = []
    invalidate_env_cache(cfg, 1)
    assert (1, 100.0) not in cfg._env_cache
    assert (1, 200.0) not in cfg._env_cache
    assert (2, 100.0) in cfg._env_cache


def test_dangerous_env_reads_self_environ(monkeypatch):
    """End-to-end: real /proc/<pid>/environ scan against the test runner.
    Test runner doesn't have LD_PRELOAD set, so no flag should fire.
    """
    cfg = SecurityConfig()
    # First call populates the cache by reading real environ.
    f = check_dangerous_env(os.getpid(), 0.0, cfg)
    # Result depends on whether the test runner sets LD_PRELOAD. Either
    # way the cache key must be present afterward.
    assert (os.getpid(), 0.0) in cfg._env_cache
    if os.environ.get("LD_PRELOAD") or os.environ.get("LD_AUDIT"):
        assert f and f["id"] == "dangerous_env"
    else:
        assert f is None


# ─── B7 paranoid scan ─────────────────────────────────────────────────────


def test_paranoid_scan_self_pid_not_hidden():
    """The test runner's own pid is alive and definitely in live_pids."""
    hidden = paranoid_scan({os.getpid()})
    # The test runner pid shouldn't appear as hidden.
    assert os.getpid() not in hidden


def test_paranoid_scan_finds_existing_pid_missing_from_live_set():
    """Pid 1 (init/systemd) is always alive; if it isn't in live_pids, it
    should show up as hidden. PermissionError is also a positive signal.
    """
    hidden = paranoid_scan(set())  # empty live set → everything counts
    assert 1 in hidden
