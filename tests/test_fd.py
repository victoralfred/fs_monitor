from monitor.fd import classify


def test_classify_pipe():
    assert classify("pipe:[12345]") == ("pipe", False)


def test_classify_socket():
    assert classify("socket:[99]") == ("socket", False)


def test_classify_anon():
    assert classify("anon_inode:[eventfd]") == ("anon", False)


def test_classify_deleted_file():
    kind, deleted = classify("/tmp/gone (deleted)")
    assert deleted is True
    assert kind in ("deleted", "unknown")


def test_classify_device():
    kind, _ = classify("/dev/null")
    assert kind == "device"
