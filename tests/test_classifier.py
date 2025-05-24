from analyzer.classifier import merge

def test_merge_rst():
    assert merge(("REFUSED", "RST")) == "SERVICE_DOWN"

def test_merge_icmp():
    assert merge(("FILTERED_OR_NO_SERVICE", "ICMP_UNREACH")) == "FILTERED"

def test_merge_ok():
    assert merge(("OPEN", "NONE")) == "OK"
