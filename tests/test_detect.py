from credgraph.detect import detect

def test_high_signal_and_placeholder_filter():
    text='AWS_ACCESS_KEY_ID="AKIA1234567890ABCDEF"\nTOKEN="changeme"\n'
    hits=detect(text)
    assert any(h.secret_type=="aws_access_key" for h in hits)
    assert not any(h.value=="changeme" for h in hits)

def test_private_key():
    text="-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"
    assert any(h.secret_type=="private_key" for h in detect(text))
