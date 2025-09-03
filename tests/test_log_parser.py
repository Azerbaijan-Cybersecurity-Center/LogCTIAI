from src.parsers.log_parser import parse_line


def test_parse_common_log_line():
    line = '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "-" "Mozilla/4.08 [en] (Win98; I ;Nav)"'
    rec = parse_line(line)
    assert rec is not None
    assert rec.ip == "127.0.0.1"
    assert rec.method == "GET"
    assert rec.status == 200
    assert rec.path == "/apache_pb.gif"


def test_parse_json_log_line():
    line = '1756536825482\t2025-08-30T06:53:45.482Z\t{"timestamp":"2025-08-30T06:53:45+00:00","remote_addr":"18.237.3.202","method":"GET","uri":"/assets/public/images/products/fan_facemask.jpg","status":304,"request_body":"","user_agent":"Mozilla/5.0","ssl_protocol":"TLSv1.3","ssl_cipher":"TLS_AES_256_GCM_SHA384"}'
    rec = parse_line(line)
    assert rec is not None
    assert rec.ip == "18.237.3.202"
    assert rec.method == "GET"
    assert rec.status == 304
    assert rec.path.endswith("fan_facemask.jpg")
