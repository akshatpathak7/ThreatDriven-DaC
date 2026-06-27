from src.log_loader import load_cloudtrail_logs


def test_load_cloudtrail_records_object() -> None:
    records = load_cloudtrail_logs("data/logs/cloudtrail_suspicious.json")

    assert len(records) == 10
    assert records[0]["eventName"] == "ConsoleLogin"


def test_benign_logs_have_expected_cloudtrail_fields() -> None:
    records = load_cloudtrail_logs("data/logs/cloudtrail_benign.json")
    required = {
        "eventTime",
        "eventSource",
        "eventName",
        "sourceIPAddress",
        "userIdentity",
        "requestParameters",
        "awsRegion",
        "recipientAccountId",
        "userAgent",
    }

    assert records
    assert required.issubset(records[0])

