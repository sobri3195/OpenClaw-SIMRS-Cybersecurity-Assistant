import csv
from io import StringIO


def ports_to_csv(ports: list[dict]) -> str:
    output = StringIO()
    fields = ["port", "protocol", "state", "service_name", "product", "version", "risk_level", "notes"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(ports)
    return output.getvalue()
