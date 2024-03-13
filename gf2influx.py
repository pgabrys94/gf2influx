import os
import subprocess
import select
import json
from influxdb import InfluxDBClient

temp_file = os.path.normpath("/var/log/gf2influx.log")
args = ['tail', '-fn0', temp_file]

f = subprocess.Popen(args, stdout=subprocess.PIPE)
p = select.poll()
p.register(f.stdout)

tags_list = ["proto", "in_if", "out_if", "sampler_address", "src_addr", "dst_addr", "src_port", "dst_port"]
fields_list = ["sequence_num", "bytes", "packets"]

try:
    db_client = InfluxDBClient("changeMe", 8086, "changeMe", "changeMe", "changeMe")
    while True:
        if p.poll():
            tags = {}
            fields = {}

            line = json.loads(f.stdout.readline().decode())

            flow_time = (float(line["time_flow_end_ns"]) - float(line["time_flow_start_ns"])) / 1e9
            fields["flow_time"] = flow_time

            for key, value in line.items():
                if key in tags_list:
                    tags[key] = value
                elif key in fields_list:
                    fields[key] = value

            formatted = [
                {
                    "measurement": line["type"],
                    "tags": tags,
                    "fields": fields,
                    "timestamp": line["time_received_ns"]
                }
            ]

            db_client.write_points(formatted)

except Exception as err:
    print(err)