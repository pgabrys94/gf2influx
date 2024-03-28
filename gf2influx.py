import os
import subprocess
import select
import json
from conson import Conson
import sys
from influxdb import InfluxDBClient

temp_file = os.path.normpath("/var/log/netflow.log")
args = ['tail', '-fn0', temp_file]

tags_list = ["proto", "in_if", "out_if", "sampler_address", "src_addr", "dst_addr", "src_port", "dst_port"]
fields_list = ["sequence_num", "bytes", "packets"]
config = Conson(salt="geoip2grafana")
config_file = os.path.join(os.getcwd(), "config.json")
pwd = ""
batch = []
counter = 0

try:
    if os.path.exists(config_file):
        config.load()
        pwd = config()["password"]
        if pwd[0] != "<" and pwd[-1] != ">":
            config.veil("password")
            config.create("password", "<" + config()["password"] + ">")
            config.save()
            pwd_crypted = config()["password"][1:-1]
            pwd = config.unveil(pwd_crypted)
        else:
            pwd_crypted = config()["password"][1:-1]
            pwd = config.unveil(pwd_crypted)

    else:
        config.create("host", "localhost")
        config.create("port", 8086)
        config.create("username", "admin")
        config.create("password", "password")
        config.create("database", "netflowDB")
        config.save()
        print("Configuration file created, change it's parameters.")
        input("Press any key to continue...")
        sys.exit()
except Exception as err:
    print("Configuration failed: ")

try:
    db_client = InfluxDBClient(config()["host"], config()["port"], config()["username"], pwd, config()["database"])
    while True:
        if os.path.exists(temp_file):
            with subprocess.Popen(args, stdout=subprocess.PIPE) as f:
                p = select.poll()
                p.register(f.stdout)

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

                    formatted = {
                        "measurement": line["type"],
                        "tags": tags,
                        "fields": fields,
                        "timestamp": line["time_received_ns"]
                    }

                    batch.append(formatted)
                    counter += 1

            if counter == 100:
                db_client.write_points(batch)
                batch = []
                counter = 0

except Exception as err:
    print(err)
