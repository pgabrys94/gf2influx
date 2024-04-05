import os
import subprocess
import select
import json
from conson import Conson
import sys
import threading
from datetime import datetime, timedelta
from influxdb import InfluxDBClient


def send_to_influxdb(data):
    try:
        db_client.write_points(data)
    except Exception as error:
        print("InfluxDB write error: ", str(type(error)) + ": " + str(error))


temp_file = os.path.normpath("/var/log/netflow.log")
args = ['tail', '-fn0', temp_file]

tags_list = ["proto", "in_if", "out_if", "sampler_address", "src_addr", "dst_addr", "src_port", "dst_port"]
fields_list = ["sequence_num", "bytes", "packets"]
config = Conson(salt="geoip2grafana")
config_file = os.path.join(os.getcwd(), "config.json")
pwd = ""
previous_time = datetime.now()
batch = []

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
    print("Configuration failed: ", str(type(err)) + ": " + str(err))

try:
    db_client = InfluxDBClient(config()["host"], config()["port"], config()["username"], pwd, config()["database"])
    while True:
        try:
            if os.path.exists(temp_file):
                with subprocess.Popen(args, stdout=subprocess.PIPE) as f:
                    p = select.poll()
                    p.register(f.stdout)

                    if p.poll():
                        tags = {}
                        fields = {}

                        raw_line = f.stdout.readline()
                        try:
                            line = json.loads(raw_line)
                        except Exception as error:
                            print(datetime.now().isoformat(), error + ":", line[:10] + "...")
                            continue

                        flow_time = (float(line["time_flow_end_ns"]) - float(line["time_flow_start_ns"])) / 1e9
                        fields["flow_time"] = flow_time

                        for key, value in line.items():
                            if key in tags_list:
                                tags[key] = str(value)
                            elif key in fields_list:
                                fields[key] = value

                        formatted = {
                            "measurement": line["type"],
                            "tags": tags,
                            "timestamp": int(line["time_received_ns"]),
                            "fields": fields
                        }

                        batch.append(formatted)


                now = datetime.now()
                if now - previous_time > timedelta(seconds=10):
                    threading.Thread(target=send_to_influxdb, args=(batch.copy(),)).start()
                    batch.clear()
                    previous_time = now

        except Exception as error:
            print("ERROR: ", error)

except Exception as err:
    print(str(type(err)) + ": " + str(err))
