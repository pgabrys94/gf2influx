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


def digester(data):
    tags_list = ["proto", "in_if", "out_if", "sampler_address", "src_addr", "dst_addr", "src_port", "dst_port"]
    fields_list = ["sequence_num", "bytes", "packets"]
    tags = {}
    fields = {}
    batch = []

    i = len(data)
    for raw_line in data:
        line = ""
        try:
            if raw_line.startswith(b"{") and raw_line.endswith(b"}\n"):
                line = json.loads(raw_line)
            else:
                print("SKIPPED: ", raw_line)
                continue
        except Exception as error:
            column = 0
            words = str(error).split()
            if "column" in words:
                column = int(words[words.index("column") + 1])
            print(datetime.now().isoformat(), str(error) + ":", str(line)[:column] +
                  ("<-" if column != 0 else ""))
            print("LINE\n", line, "\n")
            print("RAW_LINE\n", raw_line, "\n")
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
            "time": int(line["time_received_ns"]),
            "fields": fields
        }

        batch.append(formatted)
        i -= 1

    if i == 0:
        threading.Thread(target=send_to_influxdb, args=(batch.copy(),)).start()
        batch.clear()


temp_file = os.path.normpath("/var/log/netflow.log")
args = ['tail', '-fn0', temp_file]

config = Conson(salt="geoip2grafana")
config_file = os.path.join(os.getcwd(), "config.json")
pwd = ""

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
    lines = set()
    previous_time = datetime.now()
    with subprocess.Popen(args, stdout=subprocess.PIPE) as f:
        p = select.poll()
        p.register(f.stdout)
        while True:
            if os.path.exists(temp_file):

                if p.poll():
                    lines.add(f.stdout.readline())

                    now = datetime.now()
                    if datetime.now() - previous_time > timedelta(seconds=5) and len(lines) != 0:
                        threading.Thread(target=digester, args=(lines.copy(),)).start()
                        lines.clear()
                        previous_time = now

except Exception as err:
    print(str(type(err)) + ": " + str(err))
