import os
import subprocess
import select
import json
from conson import Conson
import sys
import threading
import time
from datetime import datetime, timedelta
from influxdb import InfluxDBClient


def logger(error_data, f_name, *extra_data):
    with open(log_file, "a") as log:
        log_line = "{} | ERROR in {}: {}: {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), f_name,
                                                     type(error_data), error_data)
        if extra_data:
            log_line += "\nADDITIONAL INFO:\n" + str(extra_data) + "\nADDITIONAL INFO END"
        log.write(log_line)


def send_to_influxdb(data):
    try:
        inserted = False
        i = 0
        while not inserted:
            insertion = db_client.write_points(data)
            inserted = insertion
            i += 1
            if not inserted and i < 6:
                time.sleep(3)
                continue
            elif not inserted and i >= 6:
                raise Exception("Timeout while sending data. Check database availability.")


    except Exception as error:
        logger(error, "send_to_influxdb")


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
            additional = (datetime.now().isoformat(), str(error) + ":", str(line)[:column] +
                          ("<-" if column != 0 else ""))
            additional += "LINE\n", line, "\n"
            additional += "RAW_LINE\n", raw_line, "\n"
            logger(error, "send_to_influxdb", additional)
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
log_file = os.path.join("/var/log/", "gf2influx.log")
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
    logger(err, "main")

try:
    db_client = InfluxDBClient(config()["host"], config()["port"], config()["username"], pwd, config()["database"])
    while True:
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
                        elif len(lines) == 0:
                            break

except Exception as err:
    logger(err, "main")
