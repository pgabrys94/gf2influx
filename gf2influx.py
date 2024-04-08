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


def logger(e_type, text_data, f_name, *extra_data):
    ctime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a") as log:
        if e_type == 'error':
            log_line = "{} | ERROR in {}: {}: {}".format(ctime, f_name,
                                                         type(text_data), text_data)
        elif e_type == "info":
            logline = "\n{} | INFO from {}: {}".format(ctime, f_name, text_data)

        if extra_data:
            log_line += "\nADDITIONAL INFO:\n" + str(extra_data) + "\nADDITIONAL INFO END"
        log.write(logline)


def send_to_influxdb(data, b_uid):
    send_start = time.time()
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
            else:
                send_end = time.time()
                d_msg = "Batch {} inserted in {}s.".format(b_uid, len(data), send_end - send_start)
                logger("info", d_msg, "main")

    except Exception as error:
        logger("Batch {} sending error".format(b_uid), error, "send_to_influxdb")


def digester(data, b_id):
    batch_start = time.time()
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
            logger("Batch {} digester error".format(b_id), error, "digester", additional)
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
        threading.Thread(target=send_to_influxdb, args=(batch.copy(), b_id,)).start()
        batch_end = time.time()
        d_msg = "Batch {}: processed {} entries in {}s.".format(b_id, len(data), batch_end - batch_start)
        logger("info", d_msg, "main")
        batch.clear()


temp_file = os.path.normpath("/var/log/netflow.log")
log_file = os.path.join("/var/log/", "gf2influx.log")
args = ['tail', '-fn0', temp_file]

config = Conson(salt="geoip2grafana")
config_file = os.path.join(os.getcwd(), "config.json")
pwd = ""
batch_id = 0

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
    logger("error", err, "main")

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
                            buid = batch_id
                            threading.Thread(target=digester, args=(lines.copy(), buid,)).start()
                            msg = "Batch of {} entries started processing".format(len(lines))
                            logger("info", msg, "main")
                            lines.clear()
                            previous_time = now
                            batch_id += 1
                        elif len(lines) == 0:
                            break

except Exception as err:
    logger("error", err, "main")
