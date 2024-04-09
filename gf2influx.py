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
    """
    Logger function.
    :param e_type: String -> 'error', 'info'
    :param text_data: String -> message we want to write in log
    :param f_name: String -> Invoker function name
    :param extra_data: String -> additional content
    :return:
    """
    ctime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a") as log:
        if e_type == 'error':
            log_line = "{} | ERROR in {}: {}: {}".format(ctime, f_name,
                                                         type(text_data), text_data)
        elif e_type == "info":
            log_line = "\n{} | INFO from {}: {}".format(ctime, f_name, text_data)
        elif e_type == "init":
            name = "GoFlow2 InfluxDB"
            sep = "\n" + "#" * len(name) + "\n"
            log_line = f"{sep}{name}{sep}\n{ctime} - Starting integrator...\n\n{text_data}\n\n"

        if extra_data:
            log_line += "\nADDITIONAL INFO:\n" + str(extra_data) + "\nADDITIONAL INFO END"
        log.write(log_line)


def send_to_influxdb(data, b_uid):
    """
    Database inserter function.
    :param data: list of dictionaries
    :param b_uid: int -> Batch unique identifier
    :return:
    """
    send_start = time.time()
    try:
        inserted = False
        i = 0
        while not inserted:     # try to insert data until object returns True
            insertion = db_client.write_points(data)
            inserted = insertion
            i += 1
            if not inserted and i < 5:  # 5 failures and raise exception
                time.sleep(3)
                continue
            elif not inserted and i >= 5:
                raise Exception("Timeout while sending data. Check database availability.")
            else:
                send_end = time.time()
                d_msg = "Batch {} inserted {} records in {:.2f}s.".format(b_uid, len(data), send_end - send_start)
                logger("info", d_msg, "send_to_influxdb")

    except Exception as error:
        logger("error", "Batch {} sending error".format(b_uid), error, "send_to_influxdb")


def digester(data, b_id):
    """
    Parser function.
    :param data: List of dictionaries
    :param b_id: int -> batch unique id
    :return:
    """
    batch_start = time.time()
    tags_list = ["proto", "in_if", "out_if", "sampler_address", "src_addr", "dst_addr", "src_port", "dst_port"]
    fields_list = ["sequence_num", "bytes", "packets"]
    tags = {}
    fields = {}
    samplers = {}

    i = len(data)
    for raw_line in data:   # for every line in passed list, try to interpret it as json data
        line = ""
        try:
            if raw_line.startswith(b"{") and raw_line.endswith(b"}\n"):     # verify completeness
                line = json.loads(raw_line)
            else:
                print("SKIPPED: ", raw_line)
                continue
        except Exception as error:  # if data is corrupted, log it
            column = 0
            words = str(error).split()
            if "column" in words:
                column = int(words[words.index("column") + 1])
            additional = (datetime.now().isoformat(), str(error) + ":", str(line)[:column] +
                          ("<-" if column != 0 else ""))
            additional += "LINE\n", line, "\n"
            additional += "RAW_LINE\n", raw_line, "\n"
            logger("error", "Batch {} digester error".format(b_id), error, "digester", additional)
            continue

        # create flow time field for easier insight
        flow_time = (float(line["time_flow_end_ns"]) - float(line["time_flow_start_ns"])) / 1e9
        fields["flow_time"] = flow_time

        # compare data in json with desired tags and fields values and append them properly
        for key, value in line.items():
            if key in tags_list:
                tags[key] = str(value)
            elif key in fields_list:
                fields[key] = value

        # create input data in line protocol syntax
        formatted = {
            "measurement": line["type"],
            "tags": tags,
            "time": int(line["time_received_ns"]),
            "fields": fields
        }

        # check for unique samplers IPs
        if tags["sampler_address"] not in samplers.keys():
            samplers[tags["sampler_address"]] = []
        # append data to proper sampler batch
        samplers[tags["sampler_address"]].append(formatted)
        i -= 1

    if i == 0:
        batch_end = time.time()
        # for each sampler detected, run separate inserter:
        for sampler in samplers.keys():
            threading.Thread(target=send_to_influxdb, args=(samplers[sampler].copy(), b_id,)).start()
            d_msg = ("Batch {}: for sampler {} processed {} records in {:.2f}s."
                     .format(b_id, sampler, len(samplers[sampler]), batch_end - batch_start))
            logger("info", d_msg, "digester")

        samplers.clear()


# Global variables:
temp_file = os.path.normpath("/var/log/netflow.log")
log_file = os.path.join("/var/log/", "gf2influx.log")
args = ['tail', '-fn0', "--follow=name", "--retry", temp_file]

config = Conson(salt="gf2influx")
config_file = os.path.join(os.getcwd(), "config.json")
pwd = ""
batch_id = 0

# Main function #
logger("init", f"Polling: {temp_file}\nLogging to: {log_file}", "main")
try:
    # Config operations:
    if os.path.exists(config_file):     # If configuration file exists:
        config.load()
        pwd = config()["password"]

        if pwd[0] != "<" and pwd[-1] != ">":    # If password is untagged, encrypt it.
            config.veil("password")
            config.create("password", "<" + config()["password"] + ">")     # Tag encrypted password.
            config.save()
            pwd_encrypted = config()["password"][1:-1]
            pwd = config.unveil(pwd_encrypted)
        else:                                   # Else decrypt password.
            pwd_encrypted = config()["password"][1:-1]
            pwd = config.unveil(pwd_encrypted)

    else:                                       # Else create sample config and close program.
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
    # Create database connection object:
    db_client = InfluxDBClient(config()["host"], config()["port"], config()["username"], pwd, config()["database"])
    # Create poller:
    with subprocess.Popen(args, stdout=subprocess.PIPE) as f:
        p = select.poll()
        p.register(f.stdout)
        lines = set()
        previous_time = datetime.now()

        while True:
            if p.poll():    # If new line appears, add it to set
                lines.add(f.stdout.readline())

                now = datetime.now()
                # create separate parser for collected data every 1s or 2500 lines (half of line protocol optimum)
                if now - previous_time >= timedelta(seconds=1) or len(lines) >= 2500:
                    batch_uid = batch_id
                    threading.Thread(target=digester, args=(lines.copy(), batch_uid,)).start()
                    msg = "Batch {} of {} records started processing".format(batch_uid, len(lines))
                    logger("info", msg, "main")
                    lines.clear()
                    previous_time = now
                    batch_id += 1
                elif len(lines) == 0:
                    raise Exception("No new lines in log file. Is collector active?")

except Exception as err:
    logger("error", err, "main")
