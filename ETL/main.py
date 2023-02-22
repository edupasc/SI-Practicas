# This is a sample Python script.

# Press Mayús+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

import pandas as pd
import json
import sqlite3


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    alerts = pd.read_csv("data/alerts.csv")
    fdevices = open("data/devices.json", "r")
    data = json.load(fdevices)
    devices = pd.json_normalize(data)
    conn = sqlite3.connect("database.sqlite")
    alerts.to_sql("alerts", conn, if_exists="replace", index=False)
    devices.to_sql("devices", conn, if_exists="replace", index=False)
    print(pd.read_sql("count * from devices", conn))
# See PyCharm help at https://www.jetbrains.com/help/pycharm/
