import random
import pandas as pd

def simulate_attack():

    logs = []

    for i in range(20):

        log = {
            "ip":"192.168.1."+str(random.randint(1,50)),
            "failed_login":random.randint(1,20),
            "packet_size":random.randint(200,2000)
        }

        logs.append(log)

    df = pd.DataFrame(logs)

    df.to_csv("data/sample_logs.csv",index=False)

    return df