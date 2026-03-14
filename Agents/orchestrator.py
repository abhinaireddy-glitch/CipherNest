def orchestrate(data):

    threats = data[data['anomaly'] == -1]

    return threats