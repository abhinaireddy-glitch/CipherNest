def analyze_logs(data):

    data['suspicious'] = data['failed_login'] > 10

    return data