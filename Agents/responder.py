def respond(threats):

    for index,row in threats.iterrows():

        print("Blocking IP:",row['ip'])