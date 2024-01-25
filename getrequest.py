import requests
import time
import sys

url = 'http://10.0.0.10'  # Replace with the desired URL
total=0
algo=sys.argv[2] #algo name
client = sys.argv[1] #client number
# Sending a GET request
count = 0
time.sleep(10)
for i in range(70):
    time.sleep(1)
    start=time.time()
    response = requests.get(url)
    if response.status_code == 200:  # Assuming a successful response
        end=time.time()
        count += 1
        total=total+(end-start)
        print(response.text)  # Output the response content
    else:
        print("Request failed:", response.status_code)

file=open('c' + str(client) + "-" + algo + ".txt",'w')
file.write(str(total/count))
file.close()




# Checking the response
