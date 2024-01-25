import requests

# URL of the virtual IP handled by the Ryu controller
url_cpu = 'http://10.0.0.10/?task=CPU-Intensive'
url_multimedia = 'http://10.0.0.10/?task=Multimedia'

# Send a GET request indicating a CPU-Intensive task
response_cpu = requests.get(url_cpu)

# Send a GET request indicating a Multimedia task
response_multimedia = requests.get(url_multimedia)

# Process the responses accordingly
print("Response for CPU-Intensive task:", response_cpu.status_code)
print("Response for Multimedia task:", response_multimedia.status_code)
