import json
import hashlib

# List of JSON objects (dictionaries)
dlhash1=hashlib.sha256(str(2211221).encode("utf-8")).hexdigest()
dlhash2=hashlib.sha256(str(31113331).encode("utf-8")).hexdigest()

json_objs = [
    {"name": "John", "age": 30, "city": "New York","doi":"12/01/2003","expiryDL":"11/01/2033","DL":2211221,"hashDL":dlhash1},
    {"name": "Alice", "age": 25, "city": "San Francisco","doi":"12/05/2003","expiryDL":"11/05/2033","DL":31113331,"hashDL":dlhash2}
]

# Write each JSON object to the file
with open('data.json', 'a') as file:
    for json_obj in json_objs:
        # Serialize the JSON object to a string
        json_str = json.dumps(json_obj)
        # Write the JSON string followed by a newline
        file.write(json_str + '\n')
