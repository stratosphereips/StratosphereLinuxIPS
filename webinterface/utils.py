import os

def read_db_file():
    available_db = []
    file_path = '../running_slips_info.txt'
    
    if os.path.exists(file_path):
        with open(file_path) as file:
            for line in file:
                if line.startswith("Date") or line.startswith("#") or len(line) < 3:
                    continue
                line = line.split(',')
                available_db.append({"filename": line[1], "redis_port": line[2]})
    
    return available_db