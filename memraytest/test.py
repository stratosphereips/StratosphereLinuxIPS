import memray

def generate_large_list():
    large_list = list(range(10_000_000))  # Create a list of 10 million integers
    return large_list

memray_context = memray.Tracker("output.bin")
memray_context.__enter__()
generate_large_list()
memray_context.__exit__(None, None, None)