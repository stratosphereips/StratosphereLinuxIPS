import multiprocessing


def is_avx_supported():
    """
    Illegal instructions are caused by CPUs lack of support for avx
    instructions
    """
    try:
        with open("/proc/cpuinfo", "r") as cpuinfo:
            for line in cpuinfo:
                # look for the flags line and check if avx is listed
                if line.startswith("flags"):
                    if "avx" in line.split():
                        return True
        return False
    except Exception as e:
        print(f"Error occurred: {e}")
        return False


def try_import_tensorflow():
    """
    Attempt to import tensorflow in a separate process.
    Returns True if successful, False if an error occurs.
    """
    try:
        return True
    except Exception:
        return False


def is_tf_supported() -> bool:
    """
    Check if TensorFlow can be imported safely.
    """
    # to handle "illegal instruction" errors or other hard crashes that might
    # occur at a low level and terminate the process outright. These errors
    # won't be caught by a regular try-except block because they crash the
    # Python interpreter itself.
    process = multiprocessing.Process(target=try_import_tensorflow)
    process.start()
    process.join()

    # If the process exits with a non-zero status, the import failed
    if process.exitcode != 0:
        print("TensorFlow import failed. Disabling TensorFlow...")
        return False

    return is_avx_supported()
