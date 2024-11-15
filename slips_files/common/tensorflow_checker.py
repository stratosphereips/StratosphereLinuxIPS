import multiprocessing


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
    return True
