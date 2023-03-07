def green(txt):
    """
    returns the text in green
    """
    GREEN_s = '\033[1;32;40m'
    GREEN_e = '\033[00m'
    return f'{GREEN_s}{txt}{GREEN_e}'