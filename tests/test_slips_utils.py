from ..slips_files.common.slips_utils import Utils




def create_utils_instance():
    """ Create an instance of threatintel.py
        needed by every other test in this file  """
    utils = Utils()
    return utils

def test_get_hash_from_file():
    utils = create_utils_instance()
    # a file that we know doesn't change
    assert utils.get_hash_from_file('modules/template/__init__.py') == '2d12747a3369505a4d3b722a0422f8ffc8af5514355cdb0eb18178ea7071b8d0'
