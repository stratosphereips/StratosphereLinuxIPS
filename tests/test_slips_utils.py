from tests.module_factory import ModuleFactory

def test_get_hash_from_file():
    utils = ModuleFactory().create_utils_obj()
    # a file that we know doesn't change
    assert (
        utils.get_hash_from_file('modules/template/__init__.py')
        == '2d12747a3369505a4d3b722a0422f8ffc8af5514355cdb0eb18178ea7071b8d0'
    )
