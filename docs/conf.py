# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
# import os
# import sys
# sys.path.insert(0, os.path.abspath('.'))

from recommonmark.transform import AutoStructify
import requests


# -- Project information -----------------------------------------------------

project = 'Slips'
copyright = '2021, Stratosphere Laboratory'
author = 'Stratosphere Laboratory'

# The full version, including alpha/beta/rc tags
url = "https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/VERSION"
response = requests.get(url, timeout=5)

if response.status_code == 200:
    release = response.text

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = ['recommonmark']


# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
# html_theme = 'alabaster'
html_theme = 'sphinx_rtd_theme'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

source_suffix = {
    '.rst': 'restructuredtext',
    '.txt': 'markdown',
    '.md': 'markdown',
    '.html': 'html',
}

master_doc = 'index'
# app setup hook
def setup(app):
    app.add_config_value(
        'recommonmark_config',
        {
            #'url_resolver': lambda url: github_doc_root + url,
            'auto_toc_tree_section': 'Slips',
            'enable_math': False,
            'enable_inline_math': False,
            'enable_eval_rst': True,
        },
        True,
    )
    app.add_transform(AutoStructify)
